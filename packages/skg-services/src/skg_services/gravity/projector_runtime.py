"""Service-owned projector execution runtime.

This module is intentionally runtime-coupled and belongs in skg-services.
It resolves projectors through the public registry and executes them in-process.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import re
import tempfile
import uuid
from collections import defaultdict
from pathlib import Path

from skg_core.temporal.interp import canonical_interp_payload
from skg_protocol.validation.assistant import observation_event_admissible
from skg_registry import DomainRegistry

log = logging.getLogger("skg_services.gravity.projector_runtime")

_INTERP_KEEP = 3
_projector_cache: dict[str, object] = {}

ATTACK_PATH_ALIASES = {
    "skg-ad-lateral-toolchain": {
        "ad_lateral_movement_v1": "ad_kerberoast_v1",
    },
    "skg-supply-chain-toolchain": {
        "supply_chain_rce_via_dependency_v1": "supply_chain_network_exploit_v1",
    },
}


from skg_core.config.paths import SKG_HOME


def _registry_domains():
    return DomainRegistry.discover(search_roots=[SKG_HOME / "packages" / "skg-domains", SKG_HOME]).list_domains()


def _safe_interp_part(value: str, limit: int = 80) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    cleaned = cleaned.strip("._") or "unknown"
    return cleaned[:limit]


_TOOLCHAIN_ALIASES: dict[str, set[str]] = {
    "binary_analysis": {"binary"},
    "binary": {"binary_analysis"},
}


def _toolchain_candidates(toolchain: str) -> set[str]:
    raw = str(toolchain or "").strip()
    if not raw:
        return set()
    candidates = {
        raw,
        raw.replace("-", "_"),
        raw.replace("_", "-"),
    }
    if raw.startswith("skg-") and raw.endswith("-toolchain"):
        middle = raw[len("skg-") : -len("-toolchain")]
        candidates.update({middle, middle.replace("-", "_"), middle.replace("_", "-")})
    else:
        candidates.add(f"skg-{raw}-toolchain")
    # Expand via explicit alias table.
    norm = raw.replace("-", "_")
    for alias in _TOOLCHAIN_ALIASES.get(norm, set()):
        candidates.update({alias, alias.replace("-", "_"), alias.replace("_", "-"),
                            f"skg-{alias.replace('_', '-')}-toolchain"})
    return candidates


def _toolchain_record(toolchain: str):
    requested = _toolchain_candidates(toolchain)
    if not requested:
        return None

    first_match = None
    for domain in _registry_domains():
        aliases = {
            domain.name,
            domain.name.replace("-", "_"),
            domain.name.replace("_", "-"),
            domain.root_dir.name,
        }
        if aliases & requested:
            if _projector_run_file(domain) is not None:
                return domain
            if first_match is None:
                first_match = domain
    return first_match


def _canonical_toolchain_name(toolchain: str) -> str:
    record = _toolchain_record(toolchain)
    if record is not None:
        return record.root_dir.name
    return str(toolchain or "").strip()


def _canonical_attack_path_id(toolchain: str, attack_path_id: str) -> str:
    aliases = ATTACK_PATH_ALIASES.get(_canonical_toolchain_name(toolchain), {})
    return aliases.get(attack_path_id, attack_path_id)


def _projector_run_file(record) -> Path | None:
    candidates = []

    if record.projectors_dir.exists():
        root = record.projectors_dir / "run.py"
        if root.exists():
            candidates.append(root)
        candidates.extend(sorted(record.projectors_dir.glob("*/run.py")))

    legacy_proj_root = record.root_dir / "projections"
    if legacy_proj_root.exists():
        root = legacy_proj_root / "run.py"
        if root.exists():
            candidates.append(root)
        candidates.extend(sorted(legacy_proj_root.glob("*/run.py")))

    return candidates[0] if candidates else None


def _discover_toolchain_projector(toolchain: str) -> bool:
    record = _toolchain_record(toolchain)
    if record is None:
        return False
    return _projector_run_file(record) is not None


def _domain_name(toolchain: str) -> str:
    record = _toolchain_record(toolchain)
    if record is not None:
        return record.name
    return _canonical_toolchain_name(toolchain).replace("skg-", "").replace("-toolchain", "").replace("-", "_")


def _default_attack_path(toolchain: str) -> str:
    record = _toolchain_record(toolchain)
    if record is None:
        return ""

    metadata = dict(record.manifest.metadata or {})
    for key in ("default_path", "default_attack_path"):
        value = str(metadata.get(key) or "").strip()
        if value:
            return value

    for catalog_file in sorted(record.catalogs_dir.glob("*.json")):
        try:
            catalog = json.loads(catalog_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        attack_paths = catalog.get("attack_paths") or {}
        if isinstance(attack_paths, dict) and attack_paths:
            return str(next(iter(attack_paths.keys())))
        if isinstance(attack_paths, list):
            for item in attack_paths:
                if isinstance(item, dict) and item.get("id"):
                    return str(item["id"])

    return ""


def _normalize_event(event: dict) -> dict:
    payload = dict(event.get("payload", {}))
    status = payload.get("status")
    if status is None:
        realized = payload.get("realized")
        if realized is True:
            payload["status"] = "realized"
        elif realized is False:
            payload["status"] = "blocked"
        else:
            payload["status"] = "unknown"

    source = dict(event.get("source", {}))
    source["toolchain"] = _canonical_toolchain_name(source.get("toolchain", ""))

    normalized = dict(event)
    normalized["payload"] = payload
    normalized["source"] = source
    return normalized


def _load_projector(toolchain: str):
    toolchain = _canonical_toolchain_name(toolchain)
    if toolchain in _projector_cache:
        return _projector_cache[toolchain]

    record = _toolchain_record(toolchain)
    if record is None:
        return None

    run_file = _projector_run_file(record)
    if run_file is None:
        return None

    spec = importlib.util.spec_from_file_location(
        f"skg_services_proj_{toolchain.replace('-', '_')}", run_file
    )
    if spec is None or spec.loader is None:
        return None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    preferred = []
    domain = record.name
    if domain:
        preferred.extend([f"compute_{domain}", f"compute_{domain}_score"])

    subdir = run_file.parent.name.replace("-", "_")
    if subdir and subdir != "projections":
        preferred.extend([f"compute_{subdir}", f"compute_{subdir}_score"])

    preferred.append("compute")

    compute_fn_name = None
    for name in preferred:
        if callable(getattr(module, name, None)):
            compute_fn_name = name
            break

    if compute_fn_name is None:
        compute_candidates = [
            name for name in dir(module)
            if name.startswith("compute_") and callable(getattr(module, name, None))
        ]
        if len(compute_candidates) == 1:
            compute_fn_name = compute_candidates[0]

    _projector_cache[toolchain] = (record, module, compute_fn_name)
    return _projector_cache[toolchain]


def _load_catalog(toolchain: str, attack_path_id: str) -> dict:
    attack_path_id = _canonical_attack_path_id(toolchain, attack_path_id)
    record = _toolchain_record(toolchain)
    if record is None or not record.catalogs_dir.exists():
        return {}

    candidates = list(record.catalogs_dir.glob("*.json"))
    if not candidates:
        return {}

    for catalog_file in candidates:
        try:
            catalog = json.loads(catalog_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        attack_paths = catalog.get("attack_paths") or {}
        if isinstance(attack_paths, dict) and attack_path_id in attack_paths:
            return catalog
        if isinstance(attack_paths, list) and any(
            isinstance(item, dict) and item.get("id") == attack_path_id for item in attack_paths
        ):
            return catalog

    try:
        return json.loads(candidates[0].read_text(encoding="utf-8"))
    except Exception:
        return {}


def _ensure_interp_metadata(result: dict, *, domain: str, workload_id: str, attack_path_id: str, run_id: str) -> dict:
    if not isinstance(result, dict):
        return result

    payload = result.get("payload")
    if isinstance(payload, dict):
        payload = dict(payload)
        payload.setdefault("workload_id", workload_id)
        payload.setdefault("attack_path_id", attack_path_id)
        payload.setdefault("run_id", run_id)
        payload.setdefault("domain", domain)
        updated = dict(result)
        updated["payload"] = payload
        return canonical_interp_payload(updated)

    updated = dict(result)
    updated.setdefault("workload_id", workload_id)
    updated.setdefault("attack_path_id", attack_path_id)
    updated.setdefault("run_id", run_id)
    updated.setdefault("domain", domain)
    return canonical_interp_payload(updated)


def _interp_output_path(interp_dir: Path, *, domain: str, workload_id: str, attack_path_id: str, run_id: str) -> tuple[Path, str]:
    family_prefix = "__".join([
        _safe_interp_part(domain, limit=40),
        _safe_interp_part(workload_id, limit=80),
        _safe_interp_part(attack_path_id, limit=80),
    ])
    return interp_dir / f"{family_prefix}__{run_id}.json", family_prefix


def _prune_interp_siblings(written: Path, family_prefix: str, keep: int = _INTERP_KEEP) -> None:
    siblings = sorted(
        written.parent.glob(f"{family_prefix}__*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for old in siblings[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


def project_events(
    events: list[dict],
    workload_id: str,
    toolchain: str,
    attack_path_id: str,
    run_id: str,
    interp_dir: Path,
) -> Path | None:
    events = [_normalize_event(event) for event in events]
    attack_path_id = _canonical_attack_path_id(toolchain, attack_path_id)

    loaded = _load_projector(toolchain)
    if loaded is None:
        return None

    record, module, compute_fn_name = loaded
    compute_fn = getattr(module, compute_fn_name, None) if compute_fn_name else None

    domain = record.name
    out_path, family_prefix = _interp_output_path(
        interp_dir,
        domain=domain,
        workload_id=workload_id,
        attack_path_id=attack_path_id,
        run_id=run_id,
    )

    catalog = _load_catalog(toolchain, attack_path_id)

    if compute_fn and catalog:
        try:
            result = compute_fn(
                events,
                catalog,
                attack_path_id,
                run_id=run_id,
                workload_id=workload_id,
            )
            if result:
                result = _ensure_interp_metadata(
                    result,
                    domain=domain,
                    workload_id=workload_id,
                    attack_path_id=attack_path_id,
                    run_id=run_id,
                )
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
                _prune_interp_siblings(out_path, family_prefix)
                return out_path
        except Exception as exc:
            log.debug("projector compute call failed (%s): %s", toolchain, exc)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        events_file = tmp / "events.ndjson"
        out_file = tmp / "result.json"

        with events_file.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")

        try:
            import sys

            old_argv = sys.argv
            sys.argv = [
                "run.py",
                "--in",
                str(events_file),
                "--out",
                str(out_file),
                "--attack-path-id",
                attack_path_id,
                "--run-id",
                run_id,
                "--workload-id",
                workload_id,
            ]
            try:
                module.main()
            except SystemExit:
                pass
            finally:
                sys.argv = old_argv

            if out_file.exists():
                result = json.loads(out_file.read_text(encoding="utf-8"))
                result = _ensure_interp_metadata(
                    result,
                    domain=domain,
                    workload_id=workload_id,
                    attack_path_id=attack_path_id,
                    run_id=run_id,
                )
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
                _prune_interp_siblings(out_path, family_prefix)
                return out_path
        except Exception as exc:
            log.error("projector fallback execution failed (%s): %s", toolchain, exc, exc_info=True)

    return None


def project_event_file(ev_file: Path, interp_dir: Path, run_id: str | None = None) -> list[Path]:
    run_id = run_id or str(uuid.uuid4())[:8]
    if not ev_file.exists():
        return []

    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)

    for raw_line in ev_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except Exception:
            continue

        if event.get("type") != "obs.attack.precondition":
            continue
        if not observation_event_admissible(event):
            continue

        event = _normalize_event(event)
        payload = event.get("payload", {})
        toolchain = _canonical_toolchain_name(event.get("source", {}).get("toolchain", ""))
        workload_id = payload.get("workload_id", "unknown")
        attack_path_id = payload.get("attack_path_id") or _default_attack_path(toolchain)
        attack_path_id = _canonical_attack_path_id(toolchain, attack_path_id)

        if not toolchain or not _discover_toolchain_projector(toolchain):
            continue

        groups[(workload_id, toolchain, attack_path_id)].append(event)

    outputs: list[Path] = []
    for (workload_id, toolchain, attack_path_id), grouped_events in groups.items():
        out = project_events(grouped_events, workload_id, toolchain, attack_path_id, run_id, interp_dir)
        if out is not None:
            outputs.append(out)

    return outputs


def project_events_dir(
    events_dir: Path,
    interp_dir: Path,
    run_id: str | None = None,
    since_run_id: str | None = None,
) -> list[Path]:
    run_id = run_id or str(uuid.uuid4())[:8]
    pattern = f"*_{since_run_id}.ndjson" if since_run_id else "*.ndjson"

    outputs: list[Path] = []
    for events_file in sorted(events_dir.glob(pattern)):
        outputs.extend(project_event_file(events_file, interp_dir, run_id))

    return outputs
