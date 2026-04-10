"""
skg.sensors.projector
======================
In-process projection runner.

Invokes toolchain projectors directly as Python modules — no subprocess,
no venv requirement. Each projector's run.py exposes a compute_* function
and a main() entry point. We call the compute function directly.

Domain routing:
  Events tagged toolchain=skg-aprs-toolchain        → aprs projector
  Events tagged toolchain=skg-container-escape-*    → escape projector
  Events tagged toolchain=skg-ad-lateral-*          → lateral projector
  Events tagged toolchain=skg-host-*                → host projector

For each workload+attack_path pair found in the event stream:
  1. Filter events for that pair
  2. Write to a temp NDJSON file
  3. Import the projector module
  4. Call its compute function directly
  5. Write result to INTERP_DIR/<domain>_<workload>_<run_id>.json

The feedback ingester then picks up INTERP_DIR files on the next tick.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import tempfile
import uuid
from collections import defaultdict
from pathlib import Path

import re as _re

from skg.core.assistant_contract import observation_event_admissible
from skg.temporal.interp import canonical_interp_payload
from skg_core.config.paths import SKG_HOME
from skg_registry import DomainRegistry as _CanonicalDomainRegistry
try:
    from skg_services.gravity import projector_runtime as _service_projector_runtime
except Exception:  # pragma: no cover - legacy fallback when canonical services package is unavailable
    _service_projector_runtime = None

log = logging.getLogger("skg.sensors.projector")
_INTERP_KEEP = 3  # keep only this many files per (domain, workload, attack_path) prefix


def _prune_interp_siblings(written: Path, family_prefix: str, keep: int = _INTERP_KEEP) -> None:
    """Delete oldest sibling interp files so at most `keep` files exist per family."""
    siblings = sorted(
        written.parent.glob(f"{family_prefix}__*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in siblings[keep:]:
        try:
            old.unlink()
        except OSError:
            pass

ATTACK_PATH_ALIASES = {
    "skg-ad-lateral-toolchain": {
        "ad_lateral_movement_v1": "ad_kerberoast_v1",
    },
    "skg-supply-chain-toolchain": {
        "supply_chain_rce_via_dependency_v1": "supply_chain_network_exploit_v1",
    },
}

TOOLCHAIN_ALIASES = {
    "binary_analysis": {"binary"},
    "binary": {"binary_analysis"},
}

_projector_cache: dict[str, object] = {}


def _safe_interp_part(value: str, limit: int = 80) -> str:
    cleaned = _re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    cleaned = cleaned.strip("._") or "unknown"
    return cleaned[:limit]


def _domain_inventory_rows() -> list[dict]:
    rows: list[dict] = []
    _search_roots = [SKG_HOME / "packages" / "skg-domains", SKG_HOME]
    for domain in _CanonicalDomainRegistry.discover(search_roots=_search_roots).list_domains():
        metadata = dict(domain.manifest.metadata or {})
        default_path = str(
            metadata.get("default_path")
            or metadata.get("default_attack_path")
            or ""
        ).strip()
        projector_path = ""
        if domain.projectors_dir.exists():
            run_root = domain.projectors_dir / "run.py"
            if run_root.exists():
                projector_path = str(run_root.relative_to(domain.root_dir))
            else:
                nested = sorted(domain.projectors_dir.glob("*/run.py"))
                if nested:
                    projector_path = str(nested[0].relative_to(domain.root_dir))

        rows.append(
            {
                "name": domain.name,
                "dir": domain.root_dir,
                "toolchain": domain.root_dir.name,
                "default_path": default_path,
                "projector_path": projector_path,
            }
        )
    return rows


def _toolchain_row(toolchain: str) -> dict | None:
    raw = str(toolchain or "").strip()
    if not raw:
        return None

    requested = {
        raw,
        raw.replace("-", "_"),
        raw.replace("_", "-"),
    }
    if raw.startswith("skg-") and raw.endswith("-toolchain"):
        middle = raw[len("skg-"):-len("-toolchain")]
        requested.update({middle, middle.replace("-", "_"), middle.replace("_", "-")})
    else:
        requested.add(f"skg-{raw}-toolchain")

    expanded = set(requested)
    for item in list(requested):
        norm = item.replace("-", "_")
        for alias in TOOLCHAIN_ALIASES.get(norm, set()):
            expanded.update({
                alias,
                alias.replace("-", "_"),
                alias.replace("_", "-"),
                f"skg-{alias.replace('_', '-')}-toolchain",
            })
    requested = expanded

    first_match: dict | None = None
    for row in _domain_inventory_rows():
        dir_path = row.get("dir")
        dir_name = dir_path.name if isinstance(dir_path, Path) else ""
        toolchain_name = str(row.get("toolchain") or dir_name or "").strip()
        domain_name = str(row.get("name") or "").strip()
        aliases = {
            domain_name,
            domain_name.replace("-", "_"),
            domain_name.replace("_", "-"),
            toolchain_name,
            dir_name,
        }
        if any(item for item in aliases if item in requested):
            if str(row.get("projector_path") or "").strip():
                return dict(row)
            if first_match is None:
                first_match = dict(row)
    return first_match


def _canonical_toolchain_name(toolchain: str) -> str:
    row = _toolchain_row(toolchain)
    if row:
        dir_path = row.get("dir")
        if isinstance(dir_path, Path):
            return dir_path.name
        toolchain_name = str(row.get("toolchain") or "").strip()
        if toolchain_name:
            return toolchain_name
    canonical = str(toolchain or "").strip()
    if canonical.startswith("skg-") and canonical.endswith("-toolchain"):
        return canonical
    candidate = f"skg-{canonical}-toolchain"
    if _toolchain_row(candidate):
        return candidate
    return canonical


def _canonical_attack_path_id(toolchain: str, attack_path_id: str) -> str:
    aliases = ATTACK_PATH_ALIASES.get(_canonical_toolchain_name(toolchain), {})
    return aliases.get(attack_path_id, attack_path_id)


def _discover_toolchain_projector(toolchain: str) -> bool:
    row = _toolchain_row(toolchain)
    if not row:
        return False
    dir_path = row.get("dir")
    projector_path = str(row.get("projector_path") or "").strip()
    return isinstance(dir_path, Path) and bool(projector_path) and (dir_path / projector_path).exists()


def _toolchain_domain(toolchain: str) -> str:
    row = _toolchain_row(toolchain)
    if row and row.get("name"):
        return str(row["name"])
    return _canonical_toolchain_name(toolchain).replace("skg-", "").replace("-toolchain", "").replace("-", "_")


def _default_attack_path(toolchain: str) -> str:
    row = _toolchain_row(toolchain)
    if row and row.get("default_path"):
        return str(row["default_path"])
    return ""


def _resolve_projector_entry(toolchain: str) -> tuple[dict, Path] | None:
    row = _toolchain_row(toolchain)
    if not row:
        return None
    dir_path = row.get("dir")
    projector_path = str(row.get("projector_path") or "").strip()
    if not isinstance(dir_path, Path) or not projector_path:
        return None
    run_file = dir_path / projector_path
    if not run_file.exists():
        return None
    return row, run_file


def _normalize_event(ev: dict) -> dict:
    payload = dict(ev.get("payload", {}))
    status = payload.get("status")
    if status is None:
        realized = payload.get("realized")
        if realized is True:
            status = "realized"
        elif realized is False:
            status = "blocked"
        else:
            status = "unknown"
        payload["status"] = status

    source = dict(ev.get("source", {}))
    source["toolchain"] = _canonical_toolchain_name(source.get("toolchain", ""))

    normalized = dict(ev)
    normalized["payload"] = payload
    normalized["source"] = source
    return normalized
def _load_projector(toolchain: str):
    """Dynamically import a projector's run.py. Cached per process."""
    toolchain = _canonical_toolchain_name(toolchain)
    if toolchain in _projector_cache:
        return _projector_cache[toolchain]

    resolved = _resolve_projector_entry(toolchain)
    if not resolved:
        return None

    row, run_file = resolved

    spec = importlib.util.spec_from_file_location(
        f"skg_proj_{toolchain.replace('-','_')}", run_file
    )
    if spec is None or spec.loader is None:
        log.warning(f"Projector import spec unavailable: {run_file}")
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    preferred = []
    domain = str(row.get("name") or "").strip()
    if domain:
        preferred.extend([f"compute_{domain}", f"compute_{domain}_score"])
    subdir = run_file.parent.name.replace("-", "_")
    if subdir and subdir != "projections":
        preferred.extend([f"compute_{subdir}", f"compute_{subdir}_score"])
    preferred.append("compute")

    compute_fn_name = None
    for name in preferred:
        if callable(getattr(mod, name, None)):
            compute_fn_name = name
            break
    if compute_fn_name is None:
        compute_candidates = [
            name for name in dir(mod)
            if name.startswith("compute_") and callable(getattr(mod, name, None))
        ]
        if len(compute_candidates) == 1:
            compute_fn_name = compute_candidates[0]

    _projector_cache[toolchain] = (row, mod, compute_fn_name)
    return _projector_cache[toolchain]


def _load_catalog(toolchain: str, attack_path_id: str) -> dict:
    """Load the catalog JSON for a toolchain."""
    attack_path_id = _canonical_attack_path_id(toolchain, attack_path_id)
    row = _toolchain_row(toolchain)
    tc_dir = row.get("dir") if row else None
    if not isinstance(tc_dir, Path):
        return {}
    tc_dir = tc_dir / "contracts" / "catalogs"
    candidates = list(tc_dir.glob("*.json")) if tc_dir.exists() else []
    if not candidates:
        return {}
    # Prefer the one matching the attack_path_id domain
    for f in candidates:
        try:
            d = json.loads(f.read_text())
            paths = d.get("attack_paths", {})
            if isinstance(paths, dict) and attack_path_id in paths:
                return d
            if isinstance(paths, list) and any(p.get("id") == attack_path_id for p in paths):
                return d
        except Exception:
            pass
    # Fallback: return first catalog
    try:
        return json.loads(candidates[0].read_text())
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


def project_events(
    events: list[dict],
    workload_id: str,
    toolchain: str,
    attack_path_id: str,
    run_id: str,
    interp_dir: Path,
) -> Path | None:
    """
    Project a list of events for one workload+toolchain+attack_path.
    Writes result to interp_dir. Returns output path or None.
    """
    events = [_normalize_event(ev) for ev in events]
    attack_path_id = _canonical_attack_path_id(toolchain, attack_path_id)
    loaded = _load_projector(toolchain)
    if loaded is None:
        log.warning(f"No projector for toolchain: {toolchain}")
        return None

    _row, mod, compute_fn_name = loaded
    compute_fn = getattr(mod, compute_fn_name, None) if compute_fn_name else None
    domain = _toolchain_domain(toolchain)
    out_path, family_prefix = _interp_output_path(
        interp_dir,
        domain=domain,
        workload_id=workload_id,
        attack_path_id=attack_path_id,
        run_id=run_id,
    )

    # All projectors also expose a generic compute() or main() path
    # Try compute_fn first, then fall back to running via temp files
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
                out_path.write_text(json.dumps(result, indent=2))
                _prune_interp_siblings(out_path, family_prefix)
                log.info(f"[projector] {workload_id}/{attack_path_id} → {out_path.name} "
                         f"(score={result.get('aprs', result.get('lateral_score', result.get('escape_score', result.get('host_score', result.get('web_score', result.get('ai_score', '?'))))))})")
                return out_path
        except Exception as exc:
            log.debug(f"[projector] compute_fn failed, trying file path: {exc}")

    # Fallback: write events to temp file, call projector's main via argparse shim
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ev_file  = tmp / "events.ndjson"
        out_file = tmp / "result.json"

        with ev_file.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

        try:
            import sys
            old_argv = sys.argv
            sys.argv = [
                "run.py",
                "--in", str(ev_file),
                "--out", str(out_file),
                "--attack-path-id", attack_path_id,
                "--run-id", run_id,
                "--workload-id", workload_id,
            ]
            try:
                mod.main()
            except SystemExit:
                pass
            finally:
                sys.argv = old_argv

            if out_file.exists():
                result = json.loads(out_file.read_text())
                result = _ensure_interp_metadata(
                    result,
                    domain=domain,
                    workload_id=workload_id,
                    attack_path_id=attack_path_id,
                    run_id=run_id,
                )
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, indent=2))
                _prune_interp_siblings(out_path, family_prefix)
                log.info(f"[projector] {workload_id}/{attack_path_id} → {out_path.name}")
                return out_path
        except Exception as exc:
            log.error(f"[projector] file-path fallback failed: {exc}", exc_info=True)

    return None


def project_event_file(
    ev_file: Path,
    interp_dir: Path,
    run_id: str | None = None,
) -> list[Path]:
    """
    Project all workload+toolchain combinations found in an event file.
    Groups events by (workload_id, toolchain, attack_path_id) and projects each.
    Returns list of output paths written.
    """
    run_id = run_id or str(uuid.uuid4())[:8]
    if not ev_file.exists():
        return []

    # Group events
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for line in ev_file.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue

        if ev.get("type") != "obs.attack.precondition":
            continue
        if not observation_event_admissible(ev):
            continue

        ev = _normalize_event(ev)
        payload    = ev.get("payload", {})
        toolchain  = ev.get("source", {}).get("toolchain", "")
        toolchain  = _canonical_toolchain_name(toolchain)
        wid        = payload.get("workload_id", "unknown")
        path_id    = payload.get("attack_path_id") or _default_attack_path(toolchain)
        path_id    = _canonical_attack_path_id(toolchain, path_id)

        if not toolchain or not _discover_toolchain_projector(toolchain):
            continue

        groups[(wid, toolchain, path_id)].append(ev)

    outputs = []
    for (wid, toolchain, path_id), evs in groups.items():
        out = project_events(evs, wid, toolchain, path_id, run_id, interp_dir)
        if out:
            outputs.append(out)

    return outputs


def project_events_dir(
    events_dir: Path,
    interp_dir: Path,
    run_id: str | None = None,
    since_run_id: str | None = None,
) -> list[Path]:
    """
    Project all event files in events_dir.
    If since_run_id given, only files matching that run_id pattern.
    """
    run_id = run_id or str(uuid.uuid4())[:8]
    pattern = f"*_{since_run_id}.ndjson" if since_run_id else "*.ndjson"
    outputs = []
    for ev_file in sorted(events_dir.glob(pattern)):
        results = project_event_file(ev_file, interp_dir, run_id)
        outputs.extend(results)
    return outputs


if _service_projector_runtime is not None:
    _projector_cache = _service_projector_runtime._projector_cache
    _discover_toolchain_projector = _service_projector_runtime._discover_toolchain_projector
    _canonical_toolchain_name = _service_projector_runtime._canonical_toolchain_name
    _canonical_attack_path_id = _service_projector_runtime._canonical_attack_path_id
    _default_attack_path = _service_projector_runtime._default_attack_path
    project_events = _service_projector_runtime.project_events
    project_event_file = _service_projector_runtime.project_event_file
    project_events_dir = _service_projector_runtime.project_events_dir
