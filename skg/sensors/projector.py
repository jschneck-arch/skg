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
import os
import tempfile
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("skg.sensors.projector")

SKG_HOME = Path(os.environ.get("SKG_HOME", Path(__file__).resolve().parents[2]))
TOOLCHAIN_ALIASES = {
    "aprs": "skg-aprs-toolchain",
    "container_escape": "skg-container-escape-toolchain",
    "ad_lateral": "skg-ad-lateral-toolchain",
    "host": "skg-host-toolchain",
    "web": "skg-web-toolchain",
    "data": "skg-data-toolchain",
    "ai_target": "skg-ai-toolchain",
    "iot_firmware": "skg-iot_firmware-toolchain",
    "supply_chain": "skg-supply-chain-toolchain",
    "binary": "skg-binary-toolchain",
}

TOOLCHAIN_PROJECTOR = {
    "skg-aprs-toolchain":             ("skg-aprs-toolchain",            "projections/aprs/run.py",     "compute_aprs"),
    "skg-container-escape-toolchain": ("skg-container-escape-toolchain","projections/escape/run.py",   "compute_escape"),
    "skg-ad-lateral-toolchain":       ("skg-ad-lateral-toolchain",      "projections/lateral/run.py",  "compute_lateral"),
    "skg-host-toolchain":             ("skg-host-toolchain",            "projections/host/run.py",     "compute_host_score"),
    "skg-web-toolchain":              ("skg-web-toolchain",             "projections/web/run.py",      "compute_web"),
    "skg-data-toolchain":             ("skg-data-toolchain",            "projections/data/run.py",     "compute_data_score"),
    "skg-ai-toolchain":               ("skg-ai-toolchain",              "projections/run.py",          "compute_ai"),
    "skg-iot_firmware-toolchain":     ("skg-iot_firmware-toolchain",    "projections/iot_firmware/run.py", "compute_iot_score"),
    "skg-supply-chain-toolchain":     ("skg-supply-chain-toolchain",    "projections/supply_chain/run.py", "compute_supply_chain_score"),
    "skg-binary-toolchain":           ("skg-binary-toolchain",          "projections/binary/run.py",   "compute_binary_score"),
}

# Attack path defaults per domain
DEFAULT_ATTACK_PATH = {
    "skg-aprs-toolchain":             "log4j_jndi_rce_v1",
    "skg-container-escape-toolchain": "container_escape_privileged_v1",
    "skg-ad-lateral-toolchain":       "ad_kerberoast_v1",
    "skg-host-toolchain":             "host_ssh_initial_access_v1",
    "skg-web-toolchain":              "web_initial_access_v1",
    "skg-data-toolchain":             "data_completeness_failure_v1",
    "skg-ai-toolchain":               "ai_llm_extract_v1",
    "skg-iot_firmware-toolchain":     "iot_firmware_network_exploit_v1",
    "skg-supply-chain-toolchain":     "supply_chain_network_exploit_v1",
    "skg-binary-toolchain":           "binary_stack_overflow_v1",
}

ATTACK_PATH_ALIASES = {
    "skg-ad-lateral-toolchain": {
        "ad_lateral_movement_v1": "ad_kerberoast_v1",
    },
    "skg-supply-chain-toolchain": {
        "supply_chain_rce_via_dependency_v1": "supply_chain_network_exploit_v1",
    },
}

_projector_cache: dict[str, object] = {}


def _canonical_toolchain_name(toolchain: str) -> str:
    canonical = TOOLCHAIN_ALIASES.get(toolchain, toolchain)
    if canonical != toolchain:
        return canonical
    if canonical.startswith("skg-") and canonical.endswith("-toolchain"):
        return canonical
    candidate = f"skg-{canonical}-toolchain"
    if (SKG_HOME / candidate).exists():
        return candidate
    return canonical


def _canonical_attack_path_id(toolchain: str, attack_path_id: str) -> str:
    aliases = ATTACK_PATH_ALIASES.get(toolchain, {})
    return aliases.get(attack_path_id, attack_path_id)


def _discover_toolchain_projector(toolchain: str) -> bool:
    tc_name = _canonical_toolchain_name(toolchain)
    if tc_name in TOOLCHAIN_PROJECTOR:
        return True

    tc_dir = SKG_HOME / tc_name
    if not tc_dir.exists():
        return False

    proj_files = sorted(tc_dir.glob("projections/*/run.py"))
    if not proj_files:
        return False

    run_file = proj_files[0]
    rel = run_file.relative_to(tc_dir)
    domain = run_file.parent.name.replace("-", "_")
    compute_name = f"compute_{domain}"
    TOOLCHAIN_PROJECTOR[tc_name] = (tc_name, str(rel), compute_name)

    catalogs = sorted((tc_dir / "contracts" / "catalogs").glob("*.json"))
    for catalog_file in catalogs:
        try:
            catalog = json.loads(catalog_file.read_text())
        except Exception:
            continue
        attack_paths = catalog.get("attack_paths", {})
        if isinstance(attack_paths, dict) and attack_paths:
            DEFAULT_ATTACK_PATH[tc_name] = next(iter(attack_paths.keys()))
            break
        if isinstance(attack_paths, list) and attack_paths:
            first = attack_paths[0]
            if isinstance(first, dict) and first.get("id"):
                DEFAULT_ATTACK_PATH[tc_name] = first["id"]
                break

    return True


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


def _unwrap_interp_payload(result: dict) -> dict:
    if isinstance(result, dict) and isinstance(result.get("payload"), dict):
        return result["payload"]
    return result


def _load_projector(toolchain: str):
    """Dynamically import a projector's run.py. Cached per process."""
    toolchain = _canonical_toolchain_name(toolchain)
    if toolchain in _projector_cache:
        return _projector_cache[toolchain]

    info = TOOLCHAIN_PROJECTOR.get(toolchain)
    if not info and not _discover_toolchain_projector(toolchain):
        return None
    info = TOOLCHAIN_PROJECTOR.get(toolchain)
    if not info:
        return None

    tc_name, rel_path, _ = info
    run_file = SKG_HOME / tc_name / rel_path
    if not run_file.exists():
        log.warning(f"Projector not found: {run_file}")
        return None

    spec = importlib.util.spec_from_file_location(
        f"skg_proj_{tc_name.replace('-','_')}", run_file
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _projector_cache[toolchain] = mod
    return mod


def _load_catalog(toolchain: str, attack_path_id: str) -> dict:
    """Load the catalog JSON for a toolchain."""
    attack_path_id = _canonical_attack_path_id(toolchain, attack_path_id)
    tc_dir = SKG_HOME / toolchain / "contracts" / "catalogs"
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
    mod = _load_projector(toolchain)
    if mod is None:
        log.warning(f"No projector for toolchain: {toolchain}")
        return None

    info = TOOLCHAIN_PROJECTOR[toolchain]
    compute_fn_name = info[2]
    compute_fn = getattr(mod, compute_fn_name, None)

    # All projectors also expose a generic compute() or main() path
    # Try compute_fn first, then fall back to running via temp files
    catalog = _load_catalog(toolchain, attack_path_id)

    if compute_fn and catalog:
        try:
            result = compute_fn(events, catalog, attack_path_id,
                                run_id=run_id, workload_id=workload_id)
            if result:
                payload = _unwrap_interp_payload(result)
                domain = toolchain.replace("skg-","").replace("-toolchain","").replace("-","_")
                wid_safe = workload_id.replace("/","_").replace(":","_").replace(" ","_")[:60]
                out_path = interp_dir / f"{domain}_{wid_safe}_{run_id}.json"
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, indent=2))
                log.info(f"[projector] {workload_id}/{attack_path_id} → {out_path.name} "
                         f"(score={payload.get('aprs', payload.get('lateral_score', payload.get('escape_score', payload.get('host_score', payload.get('web_score', payload.get('ai_score', '?'))))))})")
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
            ]
            try:
                mod.main()
            except SystemExit:
                pass
            finally:
                sys.argv = old_argv

            if out_file.exists():
                result = json.loads(out_file.read_text())
                domain = toolchain.replace("skg-","").replace("-toolchain","").replace("-","_")
                wid_safe = workload_id.replace("/","_").replace(":","_").replace(" ","_")[:60]
                out_path = interp_dir / f"{domain}_{wid_safe}_{run_id}.json"
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, indent=2))
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

        ev = _normalize_event(ev)
        payload    = ev.get("payload", {})
        toolchain  = ev.get("source", {}).get("toolchain", "")
        toolchain  = _canonical_toolchain_name(toolchain)
        wid        = payload.get("workload_id", "unknown")
        path_id    = payload.get("attack_path_id") or DEFAULT_ATTACK_PATH.get(toolchain, "")
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
