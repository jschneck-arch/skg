#!/usr/bin/env python3
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path

from pathlib import Path

def get_version():
    try:
        return Path(__file__).resolve().parents[2].joinpath("VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"

def read_ndjson(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            yield json.loads(line)

def load_catalog(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def iso_now():
    return datetime.now(timezone.utc).isoformat()

def compute_aprs(events, catalog, attack_path_id: str, run_id: str|None=None, workload_id: str|None=None):
    # Determine required wickets — support both dict (new) and list (legacy) catalog format
    paths = catalog.get("attack_paths", {})
    if isinstance(paths, dict):
        ap = paths.get(attack_path_id)
    else:
        ap = next((x for x in paths
                   if x.get("attack_path_id") == attack_path_id
                   or x.get("id") == attack_path_id), None)
    if not ap:
        raise SystemExit(f"Unknown attack_path_id: {attack_path_id}")
    required = ap["required_wickets"]

    # Latest status per wicket: pick the most recent observed_at
    latest = {}
    latest_ts = {}
    for ev in events:
        if ev.get("type") != "obs.attack.precondition":
            continue
        payload = ev.get("payload", {})
        if payload.get("attack_path_id") != attack_path_id:
            continue
        wid = payload.get("wicket_id")
        if wid not in required:
            continue
        obs_at = payload.get("observed_at") or ev.get("ts")
        if not obs_at:
            continue
        if wid not in latest_ts or obs_at > latest_ts[wid]:
            latest_ts[wid] = obs_at
            latest[wid] = payload.get("status", "unknown")

    realized = [w for w in required if latest.get(w) == "realized"]
    blocked  = [w for w in required if latest.get(w) == "blocked"]
    unknown  = [w for w in required if latest.get(w) not in ("realized","blocked")]

    aprs = (len(realized) / len(required)) if required else 0.0
    if blocked:
        classification = "not_realized" if not unknown else "indeterminate"
    else:
        classification = "realized" if len(realized) == len(required) else "indeterminate"

    return {
        "attack_path_id": attack_path_id,
        "required_wickets": required,
        "latest_status": {w: latest.get(w, "unknown") for w in required},
        "realized": realized,
        "blocked": blocked,
        "unknown": unknown,
        "aprs": round(aprs, 6),
        "classification": classification,
        "computed_at": iso_now(),
        "run_id": run_id,
        "workload_id": workload_id,
        "derivation": {
            "rule": "aprs=|realized|/|required|; classification uses blocked/unknown sets",
            "notes": ap.get("notes","")
        }
    }

def emit_interp(payload, out_path: Path):
    env = {
        "id": f"interp-{payload['attack_path_id']}-{payload['computed_at']}",
        "ts": payload["computed_at"],
        "type": "interp.attack_path.realizability",
        "source": {"source_id":"projection.aprs","toolchain":"skg-aprs-toolchain","version":get_version()},
        "payload": payload,
        "provenance": {
            "evidence_rank": 1,
            "evidence": {"source_kind":"projection", "pointer":"projections/aprs/run.py", "collected_at": payload["computed_at"], "confidence": 1.0}
        }
    }
    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(env) + "\n")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="infile", required=True)
    _default_catalog = str(Path(__file__).resolve().parents[2] / "contracts/catalogs/attack_preconditions_catalog.aprs.v1.json")
    p.add_argument("--catalog", default=_default_catalog)
    p.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    p.add_argument("--out", dest="outfile", required=True)
    p.add_argument("--run-id", default=None, help="Run id to stamp on interpretation (UUID).")
    p.add_argument("--workload-id", default=None, help="Workload id to stamp on interpretation.")
    args = p.parse_args()

    events = list(read_ndjson(Path(args.infile)))
    catalog = load_catalog(Path(args.catalog))
    rid = args.run_id or None
    wid = args.workload_id or None
    if rid is None:
        # try infer from latest obs event
        for ev in reversed(events):
            if ev.get('type')=='obs.attack.precondition':
                rid = (ev.get('payload') or {}).get('run_id')
                if rid:
                    break
    if rid is None:
        import uuid as _uuid
        rid = str(_uuid.uuid4())
    if wid is None:
        for ev in reversed(events):
            if ev.get('type')=='obs.attack.precondition':
                wid = (ev.get('payload') or {}).get('workload_id')
                if wid:
                    break
    payload = compute_aprs(events, catalog, args.attack_path_id, run_id=rid, workload_id=wid)
    emit_interp(payload, Path(args.outfile))

if __name__ == "__main__":
    main()
