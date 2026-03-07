#!/usr/bin/env python3
"""
projections/web/run.py
=======================
Projection engine for the web toolchain.
Same substrate as all SKG projectors — tri-state, score, classify.
"""
import argparse, json, uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-web-toolchain"
SOURCE_ID = "projection.web"


def get_version():
    try:
        return (Path(__file__).resolve().parents[2] / "VERSION").read_text().strip()
    except Exception:
        return "0.0.0"


def iso_now():
    return datetime.now(timezone.utc).isoformat()


def compute_web(events, catalog: dict, attack_path_id: str,
                run_id: str = None, workload_id: str = None) -> dict:
    """In-process projection — called by skg.sensors.projector."""
    paths = catalog.get("attack_paths", {})
    ap = paths.get(attack_path_id)
    if not ap:
        return {}
    required = ap.get("required_wickets", [])

    latest: dict[str, str] = {}
    latest_ts: dict[str, str] = {}
    for ev in events:
        if ev.get("type") != "obs.attack.precondition":
            continue
        payload = ev.get("payload", {})
        wid = payload.get("wicket_id")
        ts  = ev.get("ts", "")
        if wid in required:
            if wid not in latest_ts or ts > latest_ts[wid]:
                latest[wid]    = payload.get("status", "unknown")
                latest_ts[wid] = ts

    realized = [w for w in required if latest.get(w) == "realized"]
    blocked  = [w for w in required if latest.get(w) == "blocked"]
    unknown  = [w for w in required if latest.get(w, "unknown") == "unknown"]

    if blocked:
        classification = "not_realized"
    elif unknown:
        classification = "indeterminate"
    else:
        classification = "realized"

    score  = len(realized) / len(required) if required else 0.0
    run_id = run_id or str(uuid.uuid4())[:8]

    return {
        "id": str(uuid.uuid4()), "ts": iso_now(),
        "type": "interp.attack.path",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN,
                   "version": get_version()},
        "payload": {
            "attack_path_id":   attack_path_id,
            "workload_id":      workload_id or "unknown",
            "run_id":           run_id,
            "classification":   classification,
            "web_score":        round(score, 4),
            "required_wickets": required,
            "realized":         realized,
            "blocked":          blocked,
            "unknown":          unknown,
            "latest_status":    latest,
            "computed_at":      iso_now(),
        },
    }


def main():
    p = argparse.ArgumentParser(description="Web surface projection engine")
    p.add_argument("--in",  dest="infile",  required=True)
    p.add_argument("--out", dest="outfile", required=True)
    p.add_argument("--attack-path-id", default="web_initial_access_v1")
    p.add_argument("--workload-id",    default=None)
    p.add_argument("--run-id",         default=None)
    a = p.parse_args()

    catalog_dir = Path(__file__).resolve().parents[2] / "contracts" / "catalogs"
    catalogs = list(catalog_dir.glob("*.json"))
    if not catalogs:
        raise SystemExit("No catalog found")
    catalog = json.loads(catalogs[0].read_text())

    events = []
    for line in Path(a.infile).read_text().splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except Exception:
                pass

    result = compute_web(events, catalog, a.attack_path_id,
                         run_id=a.run_id, workload_id=a.workload_id)
    if result:
        Path(a.outfile).write_text(json.dumps(result, indent=2))
    else:
        raise SystemExit(f"Unknown attack_path_id: {a.attack_path_id}")


if __name__ == "__main__":
    main()
