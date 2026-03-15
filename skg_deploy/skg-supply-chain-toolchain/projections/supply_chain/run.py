#!/usr/bin/env python3
"""
projections/supply_chain/run.py
================================
Projection engine for the supply chain toolchain.

Same substrate logic as every other domain.
Reads obs.attack.precondition events with SC-* wicket IDs,
computes latest tri-state per wicket, scores the failure path,
optionally applies sheaf H¹ obstruction analysis.
"""
import argparse, json, uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-supply-chain-toolchain"
SOURCE_ID = "projection.supply_chain"


def get_version() -> str:
    try:
        return (Path(__file__).resolve().parents[2] / "VERSION").read_text().strip()
    except Exception:
        return "1.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_supply_chain_score(
    events: list[dict],
    catalog: dict,
    attack_path_id: str,
    run_id: str = None,
    workload_id: str = None,
) -> dict:
    paths    = catalog.get("attack_paths", {})
    ap       = paths.get(attack_path_id)
    if not ap:
        return {}
    required = ap.get("required_wickets", [])

    latest:    dict[str, str] = {}
    latest_ts: dict[str, str] = {}
    for ev in events:
        if ev.get("type") != "obs.attack.precondition":
            continue
        p   = ev.get("payload", {})
        wid = p.get("wicket_id", "")
        if wid not in required:
            continue
        ts = ev.get("ts", "")
        if wid not in latest_ts or ts > latest_ts[wid]:
            latest_ts[wid] = ts
            latest[wid]    = p.get("status", "unknown")

    realized = [w for w in required if latest.get(w) == "realized"]
    blocked  = [w for w in required if latest.get(w) == "blocked"]
    unknown  = [w for w in required if latest.get(w, "unknown") == "unknown"]

    if blocked:
        classification = "not_realized"
    elif unknown:
        classification = "indeterminate"
    else:
        classification = "realized"

    score = round(len(realized) / len(required), 6) if required else 0.0

    # H¹ sheaf obstruction
    sheaf_data = {}
    try:
        import sys as _sys, pathlib as _pl
        _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[4]))
        from skg.topology.sheaf import classify_with_sheaf
        classification, sheaf_data = classify_with_sheaf(
            classification, catalog, attack_path_id,
            realized, blocked, unknown
        )
    except Exception:
        pass

    return {
        "id":   str(uuid.uuid4()),
        "ts":   iso_now(),
        "type": "interp.supply_chain.realizability",
        "source": {
            "source_id": SOURCE_ID, "toolchain": TOOLCHAIN,
            "version":   get_version(),
        },
        "payload": {
            "attack_path_id":   attack_path_id,
            "workload_id":      workload_id or "unknown",
            "run_id":           run_id or str(uuid.uuid4()),
            "classification":   classification,
            "supply_chain_score": score,
            "required_wickets": required,
            "realized":         realized,
            "blocked":          blocked,
            "unknown":          unknown,
            "latest_status":    {w: latest.get(w, "unknown") for w in required},
            "sheaf":            sheaf_data,
            "computed_at":      iso_now(),
        },
    }


def main():
    p = argparse.ArgumentParser(description="Supply chain projection engine")
    p.add_argument("--in",  dest="infile",  required=True)
    p.add_argument("--out", dest="outfile", required=True)
    p.add_argument("--attack-path-id", required=True)
    p.add_argument("--workload-id",    default=None)
    p.add_argument("--run-id",         default=None)
    p.add_argument("--catalog",        default=None)
    a = p.parse_args()

    if a.catalog:
        catalog_path = Path(a.catalog)
    else:
        catalog_dir  = Path(__file__).resolve().parents[2] / "contracts" / "catalogs"
        catalogs     = sorted(catalog_dir.glob("*.json"))
        if not catalogs:
            raise SystemExit("No catalog found")
        catalog_path = catalogs[0]

    catalog = json.loads(catalog_path.read_text())
    events  = []
    for line in Path(a.infile).read_text().splitlines():
        if line.strip():
            try:
                events.append(json.loads(line))
            except Exception:
                pass

    result = compute_supply_chain_score(
        events, catalog, a.attack_path_id,
        run_id=a.run_id, workload_id=a.workload_id
    )
    if not result:
        raise SystemExit(f"Unknown attack_path_id: {a.attack_path_id}")

    Path(a.outfile).parent.mkdir(parents=True, exist_ok=True)
    Path(a.outfile).write_text(json.dumps(result, indent=2))

    payload = result["payload"]
    print(f"  {payload['attack_path_id']}: {payload['classification']} "
          f"({len(payload['realized'])}R {len(payload['blocked'])}B "
          f"{len(payload['unknown'])}U)")


if __name__ == "__main__":
    main()
