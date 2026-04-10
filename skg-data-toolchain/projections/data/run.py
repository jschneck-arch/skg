#!/usr/bin/env python3
"""
projections/data/run.py
========================
Projection engine for the data pipeline domain.

Same substrate logic as every other toolchain:
  - Read obs.attack.precondition events (DP-* wickets)
  - Compute latest tri-state per wicket
  - Score the requested failure path
  - Emit interp result

Tri-state semantics in data context:
  realized  — condition confirmed present and valid
  blocked   — constraint prevents this condition (NULL violation, FK broken)
  unknown   — not yet measured

Classification:
  realized      — all required wickets realized → pipeline stage is valid
  not_realized  — any wicket blocked → definite failure condition present
  indeterminate — some unknowns remain → cannot determine validity
"""
import argparse, json, uuid
from datetime import datetime, timezone
from pathlib import Path


TOOLCHAIN = "skg-data-toolchain"
SOURCE_ID = "projection.data"


def get_version() -> str:
    try:
        return (Path(__file__).resolve().parents[2] / "VERSION").read_text().strip()
    except Exception:
        return "0.1.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_data_score(events: list[dict], catalog: dict,
                       attack_path_id: str,
                       run_id: str = None,
                       workload_id: str = None) -> dict:
    """
    Core projection computation — domain-agnostic substrate logic applied
    to data pipeline wickets.
    """
    paths = catalog.get("attack_paths", {})
    ap    = paths.get(attack_path_id)
    if not ap:
        return {}
    required = ap.get("required_wickets", [])

    # Pick latest observation per wicket by timestamp
    latest:    dict[str, str] = {}
    latest_ts: dict[str, str] = {}
    for ev in events:
        if ev.get("type") != "obs.attack.precondition":
            continue
        payload = ev.get("payload", {})
        wid     = payload.get("wicket_id")
        if wid not in required:
            continue
        ts = ev.get("ts", "")
        if wid not in latest_ts or ts > latest_ts[wid]:
            latest_ts[wid] = ts
            latest[wid]    = payload.get("status", "unknown")

    realized = [w for w in required if latest.get(w) == "realized"]
    blocked  = [w for w in required if latest.get(w) == "blocked"]
    unknown  = [w for w in required if latest.get(w, "unknown") == "unknown"]

    # Tri-state projection — same formula as every domain
    if blocked:
        classification = "not_realized"
    elif unknown:
        classification = "indeterminate"
    else:
        classification = "realized"

    score  = round(len(realized) / len(required), 6) if required else 0.0
    run_id = run_id or str(uuid.uuid4())

    # H¹ sheaf obstruction — refines indeterminate into indeterminate_h1
    # when mutual dependency cycles prevent resolution by observation alone
    sheaf_data = {}
    try:
        import sys as _sys, pathlib as _pl
        _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[3]))
        from skg.topology.sheaf import classify_with_sheaf
        classification, sheaf_data = classify_with_sheaf(
            classification, catalog, attack_path_id,
            realized, blocked, unknown
        )
        if classification == "indeterminate_h1":
            sheaf_data = dict(sheaf_data or {})
            sheaf_data["classification_detail"] = "indeterminate_h1"
            classification = "indeterminate"
    except Exception:
        pass
    return {
        "id":   str(uuid.uuid4()),
        "ts":   iso_now(),
        "type": "interp.data.pipeline",
        "source": {
            "source_id":  SOURCE_ID,
            "toolchain":  TOOLCHAIN,
            "version":    get_version(),
        },
        "payload": {
            "attack_path_id":   attack_path_id,
            "failure_class":    ap.get("failure_class", "unknown"),
            "workload_id":      workload_id or "unknown",
            "run_id":           run_id,
            "classification":   classification,
            "sheaf":            sheaf_data,
            "data_score":       score,
            "required_wickets": required,
            "realized":         realized,
            "blocked":          blocked,
            "unknown":          unknown,
            "latest_status":    {w: latest.get(w, "unknown") for w in required},
            "computed_at":      iso_now(),
            "domains":          ap.get("domains", []),
            "interpretation": (
                "Pipeline stage valid — all conditions confirmed"
                if classification == "realized"
                else (
                    "Definite failure — constraint violated or condition blocked"
                    if classification == "not_realized"
                    else "Cannot determine — measurement incomplete"
                )
            ),
        },
    }


def main():
    p = argparse.ArgumentParser(description="Data pipeline projection engine")
    p.add_argument("--in",  dest="infile",  required=True)
    p.add_argument("--out", dest="outfile", required=True)
    p.add_argument("--attack-path-id", required=True)
    p.add_argument("--workload-id",    default=None)
    p.add_argument("--run-id",         default=None)
    p.add_argument("--catalog",        default=None)
    a = p.parse_args()

    # Load catalog
    if a.catalog:
        catalog_path = Path(a.catalog)
    else:
        catalog_dir  = Path(__file__).resolve().parents[2] / "contracts" / "catalogs"
        catalogs     = list(catalog_dir.glob("*.json"))
        if not catalogs:
            raise SystemExit("No catalog found")
        catalog_path = catalogs[0]

    catalog = json.loads(catalog_path.read_text())

    # Load events
    events = []
    for line in Path(a.infile).read_text().splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except Exception:
                pass

    result = compute_data_score(events, catalog, a.attack_path_id,
                                run_id=a.run_id, workload_id=a.workload_id)
    if not result:
        raise SystemExit(f"Unknown attack_path_id: {a.attack_path_id}")

    Path(a.outfile).parent.mkdir(parents=True, exist_ok=True)
    Path(a.outfile).write_text(json.dumps(result, indent=2))

    p = result["payload"]
    print(f"  {p['attack_path_id']}: {p['classification']} "
          f"({len(p['realized'])}R {len(p['blocked'])}B {len(p['unknown'])}U)")


if __name__ == "__main__":
    main()
