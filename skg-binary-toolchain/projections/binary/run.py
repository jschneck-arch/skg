#!/usr/bin/env python3
"""Binary analysis projection engine."""
import argparse, json, uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-binary-toolchain"

def iso_now(): return datetime.now(timezone.utc).isoformat()

def compute_binary_score(events, catalog, attack_path_id, run_id=None, workload_id=None):
    ap = catalog.get("attack_paths", {}).get(attack_path_id)
    if not ap: return {}
    required = ap.get("required_wickets", [])
    latest, latest_ts = {}, {}
    for ev in events:
        if ev.get("type") != "obs.attack.precondition": continue
        p = ev.get("payload", {}); wid = p.get("wicket_id","")
        if wid not in required: continue
        ts = ev.get("ts","")
        if wid not in latest_ts or ts > latest_ts[wid]:
            latest_ts[wid] = ts; latest[wid] = p.get("status","unknown")
    realized = [w for w in required if latest.get(w)=="realized"]
    blocked  = [w for w in required if latest.get(w)=="blocked"]
    unknown  = [w for w in required if latest.get(w,"unknown")=="unknown"]
    cls = ("not_realized" if blocked else "indeterminate" if unknown else "realized")
    sheaf_data = {}
    try:
        import sys as _s; _s.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from skg.topology.sheaf import classify_with_sheaf
        cls, sheaf_data = classify_with_sheaf(cls, catalog, attack_path_id,
                                               realized, blocked, unknown)
    except Exception: pass
    return {"id": str(uuid.uuid4()), "ts": iso_now(),
            "type": "interp.binary.realizability",
            "source": {"source_id":"projection.binary","toolchain":TOOLCHAIN},
            "payload": {"attack_path_id":attack_path_id,"workload_id":workload_id or "unknown",
                        "run_id":run_id or str(uuid.uuid4()),"classification":cls,
                        "binary_score":round(len(realized)/len(required),6) if required else 0.0,
                        "required_wickets":required,"realized":realized,
                        "blocked":blocked,"unknown":unknown,"sheaf":sheaf_data,
                        "computed_at":iso_now()}}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--in",dest="infile",required=True)
    p.add_argument("--out",dest="outfile",required=True)
    p.add_argument("--attack-path-id",required=True)
    p.add_argument("--workload-id",default=None)
    p.add_argument("--catalog",default=None)
    a = p.parse_args()
    cat_path = Path(a.catalog) if a.catalog else next(
        (Path(__file__).resolve().parents[2]/"contracts"/"catalogs").glob("*.json"))
    catalog = json.loads(cat_path.read_text())
    events  = [json.loads(l) for l in Path(a.infile).read_text().splitlines() if l.strip()]
    result  = compute_binary_score(events, catalog, a.attack_path_id, workload_id=a.workload_id)
    if not result: raise SystemExit(f"Unknown path: {a.attack_path_id}")
    Path(a.outfile).parent.mkdir(parents=True,exist_ok=True)
    Path(a.outfile).write_text(json.dumps(result, indent=2))
    p2 = result["payload"]
    print(f"  {p2['attack_path_id']}: {p2['classification']} ({len(p2['realized'])}R {len(p2['blocked'])}B {len(p2['unknown'])}U)")

if __name__ == "__main__": main()
