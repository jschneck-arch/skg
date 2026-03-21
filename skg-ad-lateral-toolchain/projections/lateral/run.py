#!/usr/bin/env python3
"""
projection: lateral
====================
Deterministic tri-state projection engine for AD lateral movement attack paths.
Same logic as skg-aprs-toolchain and skg-container-escape-toolchain.

Score: LATERAL = |realized| / |required|
Classification:
  realized      — all wickets realized, none blocked
  not_realized  — any wicket blocked
  indeterminate — unknowns present
"""

import argparse, json, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-ad-lateral-toolchain"
SOURCE_ID = "projection.lateral"


def get_version() -> str:
    v = Path(__file__).resolve().parents[2] / "VERSION"
    return v.read_text(encoding="utf-8").strip() if v.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_catalog(catalog_path: Path) -> dict:
    return json.loads(catalog_path.read_text(encoding="utf-8"))


def load_events(events_path: Path, attack_path_id: str,
                run_id: str | None, workload_id: str | None) -> list[dict]:
    events = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("type") != "obs.attack.precondition":
            continue
        payload = obj.get("payload", {})
        if payload.get("attack_path_id") != attack_path_id:
            continue
        if run_id and payload.get("run_id") != run_id:
            continue
        if workload_id and payload.get("workload_id") != workload_id:
            continue
        events.append(obj)
    return events


def compute_lateral(events: list[dict], catalog: dict,
                    attack_path_id: str,
                    run_id: str | None = None,
                    workload_id: str | None = None) -> dict:
    paths = catalog.get("attack_paths", {})
    if attack_path_id not in paths:
        raise ValueError(f"Attack path '{attack_path_id}' not in catalog")

    required = paths[attack_path_id]["required_wickets"]

    # Route through the canonical substrate projection engine.
    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "..", "..", "..", "skg"))
        from skg.substrate.projection import load_states_from_events_priority, project_path
        from skg.substrate.path import Path as _Path
        node_states = load_states_from_events_priority(events, required=required)
        path_obj = _Path(path_id=attack_path_id, required_nodes=required)
        ps = project_path(path_obj, node_states,
                          workload_id=workload_id or "", run_id=run_id or "")
        realized       = ps.realized
        blocked        = ps.blocked
        unknown        = ps.unknown
        latest_status  = ps.latest_status
        classification = ps.classification
        score          = ps.score
    except Exception:
        # Fallback to local accumulation if substrate import fails
        wicket_status: dict[str, str] = {}
        for event in events:
            payload = event.get("payload", {})
            wid    = payload.get("wicket_id")
            status = payload.get("status")
            if wid not in required:
                continue
            if wid not in wicket_status:
                wicket_status[wid] = status
            else:
                current = wicket_status[wid]
                if status == "blocked":
                    wicket_status[wid] = "blocked"
                elif status == "realized" and current == "unknown":
                    wicket_status[wid] = "realized"
        realized = [w for w in required if wicket_status.get(w) == "realized"]
        blocked  = [w for w in required if wicket_status.get(w) == "blocked"]
        unknown  = [w for w in required if wicket_status.get(w, "unknown") == "unknown"]
        score = round(len(realized) / len(required), 6) if required else 0.0
        if not blocked and not unknown:
            classification = "realized"
        elif blocked:
            classification = "not_realized"
        else:
            classification = "indeterminate"
        latest_status = {w: wicket_status.get(w, "unknown") for w in required}

    # H¹ sheaf obstruction — refines indeterminate into indeterminate_h1
    # when mutual dependency cycles prevent resolution by observation alone
    sheaf_data = {}
    try:
        import sys as _sys, pathlib as _pl
        _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[4]))
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
        "attack_path_id":  attack_path_id,
        "required_wickets": required,
        "latest_status":   latest_status,
        "realized":        realized,
        "blocked":         blocked,
        "unknown":         unknown,
        "lateral_score":   score,
        "classification":  classification,
            "sheaf":           sheaf_data,
        "workload_id":     workload_id,
        "run_id":          run_id,
        "computed_at":     iso_now(),
        "derivation": {
            "rule": "lateral_score=|realized|/|required|; classification uses blocked/unknown sets",
            "engine": f"{TOOLCHAIN}/projections/lateral/run.py",
            "version": get_version(),
        },
    }


def emit_interp(out_path: Path, payload: dict):
    now = iso_now()
    event = {
        "id":  str(uuid.uuid4()),
        "ts":  now,
        "type": "interp.ad_lateral.realizability",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version":   get_version(),
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": 1,
            "evidence": {
                "source_kind": "projection",
                "pointer":     "projections/lateral/run.py",
                "collected_at": payload["computed_at"],
                "confidence":  1.0,
            },
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def main():
    p = argparse.ArgumentParser(description="AD lateral movement projection engine")
    p.add_argument("--in",  dest="events_in", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--attack-path-id", required=True)
    p.add_argument("--run-id",      default=None)
    p.add_argument("--workload-id", default=None)
    p.add_argument("--catalog",     default=None)
    args = p.parse_args()

    root = Path(__file__).resolve().parents[2]
    catalog_path = Path(args.catalog) if args.catalog else (
        root / "contracts" / "catalogs" / "attack_preconditions_catalog.ad_lateral.v1.json"
    )

    catalog = load_catalog(catalog_path)
    events  = load_events(Path(args.events_in), args.attack_path_id,
                          args.run_id, args.workload_id)

    payload = compute_lateral(events, catalog, args.attack_path_id,
                              run_id=args.run_id, workload_id=args.workload_id)
    emit_interp(Path(args.out), payload)

    print(f"[OK] {args.attack_path_id}: score={payload['lateral_score']} "
          f"classification={payload['classification']} → {args.out}")


if __name__ == "__main__":
    main()
