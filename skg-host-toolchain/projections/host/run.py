#!/usr/bin/env python3
"""
projections/host/run.py
=======================
Projection engine for the host toolchain. Same substrate logic as the
APRS and container escape projections: read obs.attack.precondition events,
compute latest wicket states, score the requested attack path.

Tri-state: realized / blocked / unknown
Score: |realized| / |required|
Classification: realized | not_realized | indeterminate
"""

import argparse, json, sys, uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skg.kernel.adapters import event_to_observation
from skg.kernel.state import CollapseThresholds, StateEngine
from skg.kernel.support import SupportEngine


def get_version() -> str:
    try:
        return Path(__file__).resolve().parents[2].joinpath("VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"


def read_ndjson(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


def load_catalog(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _target_for_events(events, workload_id: str | None = None) -> str:
    if workload_id:
        return workload_id.split("::")[-1]
    for ev in reversed(events):
        payload = ev.get("payload", {})
        target = payload.get("target_ip") or payload.get("workload_id")
        if target:
            return target
    return "unknown"


def _support_statuses(events, required: list[str], workload_id: str | None = None) -> dict[str, str]:
    observations = []
    for ev in events:
        obs = event_to_observation(ev)
        if obs is None or obs.context not in required:
            continue
        observations.append(obs)

    if not observations:
        return {w: "unknown" for w in required}

    as_of = max(obs.event_time for obs in observations)
    target = _target_for_events(events, workload_id)
    support = SupportEngine()
    state = StateEngine(CollapseThresholds(realized=0.5, blocked=0.5))
    latest = {}
    for wicket_id in required:
        contrib = support.aggregate(observations, target, wicket_id, as_of)
        latest[wicket_id] = state.collapse(contrib).value
    return latest


def compute_host_score(events, catalog: dict, attack_path_id: str,
                        run_id: str = None, workload_id: str = None) -> dict:
    paths = catalog.get("attack_paths", {})
    ap = paths.get(attack_path_id)
    if not ap:
        raise SystemExit(f"Unknown attack_path_id: {attack_path_id}")
    required = ap["required_wickets"]

    latest = _support_statuses(events, required, workload_id=workload_id)

    realized = [w for w in required if latest.get(w) == "realized"]
    blocked  = [w for w in required if latest.get(w) == "blocked"]
    unknown  = [w for w in required if latest.get(w) not in ("realized", "blocked")]

    score = round(len(realized) / len(required), 6) if required else 0.0

    if blocked:
        classification = "not_realized"
    else:
        classification = "realized" if len(realized) == len(required) else "indeterminate"

    # Refine indeterminate classification with H¹ sheaf obstruction analysis.
    # indeterminate_h1 means the path is structurally stuck — more observation
    # will not resolve it; the constraint surface must change.
    sheaf_data = {}
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
        from skg.topology.sheaf import classify_with_sheaf
        classification, sheaf_data = classify_with_sheaf(
            classification, catalog, attack_path_id,
            realized, blocked, unknown
        )
    except Exception:
        pass  # sheaf analysis optional — never breaks projection

    return {
        "attack_path_id":   attack_path_id,
        "required_wickets": required,
        "latest_status":    {w: latest.get(w, "unknown") for w in required},
        "realized":         realized,
        "blocked":          blocked,
        "unknown":          unknown,
        "host_score":       score,
        "classification":   classification,
        "sheaf":            sheaf_data,
        "computed_at":      iso_now(),
        "run_id":           run_id,
        "workload_id":      workload_id,
        "derivation": {
            "rule": "host_score=|realized|/|required|; wickets collapse from aggregated support before path classification",
            "h1_note": (
                "indeterminate_h1 means H¹ obstruction detected — "
                "mutual dependency cycle prevents global section. "
                "Further observation will not resolve; constraint must change."
                if classification == "indeterminate_h1" else ""
            ),
            "notes":      ap.get("notes", ""),
            "references": ap.get("references", []),
        },
    }


def emit_interp(payload: dict, out_path: Path):
    env = {
        "id": f"interp-{payload['attack_path_id']}-{payload['computed_at']}",
        "ts": payload["computed_at"],
        "type": "interp.host.realizability",
        "source": {
            "source_id": "projection.host",
            "toolchain": "skg-host-toolchain",
            "version": get_version(),
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": 1,
            "evidence": {
                "source_kind": "projection",
                "pointer": "projections/host/run.py",
                "collected_at": payload["computed_at"],
                "confidence": 1.0,
            },
        },
    }
    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(env) + "\n")


def main():
    _default_catalog = str(
        Path(__file__).resolve().parents[2]
        / "contracts/catalogs/attack_preconditions_catalog.host.v1.json"
    )
    p = argparse.ArgumentParser()
    p.add_argument("--in",    dest="infile",  required=True)
    p.add_argument("--out",   dest="outfile", required=True)
    p.add_argument("--attack-path-id", default="host_ssh_initial_access_v1")
    p.add_argument("--catalog", default=_default_catalog)
    p.add_argument("--run-id", default=None)
    p.add_argument("--workload-id", default=None)
    args = p.parse_args()

    events = list(read_ndjson(Path(args.infile)))
    catalog = load_catalog(Path(args.catalog))

    rid = args.run_id
    wid = args.workload_id
    if rid is None:
        for ev in reversed(events):
            if ev.get("type") == "obs.attack.precondition":
                rid = (ev.get("payload") or {}).get("run_id")
                if rid:
                    break
    if rid is None:
        rid = str(uuid.uuid4())
    if wid is None:
        for ev in reversed(events):
            if ev.get("type") == "obs.attack.precondition":
                wid = (ev.get("payload") or {}).get("workload_id")
                if wid:
                    break

    payload = compute_host_score(events, catalog, args.attack_path_id,
                                  run_id=rid, workload_id=wid)
    emit_interp(payload, Path(args.outfile))


if __name__ == "__main__":
    main()
