#!/usr/bin/env python3
"""
projections/metacognition/run.py
=================================
Projection engine for the metacognition toolchain.
Same substrate logic as all SKG projectors: tri-state, score, classify.

Consumes obs.substrate.node events produced by:
  - adapter.confidence_elicitation  (MC-01, MC-06)
  - adapter.review_revision         (MC-02, MC-04, MC-05)
  - adapter.known_unknown           (MC-03, MC-07, MC-08)

Scores a requested capability path from the metacognition catalog.
"""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-metacognition-toolchain"
SOURCE_ID = "projection.metacognition"
SCORE_KEY = "metacognition_score"


def get_version() -> str:
    try:
        return Path(__file__).resolve().parents[2].joinpath("VERSION").read_text(
            encoding="utf-8"
        ).strip()
    except Exception:
        return "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_ndjson(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def load_catalog(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def compute_metacognition_score(
    events,
    catalog: dict,
    capability_path_id: str,
    run_id: str | None = None,
    workload_id: str | None = None,
) -> dict:
    run_id = run_id or str(uuid.uuid4())
    paths = catalog.get("attack_paths", {})
    cap_path = paths.get(capability_path_id)
    if not cap_path:
        raise SystemExit(f"Unknown capability_path_id: {capability_path_id}")

    required = cap_path["required_wickets"]

    # Highest-priority state wins per wicket: blocked > realized > unknown
    _PRIORITY = {"blocked": 2, "realized": 1, "unknown": 0}
    latest: dict[str, str] = {}
    latest_priority: dict[str, int] = {}
    latest_confidence: dict[str, float] = {}
    latest_notes: dict[str, str] = {}

    for ev in events:
        if ev.get("type") not in ("obs.substrate.node", "obs.attack.precondition"):
            continue
        payload = ev.get("payload", {})
        wid = payload.get("node_id") or payload.get("wicket_id", "")
        if wid not in required:
            continue
        status = payload.get("status", "unknown")
        priority = _PRIORITY.get(status, 0)
        if priority > latest_priority.get(wid, -1):
            latest[wid] = status
            latest_priority[wid] = priority
            prov = ev.get("provenance", {}).get("evidence", {})
            latest_confidence[wid] = float(prov.get("confidence", 0.5))
            latest_notes[wid] = payload.get("notes", "")

    realized = [w for w in required if latest.get(w) == "realized"]
    blocked  = [w for w in required if latest.get(w) == "blocked"]
    unknown  = [w for w in required if latest.get(w) not in ("realized", "blocked")]

    score = round(len(realized) / len(required), 6) if required else 0.0

    # Tri-state classification — same semantics as all SKG projectors
    if len(realized) == len(required):
        classification = "realized"
    elif blocked and not unknown:
        classification = "not_realized"
    else:
        classification = "indeterminate"

    # Field energy E: number of unknown wickets (per Work 3 Section 3.2)
    field_energy = len(unknown)

    return {
        "capability_path_id": capability_path_id,
        "path_description":   cap_path.get("description", ""),
        "required_wickets":   required,
        "latest_status":      {w: latest.get(w, "unknown") for w in required},
        "latest_confidence":  {w: round(latest_confidence.get(w, 0.0), 4) for w in required},
        "latest_notes":       {w: latest_notes.get(w, "") for w in required},
        "realized":           realized,
        "blocked":            blocked,
        "unknown":            unknown,
        SCORE_KEY:            score,
        "classification":     classification,
        "field_energy":       field_energy,
        "run_id":             run_id,
        "workload_id":        workload_id or "",
        "toolchain":          TOOLCHAIN,
        "toolchain_version":  get_version(),
        "computed_at":        iso_now(),
    }


def emit_result(result: dict, source_id: str = SOURCE_ID) -> dict:
    """Wrap projection result as an obs.projection.result envelope event."""
    return {
        "type": "obs.projection.result",
        "ts": iso_now(),
        "schema_version": "1.0.0",
        "source": {
            "id": source_id,
            "toolchain": TOOLCHAIN,
            "version": result["toolchain_version"],
        },
        "payload": result,
        "run_id": result.get("run_id", ""),
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Metacognition projection engine — scores a capability path"
    )
    ap.add_argument(
        "--events", required=True,
        help="NDJSON file of obs.substrate.node events from adapters",
    )
    ap.add_argument(
        "--catalog", required=True,
        help="Path to attack_preconditions_catalog.metacognition.v1.json",
    )
    ap.add_argument(
        "--path-id", required=True,
        help="Capability path ID to score (e.g. meta_full_v1)",
    )
    ap.add_argument("--out", default=None, help="Output path for projection result NDJSON")
    ap.add_argument("--workload-id", default="")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    events = list(read_ndjson(Path(args.events)))
    catalog = load_catalog(Path(args.catalog))

    result = compute_metacognition_score(
        events=events,
        catalog=catalog,
        capability_path_id=args.path_id,
        run_id=args.run_id,
        workload_id=args.workload_id,
    )

    envelope = emit_result(result)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")

    # Human-readable summary
    r = result
    print(f"\n{'='*60}")
    print(f"  Capability path : {r['capability_path_id']}")
    print(f"  Description     : {r['path_description']}")
    print(f"  Classification  : {r['classification'].upper()}")
    print(f"  Score           : {r[SCORE_KEY]:.2%}  ({len(r['realized'])}/{len(r['required_wickets'])} wickets realized)")
    print(f"  Field energy E  : {r['field_energy']} unknown wickets")
    print(f"{'='*60}")
    print(f"  {'Wicket':<8}  {'Status':<14}  {'Conf':>6}  Notes")
    print(f"  {'-'*8}  {'-'*14}  {'-'*6}  -----")
    for w in r["required_wickets"]:
        s = r["latest_status"].get(w, "unknown")
        c = r["latest_confidence"].get(w, 0.0)
        n = r["latest_notes"].get(w, "")[:60]
        marker = "✓" if s == "realized" else ("✗" if s == "blocked" else "?")
        print(f"  {w:<8}  {marker} {s:<12}  {c:>6.2f}  {n}")

    if r["field_energy"] > 0:
        print(f"\n  E = {r['field_energy']}: the following wickets remain unmeasured:")
        for w in r["unknown"]:
            print(f"    {w}")
        print(f"  These are not failures — they are unknowns.")

    print()


if __name__ == "__main__":
    main()
