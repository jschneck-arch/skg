"""
skg-ai-toolchain :: projections/run.py

Deterministic projection engine for the ai_target domain.
Reads NDJSON observation events, evaluates wicket states against
attack path requirements, produces scored interpretation.

Usage:
  python run.py --in /var/lib/skg/discovery/gravity_ai_192.168.1.10.ndjson \
                --out /var/lib/skg/interp/ai_ai_target__192.168.1.10_run.json \
                --attack-path-id ai_llm_extract_v1
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parents[1] / "contracts" / "catalogs" / "ai_attack_preconditions_catalog.v1.json"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def compute_ai(events: list[dict], catalog: dict, attack_path_id: str,
               run_id: str | None = None, workload_id: str | None = None) -> dict:
    attack_paths = catalog["attack_paths"]

    if attack_path_id not in attack_paths:
        raise ValueError(
            f"Unknown attack path: {attack_path_id}. "
            f"Available: {list(attack_paths.keys())}"
        )

    ap = attack_paths[attack_path_id]
    required = ap["required_wickets"]
    optional = ap.get("optional_wickets", [])

    wicket_states = {}
    wicket_evidence = {}
    effective_workload_id = workload_id

    for event in events:
        payload = event.get("payload", {})
        provenance = event.get("provenance", {})
        evidence = provenance.get("evidence", {})

        wid = payload.get("wicket_id")
        status = payload.get("status")
        if not wid or not status:
            continue

        if not effective_workload_id:
            effective_workload_id = payload.get("workload_id", "")

        confidence = float(evidence.get("confidence", 0.8))
        detail = payload.get("detail", "")
        ev_rank = int(provenance.get("evidence_rank", 3))

        prev = wicket_states.get(wid)
        if prev is None or confidence > wicket_evidence.get(wid, {}).get("confidence", 0):
            wicket_states[wid] = status
            wicket_evidence[wid] = {
                "confidence": confidence,
                "detail": detail,
                "rank": ev_rank,
            }

    # Classify path realizability
    realized = [w for w in required if wicket_states.get(w) == "realized"]
    blocked  = [w for w in required if wicket_states.get(w) == "blocked"]
    unknown  = [w for w in required if w not in wicket_states or
                wicket_states[w] not in ("realized", "blocked")]

    opt_realized = [w for w in optional if wicket_states.get(w) == "realized"]

    n_req     = len(required)
    n_real    = len(realized)
    n_blocked = len(blocked)

    classification_detail = None
    if n_req == 0:
        classification = "indeterminate"
        classification_detail = "empty_required_set"
        score = 0.0
    elif n_real == n_req:
        classification = "realized"
        classification_detail = "fully_realized"
        score = 1.0
    elif n_blocked > 0:
        classification = "not_realized"
        classification_detail = "blocked"
        score = 0.0
    elif n_real > 0:
        classification = "indeterminate"
        classification_detail = "partial"
        score = n_real / n_req
    else:
        classification = "indeterminate"
        classification_detail = "no_positive_observations"
        score = 0.0

    # Optional wickets boost score
    if opt_realized:
        score = min(1.0, score + 0.05 * len(opt_realized))

    return {
        "schema_version": "1.0",
        "computed_at": iso_now(),
        "run_id": run_id,
        "workload_id": effective_workload_id or "",
        "domain": "ai_target",
        "attack_path_id": attack_path_id,
        "classification": classification,
        "classification_detail": classification_detail,
        "ai_score": round(score, 4),
        "realized": realized,
        "blocked": blocked,
        "unknown": unknown,
        "optional_realized": opt_realized,
        "required_wickets": required,
        "latest_status": wicket_states,
        "evidence": wicket_evidence,
        "summary": {
            "required_total": n_req,
            "realized_count": n_real,
            "blocked_count": n_blocked,
            "unknown_count": len(unknown),
        },
    }


def project(events_path: str, out_path: str, attack_path_id: str,
            run_id: str | None = None, workload_id: str | None = None):
    catalog = load_catalog()
    events_file = Path(events_path)
    if not events_file.exists():
        raise FileNotFoundError(f"Events file not found: {events_path}")

    events = []
    with open(events_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    interp = compute_ai(events, catalog, attack_path_id, run_id=run_id, workload_id=workload_id)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(interp, indent=2), encoding="utf-8")
    return interp


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--in",   dest="events",  required=True)
    parser.add_argument("--out",  dest="out",      required=True)
    parser.add_argument("--run-id", dest="run_id", default=None)
    parser.add_argument("--workload-id", dest="workload_id", default=None)
    parser.add_argument("--attack-path-id", dest="apid",
                        default="ai_llm_extract_v1")
    args = parser.parse_args()

    result = project(args.events, args.out, args.apid,
                     run_id=args.run_id, workload_id=args.workload_id)
    print(f"[AI-PROJ] {result['classification']}  "
          f"score={result['ai_score']:.2f}  "
          f"realized={result['realized']}")
