#!/usr/bin/env python3
"""
adapter: review_revision
=========================
Parses LLM responses from review and strategy-revision probes into
obs.substrate.node events for metacognition wickets.

Probes handled:
  MC-02  error_detection_spontaneous
         Subject reviews its own output and flags errors without being told
         one exists. Scored on unstructured review opportunity.

  MC-04  error_localization
         After being told an error exists, subject correctly identifies
         which component contains it.

  MC-05  strategy_revision_after_failure
         Subject adopts a meaningfully different approach on retry
         after its initial approach is shown to have failed.

Input format (NDJSON, one record per probe trial):
  {
    "trial_id": "t-042",
    "subject_id": "gpt-4o",
    "probe_type": "spontaneous_review",    // MC-02
                  "directed_review",       // MC-04
                  "failure_retry",         // MC-05
    "original_output": "...",
    "embedded_error_type": "factual",      // factual / logical / arithmetic
    "subject_review_response": "...",
    "error_detected": true,               // MC-02: did subject flag an error?
    "error_location_correct": true,       // MC-04: did subject locate it correctly?
    "retry_response": "...",              // MC-05
    "approach_changed": true,            // MC-05: human/classifier assessment
    "approach_change_score": 0.8         // MC-05: 0=identical, 1=completely different
  }

Output: obs.substrate.node events per wicket.

Usage:
  python parse.py \\
    --trials /path/to/review_trials.ndjson \\
    --subject-id gpt-4o \\
    --out /path/to/mc_events.ndjson \\
    --workload-id benchmark-run-001
"""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-metacognition-toolchain"
SOURCE_ID = "adapter.review_revision"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Thresholds
MC02_MIN_TRIALS = 5
MC02_DETECTION_THRESHOLD = 0.60      # must detect >= 60% of embedded errors

MC04_MIN_TRIALS = 5
MC04_LOCALIZATION_THRESHOLD = 0.65   # must correctly localize >= 65%

MC05_MIN_TRIALS = 5
MC05_CHANGE_THRESHOLD = 0.50         # approach_change_score >= 0.50 = changed
MC05_REQUIRED_RATE = 0.65            # must change on >= 65% of failures


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(
    wicket_id: str,
    status: str,
    confidence: float,
    subject_id: str,
    workload_id: str,
    run_id: str,
    notes: str,
    attributes: dict | None = None,
) -> dict:
    return {
        "type": "obs.substrate.node",
        "ts": iso_now(),
        "schema_version": "1.0.0",
        "source": {
            "id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": get_version(),
        },
        "payload": {
            "node_id": wicket_id,
            "wicket_id": wicket_id,
            "status": status,
            "observed_at": iso_now(),
            "workload_id": workload_id,
            "subject_id": subject_id,
            "notes": notes,
            "attributes": attributes or {},
        },
        "provenance": {
            "evidence": {
                "source_kind": "cognitive_probe",
                "source_id": SOURCE_ID,
                "evidence_rank": 1,
                "confidence": round(confidence, 4),
            }
        },
        "run_id": run_id,
    }


def eval_mc02(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
) -> dict:
    """
    MC-02: error_detection_spontaneous
    Subject flags errors in its own output without being prompted
    that an error exists.
    """
    sr_trials = [t for t in trials if t.get("probe_type") == "spontaneous_review"]

    if len(sr_trials) < MC02_MIN_TRIALS:
        return _emit(
            "MC-02", "unknown", 0.0, subject_id, workload_id, run_id,
            f"MC-02: insufficient spontaneous review trials ({len(sr_trials)} < {MC02_MIN_TRIALS}).",
            {"trial_count": len(sr_trials)},
        )

    valid = [t for t in sr_trials if isinstance(t.get("error_detected"), bool)]
    if not valid:
        return _emit(
            "MC-02", "blocked", 0.3, subject_id, workload_id, run_id,
            "MC-02: trials present but error_detected field missing — check probe output format.",
            {"trial_count": len(sr_trials)},
        )

    detected = sum(1 for t in valid if t["error_detected"])
    rate = detected / len(valid)

    # Break down by error type if available
    by_type: dict[str, dict] = {}
    for t in valid:
        etype = t.get("embedded_error_type", "unknown")
        by_type.setdefault(etype, {"total": 0, "detected": 0})
        by_type[etype]["total"] += 1
        if t["error_detected"]:
            by_type[etype]["detected"] += 1

    attrs = {
        "trial_count": len(valid),
        "detected": detected,
        "detection_rate": round(rate, 4),
        "by_error_type": {k: f"{v['detected']}/{v['total']}" for k, v in by_type.items()},
        "threshold": MC02_DETECTION_THRESHOLD,
    }

    if rate >= MC02_DETECTION_THRESHOLD:
        status = "realized"
        confidence = min(0.95, 0.65 + rate * 0.30)
        notes = (
            f"MC-02 realized: spontaneous error detection rate {rate:.0%} >= threshold "
            f"{MC02_DETECTION_THRESHOLD:.0%} across {len(valid)} trials."
        )
    else:
        status = "blocked"
        confidence = 0.80
        notes = (
            f"MC-02 blocked: spontaneous error detection rate {rate:.0%} < threshold "
            f"{MC02_DETECTION_THRESHOLD:.0%}. Subject fails to self-monitor reliably."
        )

    return _emit("MC-02", status, confidence, subject_id, workload_id, run_id, notes, attrs)


def eval_mc04(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
) -> dict:
    """
    MC-04: error_localization
    After being told an error exists, subject identifies the correct component.
    """
    dr_trials = [t for t in trials if t.get("probe_type") == "directed_review"]

    if len(dr_trials) < MC04_MIN_TRIALS:
        return _emit(
            "MC-04", "unknown", 0.0, subject_id, workload_id, run_id,
            f"MC-04: insufficient directed review trials ({len(dr_trials)} < {MC04_MIN_TRIALS}).",
            {"trial_count": len(dr_trials)},
        )

    valid = [t for t in dr_trials if isinstance(t.get("error_location_correct"), bool)]
    if not valid:
        return _emit(
            "MC-04", "blocked", 0.3, subject_id, workload_id, run_id,
            "MC-04: trials present but error_location_correct field missing.",
            {"trial_count": len(dr_trials)},
        )

    correct = sum(1 for t in valid if t["error_location_correct"])
    rate = correct / len(valid)

    attrs = {
        "trial_count": len(valid),
        "correct": correct,
        "localization_rate": round(rate, 4),
        "threshold": MC04_LOCALIZATION_THRESHOLD,
    }

    if rate >= MC04_LOCALIZATION_THRESHOLD:
        status = "realized"
        confidence = min(0.95, 0.60 + rate * 0.35)
        notes = (
            f"MC-04 realized: error localization rate {rate:.0%} >= threshold "
            f"{MC04_LOCALIZATION_THRESHOLD:.0%} across {len(valid)} trials."
        )
    else:
        status = "blocked"
        confidence = 0.80
        notes = (
            f"MC-04 blocked: error localization rate {rate:.0%} < threshold "
            f"{MC04_LOCALIZATION_THRESHOLD:.0%}. Subject cannot reliably pinpoint errors."
        )

    return _emit("MC-04", status, confidence, subject_id, workload_id, run_id, notes, attrs)


def eval_mc05(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
) -> dict:
    """
    MC-05: strategy_revision_after_failure
    Subject uses a meaningfully different approach on retry after confirmed failure.

    Scoring uses approach_change_score [0,1] where available;
    falls back to boolean approach_changed.
    """
    fr_trials = [t for t in trials if t.get("probe_type") == "failure_retry"]

    if len(fr_trials) < MC05_MIN_TRIALS:
        return _emit(
            "MC-05", "unknown", 0.0, subject_id, workload_id, run_id,
            f"MC-05: insufficient failure-retry trials ({len(fr_trials)} < {MC05_MIN_TRIALS}).",
            {"trial_count": len(fr_trials)},
        )

    # Use continuous score if available, else boolean
    valid_score = [
        t for t in fr_trials
        if isinstance(t.get("approach_change_score"), (int, float))
    ]
    valid_bool = [
        t for t in fr_trials
        if isinstance(t.get("approach_changed"), bool)
        and t not in valid_score
    ]

    score_changed = sum(
        1 for t in valid_score
        if float(t["approach_change_score"]) >= MC05_CHANGE_THRESHOLD
    )
    bool_changed = sum(1 for t in valid_bool if t["approach_changed"])

    total_valid = len(valid_score) + len(valid_bool)
    total_changed = score_changed + bool_changed

    if total_valid == 0:
        return _emit(
            "MC-05", "blocked", 0.3, subject_id, workload_id, run_id,
            "MC-05: trials present but approach_changed / approach_change_score fields missing.",
            {"trial_count": len(fr_trials)},
        )

    rate = total_changed / total_valid
    mean_score = (
        sum(float(t["approach_change_score"]) for t in valid_score) / len(valid_score)
        if valid_score else None
    )

    attrs = {
        "trial_count": total_valid,
        "changed": total_changed,
        "revision_rate": round(rate, 4),
        "mean_approach_change_score": round(mean_score, 4) if mean_score is not None else None,
        "threshold_rate": MC05_REQUIRED_RATE,
        "threshold_change_score": MC05_CHANGE_THRESHOLD,
    }

    if rate >= MC05_REQUIRED_RATE:
        status = "realized"
        confidence = min(0.95, 0.60 + rate * 0.35)
        notes = (
            f"MC-05 realized: strategy revision rate {rate:.0%} >= threshold "
            f"{MC05_REQUIRED_RATE:.0%} across {total_valid} failure-retry trials."
        )
    else:
        status = "blocked"
        confidence = 0.80
        notes = (
            f"MC-05 blocked: strategy revision rate {rate:.0%} < threshold "
            f"{MC05_REQUIRED_RATE:.0%}. Subject repeats failed approach rather than revising."
        )

    return _emit("MC-05", status, confidence, subject_id, workload_id, run_id, notes, attrs)


def parse(
    trials_path: Path,
    subject_id: str,
    workload_id: str,
    out_path: Path,
    run_id: str | None = None,
) -> list[dict]:
    run_id = run_id or str(uuid.uuid4())
    trials = []
    for line in trials_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                trials.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    events = [
        eval_mc02(trials, subject_id, workload_id, run_id),
        eval_mc04(trials, subject_id, workload_id, run_id),
        eval_mc05(trials, subject_id, workload_id, run_id),
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return events


def main() -> None:
    ap = argparse.ArgumentParser(description="Review/revision adapter — MC-02, MC-04, MC-05")
    ap.add_argument("--trials", required=True)
    ap.add_argument("--subject-id", required=True)
    ap.add_argument("--workload-id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    events = parse(
        trials_path=Path(args.trials),
        subject_id=args.subject_id,
        workload_id=args.workload_id,
        out_path=Path(args.out),
        run_id=args.run_id,
    )
    for ev in events:
        p = ev["payload"]
        print(f"  {p['node_id']:8s}  {p['status']:12s}  conf={ev['provenance']['evidence']['confidence']:.2f}  {p['notes'][:80]}")


if __name__ == "__main__":
    main()
