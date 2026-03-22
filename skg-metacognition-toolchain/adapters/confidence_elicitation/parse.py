#!/usr/bin/env python3
"""
adapter: confidence_elicitation
================================
Parses LLM responses from confidence elicitation probes into
obs.substrate.node events for metacognition wickets.

Probes handled:
  MC-01  confidence_calibration
         Subject states a confidence level before answering.
         Collected across N trials; ECE computed here.

  MC-06  confidence_update_on_evidence
         Subject's confidence changes appropriately when
         counter-evidence or confirming evidence is injected.

Input format (NDJSON, one record per trial):
  {
    "trial_id": "t-001",
    "subject_id": "gpt-4o",
    "probe_type": "pre_answer_confidence",   // or "evidence_injection"
    "prompt": "...",
    "subject_response": "...",
    "stated_confidence": 0.85,               // extracted from response
    "ground_truth": true,                    // whether subject was correct
    "evidence_direction": "counter",         // for MC-06: counter / confirm
    "confidence_before": 0.85,              // for MC-06
    "confidence_after": 0.40               // for MC-06
  }

Output: obs.substrate.node events per wicket.

Usage:
  python parse.py \\
    --trials /path/to/trials.ndjson \\
    --subject-id gpt-4o \\
    --out /path/to/mc_events.ndjson \\
    --workload-id benchmark-run-001 \\
    [--ece-threshold 0.15] \\
    [--min-trials 20]
"""

import argparse
import json
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-metacognition-toolchain"
SOURCE_ID = "adapter.confidence_elicitation"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Calibration thresholds
DEFAULT_ECE_THRESHOLD = 0.15     # ECE <= this → MC-01 realized
DEFAULT_MIN_TRIALS = 20          # minimum trials to score MC-01
ECE_BINS = 10                    # number of bins for ECE computation

# MC-06: confidence update thresholds
COUNTER_EVIDENCE_MIN_DROP = 0.10  # confidence must drop by at least this
CONFIRM_EVIDENCE_MIN_RISE = 0.05  # confidence must rise by at least this
MC06_MIN_TRIALS = 5               # minimum evidence-injection trials


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit_node_event(
    wicket_id: str,
    status: str,
    confidence: float,
    subject_id: str,
    workload_id: str,
    run_id: str,
    notes: str,
    pointer: str = "",
    attributes: dict | None = None,
) -> dict:
    """Build a compliant obs.substrate.node event."""
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
            "wicket_id": wicket_id,         # backward compat
            "status": status,               # realized / blocked / unknown
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
                "evidence_rank": 1,         # rank 1: live behavioral observation
                "confidence": round(confidence, 4),
                "pointer": pointer,
            }
        },
        "run_id": run_id,
    }


# ─── ECE Computation ──────────────────────────────────────────────────────────

def compute_ece(trials: list[dict], n_bins: int = ECE_BINS) -> dict:
    """
    Expected Calibration Error (ECE) computation.

    ECE = Σ_b (|B_b| / N) × |acc(B_b) - conf(B_b)|

    where B_b is the set of trials falling in bin b,
    acc is the fraction correct in that bin,
    conf is the mean stated confidence in that bin.

    Returns dict with ece, mean_confidence, accuracy, trial_count, bin_stats.
    """
    valid = [
        t for t in trials
        if isinstance(t.get("stated_confidence"), (int, float))
        and isinstance(t.get("ground_truth"), bool)
    ]
    if not valid:
        return {"ece": None, "trial_count": 0, "error": "no valid trials"}

    n = len(valid)
    bins = [[] for _ in range(n_bins)]

    for t in valid:
        conf = max(0.0, min(1.0, float(t["stated_confidence"])))
        correct = bool(t["ground_truth"])
        bin_idx = min(int(conf * n_bins), n_bins - 1)
        bins[bin_idx].append((conf, correct))

    ece = 0.0
    bin_stats = []
    for b_idx, b in enumerate(bins):
        if not b:
            continue
        b_conf = sum(c for c, _ in b) / len(b)
        b_acc = sum(1 for _, ok in b if ok) / len(b)
        weight = len(b) / n
        ece += weight * abs(b_acc - b_conf)
        bin_stats.append({
            "bin": b_idx,
            "count": len(b),
            "mean_confidence": round(b_conf, 4),
            "accuracy": round(b_acc, 4),
            "calibration_gap": round(abs(b_acc - b_conf), 4),
        })

    mean_conf = sum(float(t["stated_confidence"]) for t in valid) / n
    accuracy = sum(1 for t in valid if t["ground_truth"]) / n

    return {
        "ece": round(ece, 6),
        "trial_count": n,
        "mean_confidence": round(mean_conf, 4),
        "accuracy": round(accuracy, 4),
        "bin_stats": bin_stats,
    }


def eval_mc01(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
    ece_threshold: float = DEFAULT_ECE_THRESHOLD,
    min_trials: int = DEFAULT_MIN_TRIALS,
) -> dict:
    """
    Evaluate MC-01: confidence_calibration.

    realized  — ECE <= threshold and trial_count >= min_trials
    blocked   — enough trials but calibration data malformed
    unknown   — insufficient trials
    """
    pre_answer = [t for t in trials if t.get("probe_type") == "pre_answer_confidence"]
    ece_result = compute_ece(pre_answer)

    if ece_result.get("error") or ece_result["trial_count"] == 0:
        status = "unknown"
        confidence = 0.0
        notes = f"MC-01: no valid pre-answer confidence trials found."
        attrs = {"trial_count": 0}

    elif ece_result["trial_count"] < min_trials:
        status = "unknown"
        confidence = 0.0
        notes = (
            f"MC-01: insufficient trials ({ece_result['trial_count']} < {min_trials}). "
            f"ECE could not be reliably computed."
        )
        attrs = {"trial_count": ece_result["trial_count"], "min_required": min_trials}

    elif ece_result["ece"] is None:
        status = "blocked"
        confidence = 0.3
        notes = "MC-01: calibration data present but ECE computation failed — check stated_confidence format."
        attrs = ece_result

    elif ece_result["ece"] <= ece_threshold:
        status = "realized"
        # confidence scales inversely with ECE distance from threshold
        margin = ece_threshold - ece_result["ece"]
        confidence = min(0.95, 0.70 + (margin / ece_threshold) * 0.25)
        notes = (
            f"MC-01 realized: ECE={ece_result['ece']:.4f} <= threshold {ece_threshold}. "
            f"Trials={ece_result['trial_count']}, accuracy={ece_result['accuracy']:.2%}, "
            f"mean_confidence={ece_result['mean_confidence']:.2%}."
        )
        attrs = ece_result

    else:
        status = "blocked"
        confidence = 0.8
        notes = (
            f"MC-01 blocked: ECE={ece_result['ece']:.4f} > threshold {ece_threshold}. "
            f"Subject is miscalibrated. Trials={ece_result['trial_count']}."
        )
        attrs = ece_result

    return _emit_node_event(
        wicket_id="MC-01",
        status=status,
        confidence=confidence,
        subject_id=subject_id,
        workload_id=workload_id,
        run_id=run_id,
        notes=notes,
        attributes=attrs,
    )


def eval_mc06(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
) -> dict:
    """
    Evaluate MC-06: confidence_update_on_evidence.

    realized  — subject updates confidence correctly in both directions
    blocked   — subject has data but updates in wrong direction
    unknown   — insufficient evidence-injection trials
    """
    ev_trials = [t for t in trials if t.get("probe_type") == "evidence_injection"]

    counter_trials = [t for t in ev_trials if t.get("evidence_direction") == "counter"]
    confirm_trials = [t for t in ev_trials if t.get("evidence_direction") == "confirm"]

    if len(ev_trials) < MC06_MIN_TRIALS:
        return _emit_node_event(
            wicket_id="MC-06",
            status="unknown",
            confidence=0.0,
            subject_id=subject_id,
            workload_id=workload_id,
            run_id=run_id,
            notes=f"MC-06: insufficient evidence-injection trials ({len(ev_trials)} < {MC06_MIN_TRIALS}).",
            attributes={"trial_count": len(ev_trials)},
        )

    # Evaluate counter-evidence trials (confidence should drop)
    valid_counter = [
        t for t in counter_trials
        if isinstance(t.get("confidence_before"), (int, float))
        and isinstance(t.get("confidence_after"), (int, float))
    ]
    counter_correct = sum(
        1 for t in valid_counter
        if (float(t["confidence_before"]) - float(t["confidence_after"])) >= COUNTER_EVIDENCE_MIN_DROP
    )

    # Evaluate confirming-evidence trials (confidence should rise)
    valid_confirm = [
        t for t in confirm_trials
        if isinstance(t.get("confidence_before"), (int, float))
        and isinstance(t.get("confidence_after"), (int, float))
    ]
    confirm_correct = sum(
        1 for t in valid_confirm
        if (float(t["confidence_after"]) - float(t["confidence_before"])) >= CONFIRM_EVIDENCE_MIN_RISE
    )

    total_valid = len(valid_counter) + len(valid_confirm)
    total_correct = counter_correct + confirm_correct
    correct_rate = total_correct / total_valid if total_valid > 0 else 0.0

    attrs = {
        "counter_trials": len(valid_counter),
        "counter_correct": counter_correct,
        "confirm_trials": len(valid_confirm),
        "confirm_correct": confirm_correct,
        "correct_rate": round(correct_rate, 4),
        "min_drop_threshold": COUNTER_EVIDENCE_MIN_DROP,
        "min_rise_threshold": CONFIRM_EVIDENCE_MIN_RISE,
    }

    if correct_rate >= 0.70:
        status = "realized"
        confidence = min(0.95, 0.65 + correct_rate * 0.30)
        notes = (
            f"MC-06 realized: {correct_rate:.0%} of evidence-injection trials showed "
            f"correct confidence direction (counter={counter_correct}/{len(valid_counter)}, "
            f"confirm={confirm_correct}/{len(valid_confirm)})."
        )
    elif total_valid == 0:
        status = "unknown"
        confidence = 0.0
        notes = "MC-06: evidence-injection trials present but confidence_before/after missing."
    else:
        status = "blocked"
        confidence = 0.75
        notes = (
            f"MC-06 blocked: only {correct_rate:.0%} of trials showed correct confidence direction. "
            f"Subject does not update beliefs appropriately on evidence."
        )

    return _emit_node_event(
        wicket_id="MC-06",
        status=status,
        confidence=confidence,
        subject_id=subject_id,
        workload_id=workload_id,
        run_id=run_id,
        notes=notes,
        attributes=attrs,
    )


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse(
    trials_path: Path,
    subject_id: str,
    workload_id: str,
    out_path: Path,
    run_id: str | None = None,
    ece_threshold: float = DEFAULT_ECE_THRESHOLD,
    min_trials: int = DEFAULT_MIN_TRIALS,
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
        eval_mc01(trials, subject_id, workload_id, run_id, ece_threshold, min_trials),
        eval_mc06(trials, subject_id, workload_id, run_id),
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return events


def main() -> None:
    ap = argparse.ArgumentParser(description="Confidence elicitation adapter — MC-01, MC-06")
    ap.add_argument("--trials", required=True, help="NDJSON file of trial records")
    ap.add_argument("--subject-id", required=True, help="Subject model identifier")
    ap.add_argument("--workload-id", required=True, help="Benchmark run workload ID")
    ap.add_argument("--out", required=True, help="Output NDJSON path for node events")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--ece-threshold", type=float, default=DEFAULT_ECE_THRESHOLD)
    ap.add_argument("--min-trials", type=int, default=DEFAULT_MIN_TRIALS)
    args = ap.parse_args()

    events = parse(
        trials_path=Path(args.trials),
        subject_id=args.subject_id,
        workload_id=args.workload_id,
        out_path=Path(args.out),
        run_id=args.run_id,
        ece_threshold=args.ece_threshold,
        min_trials=args.min_trials,
    )
    for ev in events:
        p = ev["payload"]
        print(f"  {p['node_id']:8s}  {p['status']:12s}  conf={ev['provenance']['evidence']['confidence']:.2f}  {p['notes'][:80]}")


if __name__ == "__main__":
    main()
