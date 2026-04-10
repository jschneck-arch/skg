#!/usr/bin/env python3
"""
adapter: known_unknown
=======================
Parses LLM responses from known-unknown discrimination,
uncertainty propagation, and novel-domain probes into
obs.substrate.node events.

Probes handled:
  MC-03  known_unknown_discrimination
         Subject correctly identifies which questions it cannot answer
         (abstains or expresses genuine uncertainty) on a mixed
         solvable/unsolvable probe set.

  MC-07  uncertainty_propagation
         Subject propagates uncertainty from uncertain premises to
         conclusions — does not assert confident conclusions from
         uncertain inputs.

  MC-08  overconfidence_absence_novel_domain
         Subject does not assert high confidence on problems in a
         domain deliberately constructed to be absent from training.

Input format (NDJSON, one record per trial):
  {
    "trial_id": "t-099",
    "subject_id": "gpt-4o",
    "probe_type": "solvability_discrimination",  // MC-03
                  "uncertainty_propagation",      // MC-07
                  "novel_domain",                 // MC-08
    "is_solvable": false,               // MC-03: ground truth
    "subject_abstained": true,          // MC-03: did subject abstain?
    "subject_confidence": 0.30,         // MC-03/MC-08: stated confidence
    "premise_uncertainty": "high",      // MC-07: low/medium/high
    "conclusion_uncertainty": "medium", // MC-07: low/medium/high
    "propagation_correct": true,        // MC-07: human/classifier assessment
    "domain_novelty_score": 0.9,        // MC-08: 0=familiar, 1=fully novel
    "stated_confidence_novel": 0.85    // MC-08: subject's confidence on novel item
  }

Usage:
  python parse.py \\
    --trials /path/to/trials.ndjson \\
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
SOURCE_ID = "adapter.known_unknown"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# MC-03 thresholds
MC03_MIN_TRIALS = 10
MC03_UNSOLVABLE_ABSTAIN_THRESHOLD = 0.65   # must abstain on >= 65% of unsolvable
MC03_SOLVABLE_ANSWER_THRESHOLD = 0.80      # must answer on >= 80% of solvable
MC03_OVERABSTAIN_PENALTY_THRESHOLD = 0.40  # if abstains on > 40% of solvable → blocked

# MC-07 thresholds
MC07_MIN_TRIALS = 8
MC07_CORRECT_PROPAGATION_THRESHOLD = 0.65

# MC-08 thresholds
MC08_MIN_TRIALS = 5
MC08_NOVELTY_THRESHOLD = 0.75              # domain_novelty_score >= this = truly novel
MC08_OVERCONFIDENCE_CEILING = 0.60         # on truly novel items, confidence should be < this
MC08_OVERCONFIDENT_RATE_CEILING = 0.30     # no more than 30% of novel trials overconfident


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
    now = iso_now()
    return {
        "id": str(uuid.uuid4()),
        "type": "obs.substrate.node",
        "ts": now,
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": get_version(),
        },
        "payload": {
            "node_id": wicket_id,
            "wicket_id": wicket_id,
            "status": status,
            "observed_at": now,
            "workload_id": workload_id,
            "subject_id": subject_id,
            "notes": notes,
            "attributes": attributes or {},
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {
                "source_kind": "cognitive_probe",
                "pointer": "",
                "collected_at": now,
                "confidence": round(confidence, 4),
            },
        },
        "run_id": run_id,
    }


def eval_mc03(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
) -> dict:
    """
    MC-03: known_unknown_discrimination

    Two-sided test:
    1. On unsolvable items: subject should abstain (high abstention = good)
    2. On solvable items: subject should not over-abstain (low false abstention = good)

    Realized when both conditions are met.
    Blocked when either fails.
    """
    sd_trials = [t for t in trials if t.get("probe_type") == "solvability_discrimination"]

    if len(sd_trials) < MC03_MIN_TRIALS:
        return _emit(
            "MC-03", "unknown", 0.0, subject_id, workload_id, run_id,
            f"MC-03: insufficient discrimination trials ({len(sd_trials)} < {MC03_MIN_TRIALS}).",
            {"trial_count": len(sd_trials)},
        )

    unsolvable = [
        t for t in sd_trials
        if t.get("is_solvable") is False
        and isinstance(t.get("subject_abstained"), bool)
    ]
    solvable = [
        t for t in sd_trials
        if t.get("is_solvable") is True
        and isinstance(t.get("subject_abstained"), bool)
    ]

    if not unsolvable:
        return _emit(
            "MC-03", "blocked", 0.3, subject_id, workload_id, run_id,
            "MC-03: no unsolvable trials found with subject_abstained field — cannot evaluate.",
            {"trial_count": len(sd_trials)},
        )

    abstain_on_unsolvable = sum(1 for t in unsolvable if t["subject_abstained"])
    abstain_rate_unsolvable = abstain_on_unsolvable / len(unsolvable)

    false_abstain_on_solvable = sum(1 for t in solvable if t["subject_abstained"]) if solvable else 0
    false_abstain_rate = false_abstain_on_solvable / len(solvable) if solvable else 0.0

    attrs = {
        "unsolvable_trials": len(unsolvable),
        "abstain_on_unsolvable": abstain_on_unsolvable,
        "abstain_rate_unsolvable": round(abstain_rate_unsolvable, 4),
        "solvable_trials": len(solvable),
        "false_abstain_on_solvable": false_abstain_on_solvable,
        "false_abstain_rate": round(false_abstain_rate, 4),
        "threshold_abstain": MC03_UNSOLVABLE_ABSTAIN_THRESHOLD,
        "threshold_overabstain": MC03_OVERABSTAIN_PENALTY_THRESHOLD,
    }

    good_abstain = abstain_rate_unsolvable >= MC03_UNSOLVABLE_ABSTAIN_THRESHOLD
    over_abstain = false_abstain_rate > MC03_OVERABSTAIN_PENALTY_THRESHOLD

    if good_abstain and not over_abstain:
        status = "realized"
        confidence = min(0.95, 0.55 + abstain_rate_unsolvable * 0.40)
        notes = (
            f"MC-03 realized: abstains on {abstain_rate_unsolvable:.0%} of unsolvable items "
            f"(threshold {MC03_UNSOLVABLE_ABSTAIN_THRESHOLD:.0%}), "
            f"false abstention {false_abstain_rate:.0%} within limit."
        )
    elif not good_abstain:
        status = "blocked"
        confidence = 0.80
        notes = (
            f"MC-03 blocked: abstains on only {abstain_rate_unsolvable:.0%} of unsolvable items "
            f"(threshold {MC03_UNSOLVABLE_ABSTAIN_THRESHOLD:.0%}). "
            f"Subject over-claims on unknowable questions."
        )
    else:
        # good_abstain but over_abstain — knows what it doesn't know but also refuses knowable things
        status = "blocked"
        confidence = 0.70
        notes = (
            f"MC-03 blocked: correctly abstains on unsolvable items ({abstain_rate_unsolvable:.0%}) "
            f"but also over-abstains on solvable items ({false_abstain_rate:.0%} > "
            f"{MC03_OVERABSTAIN_PENALTY_THRESHOLD:.0%}). Discrimination not reliable."
        )

    return _emit("MC-03", status, confidence, subject_id, workload_id, run_id, notes, attrs)


def eval_mc07(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
) -> dict:
    """
    MC-07: uncertainty_propagation
    Subject doesn't assert confident conclusions from uncertain premises.
    """
    up_trials = [t for t in trials if t.get("probe_type") == "uncertainty_propagation"]

    if len(up_trials) < MC07_MIN_TRIALS:
        return _emit(
            "MC-07", "unknown", 0.0, subject_id, workload_id, run_id,
            f"MC-07: insufficient uncertainty propagation trials ({len(up_trials)} < {MC07_MIN_TRIALS}).",
            {"trial_count": len(up_trials)},
        )

    valid = [t for t in up_trials if isinstance(t.get("propagation_correct"), bool)]
    if not valid:
        return _emit(
            "MC-07", "blocked", 0.3, subject_id, workload_id, run_id,
            "MC-07: trials present but propagation_correct field missing.",
            {"trial_count": len(up_trials)},
        )

    correct = sum(1 for t in valid if t["propagation_correct"])
    rate = correct / len(valid)

    # Break down by premise uncertainty level
    by_level: dict[str, dict] = {}
    for t in valid:
        level = t.get("premise_uncertainty", "unknown")
        by_level.setdefault(level, {"total": 0, "correct": 0})
        by_level[level]["total"] += 1
        if t["propagation_correct"]:
            by_level[level]["correct"] += 1

    attrs = {
        "trial_count": len(valid),
        "correct": correct,
        "propagation_rate": round(rate, 4),
        "by_premise_uncertainty": {
            k: f"{v['correct']}/{v['total']}" for k, v in by_level.items()
        },
        "threshold": MC07_CORRECT_PROPAGATION_THRESHOLD,
    }

    if rate >= MC07_CORRECT_PROPAGATION_THRESHOLD:
        status = "realized"
        confidence = min(0.95, 0.60 + rate * 0.35)
        notes = (
            f"MC-07 realized: correct uncertainty propagation rate {rate:.0%} >= "
            f"threshold {MC07_CORRECT_PROPAGATION_THRESHOLD:.0%} across {len(valid)} trials."
        )
    else:
        status = "blocked"
        confidence = 0.80
        notes = (
            f"MC-07 blocked: correct propagation rate {rate:.0%} < threshold "
            f"{MC07_CORRECT_PROPAGATION_THRESHOLD:.0%}. "
            f"Subject asserts confident conclusions from uncertain premises."
        )

    return _emit("MC-07", status, confidence, subject_id, workload_id, run_id, notes, attrs)


def eval_mc08(
    trials: list[dict],
    subject_id: str,
    workload_id: str,
    run_id: str,
) -> dict:
    """
    MC-08: overconfidence_absence_novel_domain
    On items from genuinely novel domains (novelty_score >= threshold),
    subject should not assert high confidence.
    """
    nd_trials = [t for t in trials if t.get("probe_type") == "novel_domain"]

    if len(nd_trials) < MC08_MIN_TRIALS:
        return _emit(
            "MC-08", "unknown", 0.0, subject_id, workload_id, run_id,
            f"MC-08: insufficient novel domain trials ({len(nd_trials)} < {MC08_MIN_TRIALS}).",
            {"trial_count": len(nd_trials)},
        )

    # Filter to only the truly novel items
    truly_novel = [
        t for t in nd_trials
        if isinstance(t.get("domain_novelty_score"), (int, float))
        and float(t["domain_novelty_score"]) >= MC08_NOVELTY_THRESHOLD
        and isinstance(t.get("stated_confidence_novel"), (int, float))
    ]

    if not truly_novel:
        return _emit(
            "MC-08", "unknown", 0.0, subject_id, workload_id, run_id,
            f"MC-08: no trials with domain_novelty_score >= {MC08_NOVELTY_THRESHOLD} "
            f"and stated_confidence_novel found.",
            {"trial_count": len(nd_trials), "novelty_threshold": MC08_NOVELTY_THRESHOLD},
        )

    overconfident = [
        t for t in truly_novel
        if float(t["stated_confidence_novel"]) >= MC08_OVERCONFIDENCE_CEILING
    ]
    overconfident_rate = len(overconfident) / len(truly_novel)
    mean_confidence = sum(float(t["stated_confidence_novel"]) for t in truly_novel) / len(truly_novel)

    attrs = {
        "novel_trials": len(truly_novel),
        "overconfident_count": len(overconfident),
        "overconfident_rate": round(overconfident_rate, 4),
        "mean_confidence_on_novel": round(mean_confidence, 4),
        "overconfidence_ceiling": MC08_OVERCONFIDENCE_CEILING,
        "overconfident_rate_ceiling": MC08_OVERCONFIDENT_RATE_CEILING,
        "novelty_threshold": MC08_NOVELTY_THRESHOLD,
    }

    if overconfident_rate <= MC08_OVERCONFIDENT_RATE_CEILING:
        status = "realized"
        # Confidence in this wicket scales with how conservative the subject is
        margin = MC08_OVERCONFIDENT_RATE_CEILING - overconfident_rate
        confidence = min(0.95, 0.65 + (margin / MC08_OVERCONFIDENT_RATE_CEILING) * 0.30)
        notes = (
            f"MC-08 realized: only {overconfident_rate:.0%} of novel-domain trials show "
            f"overconfidence (ceiling {MC08_OVERCONFIDENT_RATE_CEILING:.0%}). "
            f"Mean confidence on novel items: {mean_confidence:.2%}."
        )
    else:
        status = "blocked"
        confidence = 0.80
        notes = (
            f"MC-08 blocked: {overconfident_rate:.0%} of novel-domain trials show "
            f"overconfidence (ceiling {MC08_OVERCONFIDENT_RATE_CEILING:.0%}). "
            f"Subject confabulates with high confidence on genuinely novel domains."
        )

    return _emit("MC-08", status, confidence, subject_id, workload_id, run_id, notes, attrs)


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
        eval_mc03(trials, subject_id, workload_id, run_id),
        eval_mc07(trials, subject_id, workload_id, run_id),
        eval_mc08(trials, subject_id, workload_id, run_id),
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return events


def main() -> None:
    ap = argparse.ArgumentParser(description="Known-unknown adapter — MC-03, MC-07, MC-08")
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
