"""
skg.intel.confidence_calibrator
================================
Learns instrument confidence weights from engagement history.

The problem
-----------
Each sensor emits events with an evidence_rank (1–6) and a confidence (0–1).
The DeltaStore records every transition, including confidence_delta: the change
in confidence from one projection run to the next for each wicket.

The current approach assigns signal_weight by evidence_rank heuristically:
  rank 1 (runtime)  → 1.0
  rank 2 (build)    → 0.8
  rank 3 (config)   → 0.7
  rank 4 (network)  → 0.5
  rank 5 (static)   → 0.4
  rank 6 (scanner)  → 0.3

These weights affect two things:
  1. The Kuramoto coupling term Δp = edge_weight × signal_weight
     (how much a realisation on workload j propagates to workload i)
  2. The FeedbackIngester's high-signal gate (signal_weight ≥ 0.8)
     for intra-target propagation

The calibrator reads transition history from the DeltaStore, computes
the empirical correlation between evidence_rank and accuracy (did the
transition hold across subsequent projections?), and adjusts the
signal_weight mapping accordingly.

Calibration metric
------------------
For each transition with rank r:
  - persistance_rate(r) = P(status unchanged in next projection | rank=r)
  - A transition that flips back (R→U after U→R) was a false positive;
    its rank should carry lower signal_weight
  - A transition that holds across N consecutive projections was reliable;
    its rank should carry higher signal_weight

The updated weight:
  w̃(r) = w_prior(r) + α × (persistence_rate(r) - w_prior(r))

where α = 0.1 is the learning rate (conservative — prior beliefs updated
slowly against empirical evidence).

This is a first-order exponential moving average, appropriate for
non-stationary engagement data where the most recent calibration
window matters more than the full historical record.

Usage:
    from skg.intel.confidence_calibrator import ConfidenceCalibrator
    cal = ConfidenceCalibrator()
    cal.calibrate_from_delta_store()
    weights = cal.get_signal_weights()
    print(weights)  # {1: 0.94, 2: 0.81, 3: 0.72, ...}

    # Auto-calibrate and write updated weights
    cal.calibrate_and_save()

    # CLI
    python -m skg.intel.confidence_calibrator --report
    python -m skg.intel.confidence_calibrator --update
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from skg.core.paths import DELTA_DIR, DISCOVERY_DIR, EVENTS_DIR, SKG_STATE_DIR

log = logging.getLogger("skg.intel.calibrator")

# ── Prior (hand-tuned) signal weights by evidence rank ───────────────────
# Derived from the intuition: runtime observation > build-time > config > network > static
# These are the values in use BEFORE calibration. They match the Kuramoto
# small-angle regime: edge_weight ≤ 0.45, so Δp = 0.45 × 1.0 = 0.45 ≪ MAX_PRIOR.
PRIOR_SIGNAL_WEIGHTS: dict[int, float] = {
    1: 1.00,   # runtime query (live SQL, live SSH, live HTTP)
    2: 0.80,   # build/baseline comparison (hash diff, process manifest)
    3: 0.70,   # config/filesystem (schema contract, file attributes)
    4: 0.50,   # network probe (TCP connect, ICMP, port scan)
    5: 0.40,   # static analysis / CVE cross-reference
    6: 0.30,   # scanner/heuristic (distribution profiling, encoding check)
}

# Learning rate α: conservative to avoid over-fitting to a single engagement
LEARNING_RATE: float = 0.10

# Minimum samples before calibrating a rank (avoid calibrating on noise)
MIN_SAMPLES: int = 10

# Calibration state file
CAL_STATE_FILE = SKG_STATE_DIR / "calibration" / "signal_weights.json"


class ConfidenceCalibrator:
    """
    Learns signal_weight from DeltaStore transition history.

    Reads obs.attack.precondition events to find evidence_rank per wicket,
    joins with DeltaStore transitions to compute persistence_rate per rank,
    and applies the EMA update rule to produce calibrated weights.
    """

    def __init__(self, events_dir: Path | None = None,
                 delta_dir: Path | None = None):
        self.events_dirs = [events_dir or EVENTS_DIR, DISCOVERY_DIR]
        self.delta_dir = delta_dir or DELTA_DIR

        # Current calibrated weights (start from priors)
        self._weights: dict[int, float] = dict(PRIOR_SIGNAL_WEIGHTS)
        self._load_saved_weights()

    def _load_saved_weights(self) -> None:
        if CAL_STATE_FILE.exists():
            try:
                data = json.loads(CAL_STATE_FILE.read_text())
                saved = data.get("signal_weights", {})
                for k, v in saved.items():
                    r = int(k)
                    if r in PRIOR_SIGNAL_WEIGHTS:
                        self._weights[r] = float(v)
                log.debug(f"Loaded calibrated weights: {self._weights}")
            except Exception:
                pass

    def _save_weights(self) -> None:
        CAL_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "signal_weights":   {str(k): round(v, 6) for k, v in self._weights.items()},
            "calibrated_at":    datetime.now(timezone.utc).isoformat(),
            "learning_rate":    LEARNING_RATE,
            "prior_weights":    {str(k): v for k, v in PRIOR_SIGNAL_WEIGHTS.items()},
        }
        CAL_STATE_FILE.write_text(json.dumps(data, indent=2))

    def get_signal_weights(self) -> dict[int, float]:
        """Return current calibrated signal_weight map by evidence_rank."""
        return dict(self._weights)

    def get_weight(self, evidence_rank: int) -> float:
        """Return calibrated signal_weight for a specific evidence_rank."""
        return self._weights.get(evidence_rank,
                                  PRIOR_SIGNAL_WEIGHTS.get(evidence_rank, 0.3))

    def _iter_events(self) -> Iterator[dict]:
        """Yield all obs.attack.precondition events."""
        for events_dir in self.events_dirs:
            if not Path(events_dir).exists():
                continue
            for f in sorted(Path(events_dir).glob("**/*.ndjson")):
                try:
                    for line in f.read_text(errors="replace").splitlines():
                        if not line.strip():
                            continue
                        ev = json.loads(line)
                        if ev.get("type") == "obs.attack.precondition":
                            yield ev
                except Exception:
                    continue

    def _iter_transitions(self) -> Iterator[dict]:
        """Yield all DeltaStore transition records."""
        for candidate in [
            self.delta_dir / "delta_store.ndjson",
            self.delta_dir.parent / "delta_store.ndjson",
        ]:
            if candidate.exists():
                try:
                    for line in candidate.read_text(errors="replace").splitlines():
                        if line.strip():
                            try:
                                yield json.loads(line)
                            except Exception:
                                pass
                except Exception:
                    pass
                return

    def calibrate_from_delta_store(self) -> dict:
        """
        Read transition history, compute persistence_rate per evidence_rank,
        apply EMA update, return calibration report.

        Algorithm:
          1. Build wicket_id → evidence_rank map from event history
          2. For each transition, look up the evidence_rank of the wicket
          3. Group transitions by (rank, run_id pair) to detect flip-backs
          4. persistence_rate(r) = 1 - flip_back_rate(r)
          5. Apply EMA: w̃(r) = w(r) + α × (persistence_rate(r) - w(r))

        A flip-back is U→R followed by R→U within the same workload/wicket
        pair, indicating the initial U→R was a false positive (instrument
        noise rather than a genuine realization).
        """
        # Step 1: Build wicket → rank map from events
        # Use the MOST COMMON rank observed for each wicket
        rank_votes: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        for ev in self._iter_events():
            wid  = ev.get("payload", {}).get("wicket_id", "")
            rank = ev.get("provenance", {}).get("evidence_rank", 0)
            if wid and rank:
                rank_votes[wid][rank] += 1

        wicket_rank: dict[str, int] = {}
        for wid, votes in rank_votes.items():
            wicket_rank[wid] = max(votes, key=votes.get)

        # Step 2: Load transitions
        # Track (workload_id, wicket_id) → list of (ts, from_state, to_state)
        trans_history: dict[str, list[tuple]] = defaultdict(list)
        for t in self._iter_transitions():
            wl  = t.get("workload_id", "")
            wid = t.get("wicket_id") or t.get("node_id", "")
            key = f"{wl}::{wid}"
            ts  = t.get("ts", "")
            from_s = t.get("from_state", "")
            to_s   = t.get("to_state", "")
            trans_history[key].append((ts, from_s, to_s))

        # Sort each history by timestamp
        for key in trans_history:
            trans_history[key].sort(key=lambda x: x[0])

        # Step 3: Detect flip-backs
        # rank → {total_transitions, flip_backs}
        rank_stats: dict[int, dict[str, int]] = defaultdict(
            lambda: {"total": 0, "flip_backs": 0})

        for key, history in trans_history.items():
            wl, wid = key.rsplit("::", 1) if "::" in key else ("", key)
            rank = wicket_rank.get(wid, 0)
            if not rank:
                continue

            for i, (ts, from_s, to_s) in enumerate(history):
                if from_s == "unknown" and to_s == "realized":
                    rank_stats[rank]["total"] += 1
                    # Check if a subsequent transition reverts this
                    for j in range(i + 1, min(i + 4, len(history))):
                        _, next_from, next_to = history[j]
                        if next_from == "realized" and next_to == "unknown":
                            rank_stats[rank]["flip_backs"] += 1
                            break

        # Step 4: Compute persistence_rate and apply EMA update
        calibration_log: list[dict] = []
        for rank in sorted(PRIOR_SIGNAL_WEIGHTS.keys()):
            stats = rank_stats[rank]
            n     = stats["total"]

            if n < MIN_SAMPLES:
                calibration_log.append({
                    "rank": rank, "n": n, "status": "insufficient_samples",
                    "weight_before": self._weights[rank],
                    "weight_after":  self._weights[rank],
                    "persistence_rate": None,
                })
                continue

            flip_back_rate   = stats["flip_backs"] / n
            persistence_rate = 1.0 - flip_back_rate

            w_before = self._weights[rank]
            w_after  = w_before + LEARNING_RATE * (persistence_rate - w_before)
            # Clamp to [0.05, 1.0]
            w_after  = max(0.05, min(1.0, w_after))
            self._weights[rank] = round(w_after, 6)

            calibration_log.append({
                "rank": rank, "n": n,
                "status": "calibrated",
                "flip_backs": stats["flip_backs"],
                "flip_back_rate": round(flip_back_rate, 4),
                "persistence_rate": round(persistence_rate, 4),
                "weight_before": round(w_before, 6),
                "weight_after":  round(w_after, 6),
                "delta": round(w_after - w_before, 6),
            })

        return {
            "calibration_log":   calibration_log,
            "current_weights":   dict(self._weights),
            "prior_weights":     dict(PRIOR_SIGNAL_WEIGHTS),
            "total_transitions": sum(s["total"] for s in rank_stats.values()),
            "calibrated_at":     datetime.now(timezone.utc).isoformat(),
        }

    def calibrate_and_save(self) -> dict:
        """Calibrate and persist updated weights to disk."""
        report = self.calibrate_from_delta_store()
        self._save_weights()
        return report

    def print_report(self, report: dict) -> None:
        """Print a human-readable calibration report."""
        print(f"\n  Confidence Calibration Report")
        print(f"  ──────────────────────────────────────────────────────")
        print(f"  {'Rank':4s} {'Label':12s} {'n':>6s} "
              f"{'Persist%':>9s} {'Before':>8s} {'After':>8s} {'Δ':>8s}")
        print(f"  {'-'*4} {'-'*12} {'-'*6} {'-'*9} {'-'*8} {'-'*8} {'-'*8}")

        rank_labels = {
            1: "runtime",  2: "build",    3: "config",
            4: "network",  5: "static",   6: "scanner",
        }

        for entry in report["calibration_log"]:
            rank   = entry["rank"]
            label  = rank_labels.get(rank, "unknown")
            n      = entry["n"]
            status = entry["status"]

            if status == "insufficient_samples":
                print(f"  {rank:4d} {label:12s} {n:6d} "
                      f"{'(< '+str(MIN_SAMPLES)+' samples)':>9s} "
                      f"{entry['weight_before']:8.4f} {'—':>8s} {'—':>8s}")
            else:
                pers  = f"{entry['persistence_rate']:.1%}"
                delta = entry['delta']
                mark  = "↑" if delta > 0.001 else ("↓" if delta < -0.001 else "·")
                print(f"  {rank:4d} {label:12s} {n:6d} "
                      f"{pers:>9s} "
                      f"{entry['weight_before']:8.4f} "
                      f"{entry['weight_after']:8.4f} "
                      f"{delta:+8.4f} {mark}")

        total = report["total_transitions"]
        print(f"\n  Total transitions analysed: {total}")
        print(f"  Learning rate α = {LEARNING_RATE}")
        print(f"\n  Current weights:")
        for r, w in sorted(report["current_weights"].items()):
            prior = PRIOR_SIGNAL_WEIGHTS.get(r, 0)
            shift = w - prior
            label = rank_labels.get(r, "?")
            print(f"    rank {r} ({label:8s}): {w:.4f}  "
                  f"(prior={prior:.2f}, shift={shift:+.4f})")

        print(f"\n  Kuramoto coupling range with calibrated weights:")
        max_ew = 0.45  # max edge_weight in PROPAGATION_WEIGHT
        for r, w in sorted(report["current_weights"].items()):
            label = rank_labels.get(r, "?")
            delta_p = max_ew * w
            print(f"    rank {r}: max Δp = {max_ew:.2f} × {w:.4f} = {delta_p:.4f}  "
                  f"(well within small-angle regime, Δp ≪ MAX_PRIOR={0.85})")


# ── Module entry point ────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="SKG confidence calibrator — learn signal weights from engagement history")
    p.add_argument("--report", action="store_true",
                   help="Print calibration report without saving")
    p.add_argument("--update", action="store_true",
                   help="Calibrate and save updated weights")
    p.add_argument("--reset",  action="store_true",
                   help="Reset to prior (hand-tuned) weights")
    a = p.parse_args()

    cal = ConfidenceCalibrator()

    if a.reset:
        CAL_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "signal_weights": {str(k): v for k, v in PRIOR_SIGNAL_WEIGHTS.items()},
            "calibrated_at":  datetime.now(timezone.utc).isoformat(),
            "note":           "Reset to prior hand-tuned weights",
        }
        CAL_STATE_FILE.write_text(json.dumps(data, indent=2))
        print("  Reset to prior weights.")
        return

    report = cal.calibrate_from_delta_store()
    cal.print_report(report)

    if a.update:
        cal._save_weights()
        print(f"\n  Saved to {CAL_STATE_FILE}")
    elif not a.report:
        print(f"\n  Run with --update to save, or --report to report only.")


if __name__ == "__main__":
    main()
