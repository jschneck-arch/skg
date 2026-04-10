"""
skg.sensors.confidence_calibrator
===================================
Learns per-sensor confidence weights from the DeltaStore transition history.

The problem:
  Every sensor emits events with a confidence value (0.0–1.0) that is
  currently set by hand based on instrument type and evidence rank:
    rank 1 (runtime)  → 0.90–0.99
    rank 3 (config)   → 0.70–0.85
    rank 6 (scanner)  → 0.60–0.80

  These are reasonable priors. They are not learned from engagement data.
  The accuracy claim in the paper depends on them — if a rank-1 SSH sensor
  consistently produces transitions that reverse themselves (surface_expansion
  followed by evidence_decay) its effective confidence should drop.

The fix:
  After each engagement, compute per-(source_id, status) calibration
  factors from the DeltaStore. A calibration factor < 1.0 means the
  sensor's confidence claims were too high relative to what it actually
  observed. A factor > 1.0 means claims were conservative.

  Calibration metric:
    For each (source_id, status) bucket:
      precision  = P(transition is stable | source emitted it)
                 = 1 - P(evidence_decay within N steps of surface_expansion)
      adjustment = precision * hand_tuned_confidence

  The calibrated confidence is then:
    calibrated_conf = hand_conf * precision_factor

  This is written under SKG_STATE_DIR as calibration.json and loaded by
  the runtime confidence context before observations enter the evidence
  pipeline.

Why this matters for the paper:
  The paper claims SKG avoids false certainty. If the confidence values
  are uncalibrated, the system may be falsely certain that a rank-1
  observation is reliable when empirically it reverses frequently.
  Calibration makes the confidence claim empirically grounded.

Usage:
  from skg.sensors.confidence_calibrator import (
      ConfidenceCalibrator, load_calibration, apply_calibration
  )

  # After an engagement:
  cal = ConfidenceCalibrator()
  cal.fit_from_delta_store(delta_store)
  cal.save()

  # At sensor emit time:
  conf = apply_calibration(source_id, status, raw_confidence=0.90)
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from skg_core.config.paths import SKG_STATE_DIR

log = logging.getLogger("skg.sensors.calibrator")

CALIBRATION_PATH = SKG_STATE_DIR / "calibration.json"

# Minimum observations before calibration is trusted
MIN_OBSERVATIONS = 5

# Maximum adjustment factor — don't let calibration push confidence
# above the hand-tuned ceiling or below 0.1
MAX_CALIBRATED   = 0.99
MIN_CALIBRATED   = 0.10

# Decay window: how many projection cycles to look for reversals
REVERSAL_WINDOW_STEPS = 3


@dataclass
class SourceStats:
    """Empirical statistics for one (source_id, from_state→to_state) bucket."""
    source_id:     str
    transition:    str          # e.g. "unknown→realized"
    count:         int = 0
    reversals:     int = 0      # surface_expansion followed by evidence_decay
    mean_conf:     float = 0.0  # mean confidence of emitting events
    conf_sum:      float = 0.0

    @property
    def precision(self) -> float:
        """P(stable | emitted) = 1 - reversal_rate."""
        if self.count < MIN_OBSERVATIONS:
            return 1.0   # not enough data — don't penalise
        return max(0.0, 1.0 - (self.reversals / self.count))

    @property
    def calibration_factor(self) -> float:
        """
        How much to scale the hand-tuned confidence.

        When precision = 1.0 (no reversals), factor = 1.0.
        When precision = 0.5 (half reverse), factor = 0.5.
        When precision = 0.0 (all reverse), factor = MIN_CALIBRATED / mean_conf.

        The factor is the ratio of empirical precision to the
        assumed reliability implied by the hand-tuned confidence.
        If the hand-tuned confidence was 0.90 and the observed
        precision is 0.60, the calibration factor = 0.60/0.90 ≈ 0.67.
        """
        if self.count < MIN_OBSERVATIONS:
            return 1.0
        assumed_reliability = self.mean_conf if self.mean_conf > 0 else 0.5
        return max(0.0, self.precision / assumed_reliability)

    def to_dict(self) -> dict:
        return {
            "source_id":          self.source_id,
            "transition":         self.transition,
            "count":              self.count,
            "reversals":          self.reversals,
            "precision":          round(self.precision, 4),
            "mean_conf":          round(self.mean_conf, 4),
            "calibration_factor": round(self.calibration_factor, 4),
        }


class ConfidenceCalibrator:
    """
    Learns per-sensor confidence calibration from DeltaStore history.

    The calibrator processes the stream of WicketTransitions and looks for
    unstable surface-expansions — realizations that reversed within
    REVERSAL_WINDOW_STEPS subsequent projection cycles.

    A sensor that frequently produces reversals gets a lower calibration
    factor, which scales down its emitted confidence values.
    """

    def __init__(self) -> None:
        self._stats: dict[str, SourceStats] = {}

    def _key(self, source_id: str, transition: str) -> str:
        return f"{source_id}::{transition}"

    def _get_or_create(self, source_id: str, transition: str) -> SourceStats:
        key = self._key(source_id, transition)
        if key not in self._stats:
            self._stats[key] = SourceStats(
                source_id=source_id, transition=transition)
        return self._stats[key]

    def fit_from_delta_store(self, delta_store) -> dict:
        """
        Compute calibration factors from a DeltaStore instance.

        Process:
          1. For each workload, get all transitions sorted by time
          2. For each surface_expansion, look ahead REVERSAL_WINDOW_STEPS
             for an evidence_decay of the same wicket
          3. Track per-source precision
        """
        from skg.temporal import DeltaStore

        # Collect all transitions grouped by (workload_id, wicket_id)
        wl_wicket_chains: dict[str, list] = defaultdict(list)

        for wl in delta_store.all_workloads():
            for t in delta_store.transitions_for(wl, min_weight=0.0):
                key = f"{wl}::{t.wicket_id}"
                wl_wicket_chains[key].append(t)

        # Process each chain
        for key, transitions in wl_wicket_chains.items():
            # Sort by timestamp
            transitions = sorted(transitions, key=lambda t: t.to_ts)

            for i, t in enumerate(transitions):
                if t.meaning != "surface_expansion":
                    continue

                source_id = getattr(t, "source_id", "unknown")
                stats     = self._get_or_create(
                    source_id, "unknown→realized")
                stats.count   += 1
                stats.conf_sum += t.to_confidence
                stats.mean_conf = stats.conf_sum / stats.count

                # Look ahead for reversals (evidence_decay of same wicket)
                look_ahead = transitions[i+1 : i+1+REVERSAL_WINDOW_STEPS]
                reversed_ = any(
                    lt.meaning == "evidence_decay" and
                    lt.wicket_id == t.wicket_id
                    for lt in look_ahead
                )
                if reversed_:
                    stats.reversals += 1

        return self.summary()

    def fit_from_ndjson(self, delta_ndjson_path: Path) -> dict:
        """
        Compute calibration from a serialized DeltaStore NDJSON file.
        This is the primary path when the daemon is not running.
        """
        transitions_by_chain: dict[str, list[dict]] = defaultdict(list)

        if not delta_ndjson_path.exists():
            log.warning(f"[calibrator] Delta file not found: {delta_ndjson_path}")
            return {}

        for line in delta_ndjson_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                t = json.loads(line)
            except Exception:
                continue

            wl  = t.get("workload_id", "")
            wid = t.get("wicket_id", t.get("node_id", ""))
            if wl and wid:
                transitions_by_chain[f"{wl}::{wid}"].append(t)

        for chain_key, chain in transitions_by_chain.items():
            chain_sorted = sorted(chain, key=lambda t: t.get("to_ts", ""))

            for i, t in enumerate(chain_sorted):
                if t.get("meaning") != "surface_expansion":
                    continue

                source_id = t.get("source_id", t.get("source", {}).get(
                    "source_id", "unknown") if isinstance(t.get("source"), dict)
                    else "unknown")
                stats = self._get_or_create(source_id, "unknown→realized")
                conf  = t.get("to_confidence", t.get("confidence", 0.5))
                stats.count   += 1
                stats.conf_sum += float(conf)
                stats.mean_conf = stats.conf_sum / stats.count

                look_ahead = chain_sorted[i+1 : i+1+REVERSAL_WINDOW_STEPS]
                if any(lt.get("meaning") == "evidence_decay" for lt in look_ahead):
                    stats.reversals += 1

        return self.summary()

    def fit_from_engagement_db(self, db_path: Path) -> dict:
        """
        Compute calibration from a built engagement SQLite database.
        Uses observations.source_id joined to transition outcomes by
        (workload_id, wicket_id, run_id).
        """
        import sqlite3
        if not db_path.exists():
            return {}

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        obs_rows = conn.execute("""
            SELECT workload_id, wicket_id, run_id, source_id, confidence, ts
            FROM observations
            WHERE source_id != ''
            ORDER BY workload_id, wicket_id, run_id, ts
        """).fetchall()
        rows = conn.execute("""
            SELECT workload_id, wicket_id, meaning, signal_weight,
                   to_state, run_id, ts
            FROM transitions
            WHERE meaning IN ('surface_expansion', 'evidence_decay')
            ORDER BY workload_id, wicket_id, ts
        """).fetchall()
        conn.close()

        obs_index: dict[tuple[str, str, str], dict[str, float | str]] = {}
        for row in obs_rows:
            key = (row["workload_id"], row["wicket_id"], row["run_id"])
            confidence = float(row["confidence"] or 0.0)
            existing = obs_index.get(key)
            if existing is None or confidence >= float(existing.get("confidence", 0.0)):
                obs_index[key] = {
                    "source_id": row["source_id"] or "unknown",
                    "confidence": confidence,
                    "ts": row["ts"] or "",
                }

        chains: dict[str, list] = defaultdict(list)
        for row in rows:
            chains[f"{row['workload_id']}::{row['wicket_id']}"].append(dict(row))

        for chain_key, chain in chains.items():
            for i, t in enumerate(chain):
                if t["meaning"] != "surface_expansion":
                    continue
                obs = obs_index.get(
                    (t["workload_id"], t["wicket_id"], t.get("run_id", "")),
                    {},
                )
                source_id = str(obs.get("source_id") or "unknown")
                stats = self._get_or_create(source_id, "unknown→realized")
                stats.count   += 1
                stats.conf_sum += float(obs.get("confidence", 0.5))
                stats.mean_conf = stats.conf_sum / stats.count
                look_ahead = chain[i+1 : i+1+REVERSAL_WINDOW_STEPS]
                if any(lt["meaning"] == "evidence_decay" for lt in look_ahead):
                    stats.reversals += 1

        return self.summary()

    def calibration_for(self, source_id: str,
                         transition: str = "unknown→realized") -> float:
        """
        Return the calibration factor for a given source+transition.
        Returns 1.0 if no calibration data is available.
        """
        key = self._key(source_id, transition)
        if key not in self._stats:
            return 1.0
        return self._stats[key].calibration_factor

    def apply(self, source_id: str, raw_confidence: float,
               transition: str = "unknown→realized") -> float:
        """
        Apply calibration to a raw confidence value.

        calibrated = raw_confidence * calibration_factor
        Clamped to [MIN_CALIBRATED, MAX_CALIBRATED].
        """
        factor = self.calibration_for(source_id, transition)
        cal    = raw_confidence * factor
        return max(MIN_CALIBRATED, min(MAX_CALIBRATED, cal))

    def summary(self) -> dict:
        return {
            key: stats.to_dict()
            for key, stats in self._stats.items()
        }

    def save(self, path: Optional[Path] = None) -> None:
        """Persist calibration to JSON."""
        target = path or CALIBRATION_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sensors":      self.summary(),
        }
        tmp_target = target.with_suffix(target.suffix + ".tmp")
        tmp_target.write_text(json.dumps(data, indent=2))
        tmp_target.replace(target)
        log.info(f"[calibrator] Saved {len(self._stats)} calibration records "
                 f"→ {target}")

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "ConfidenceCalibrator":
        target = path or CALIBRATION_PATH
        cal = cls()
        if not target.exists():
            return cal
        try:
            data    = json.loads(target.read_text())
            sensors = data.get("sensors", {})
            for key, s in sensors.items():
                stats = SourceStats(
                    source_id  = s["source_id"],
                    transition = s["transition"],
                    count      = s["count"],
                    reversals  = s["reversals"],
                    mean_conf  = s["mean_conf"],
                    conf_sum   = s["mean_conf"] * s["count"],
                )
                cal._stats[key] = stats
            log.info(f"[calibrator] Loaded {len(cal._stats)} calibration records "
                     f"from {target}")
        except Exception as exc:
            log.warning(f"[calibrator] Failed to load {target}: {exc}")
        return cal

    def report(self) -> str:
        """Human-readable calibration report."""
        if not self._stats:
            return "No calibration data — run: skg calibrate"

        lines = ["Sensor confidence calibration:"]
        lines.append(f"  {'Source':35s} {'Trans':20s} {'N':>5s} "
                     f"{'Rev':>5s} {'Prec':>6s} {'Factor':>7s}")
        lines.append(f"  {'-'*35} {'-'*20} {'-'*5} {'-'*5} {'-'*6} {'-'*7}")

        for key, stats in sorted(self._stats.items()):
            if stats.count < 2:
                continue
            flag = " ⚠" if stats.calibration_factor < 0.7 else ""
            lines.append(
                f"  {stats.source_id:35s} {stats.transition:20s} "
                f"{stats.count:5d} {stats.reversals:5d} "
                f"{stats.precision:6.2f} {stats.calibration_factor:7.3f}{flag}"
            )

        return "\n".join(lines)


# ── Module-level singleton ────────────────────────────────────────────────

_calibrator: Optional[ConfidenceCalibrator] = None


def load_calibration(path: Optional[Path] = None) -> ConfidenceCalibrator:
    """Load (or reload) the global calibrator from disk."""
    global _calibrator
    _calibrator = ConfidenceCalibrator.load(path)
    return _calibrator


def apply_calibration(source_id: str, raw_confidence: float,
                       transition: str = "unknown→realized") -> float:
    """
    Apply calibration to a confidence value using the global calibrator.
    Safe to call before calibration is loaded — returns raw_confidence unchanged.
    """
    global _calibrator
    if _calibrator is None:
        return raw_confidence
    return _calibrator.apply(source_id, raw_confidence, transition)


def calibrate_from_engagement(db_path: Path,
                               save: bool = True) -> ConfidenceCalibrator:
    """
    Build calibration from an engagement database and optionally save it.
    Called by `skg calibrate` and at daemon startup.
    """
    cal = ConfidenceCalibrator()
    cal.fit_from_engagement_db(db_path)

    if save:
        cal.save()

    global _calibrator
    _calibrator = cal
    return cal
