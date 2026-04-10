from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from skg.temporal.interp import canonical_interp_payload, normalize_interp_classification

log = logging.getLogger("skg.temporal")

StateValue = Literal["realized", "blocked", "unknown"]

TRANSITION_MEANINGS = {
    ("unknown",  "realized"): "surface_expansion",
    ("realized", "blocked"):  "remediation",
    ("realized", "unknown"):  "evidence_decay",
    ("blocked",  "realized"): "regression",
    ("unknown",  "blocked"):  "control_observed",
    ("blocked",  "unknown"):  "control_evidence_lost",
    ("realized", "realized"): "persistence_confirmed",
    ("blocked",  "blocked"):  "control_persists",
    ("unknown",  "unknown"):  "still_unknown",
}

SIGNAL_WEIGHT = {
    "surface_expansion":      1.0,
    "regression":             1.0,
    "remediation":            0.8,
    "evidence_decay":         0.6,
    "control_observed":       0.5,
    "control_evidence_lost":  0.5,
    "persistence_confirmed":  0.2,
    "control_persists":       0.2,
    "still_unknown":          0.0,
}


def _safe(s: str) -> str:
    """Make a string safe for use as a filename."""
    return s.replace("/", "_").replace(":", "_").replace(" ", "_")[:120]


def _float_or(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


@dataclass
class WicketTransition:
    """
    A single wicket/node state change between two projection runs.

    Backward-compatible name retained.
    Conceptually this now means: transition of an atomic condition
    within a workload/path context.
    """
    workload_id: str
    domain: str
    wicket_id: str
    attack_path_id: str
    from_state: str
    to_state: str
    from_run_id: str
    to_run_id: str
    from_ts: str
    to_ts: str
    meaning: str
    signal_weight: float
    aprs_delta: float

    # richer optional temporal metadata
    from_confidence: float = 0.0
    to_confidence: float = 0.0
    confidence_delta: float = 0.0

    from_local_energy: float = 0.0
    to_local_energy: float = 0.0
    local_energy_delta: float = 0.0

    from_phase: float = 0.0
    to_phase: float = 0.0
    phase_delta: float = 0.0

    from_is_latent: bool = False
    to_is_latent: bool = False
    latent_delta: int = 0

    # evidence rank of the observation that produced the to_state
    evidence_rank: int = 1

    def to_dict(self) -> dict:
        d = asdict(self)
        # node_id alias for future substrate normalization
        d["node_id"] = self.wicket_id
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "WicketTransition":
        if "wicket_id" not in d and "node_id" in d:
            d = dict(d)
            d["wicket_id"] = d["node_id"]
        return cls(**{k: v for k, v in d.items() if k != "node_id"})

    @property
    def node_id(self) -> str:
        return self.wicket_id


@dataclass
class WorkloadSnapshot:
    """
    The projection state of a single workload at a point in time.

    Backward-compatible wicket naming is preserved, but the structure now
    supports node-compatible condition metadata.
    """
    workload_id: str
    domain: str
    attack_path_id: str
    run_id: str
    ts: str
    wicket_states: dict[str, str]
    aprs: float
    classification: str

    # richer optional snapshot metadata
    wicket_confidences: dict[str, float] = field(default_factory=dict)
    wicket_local_energy: dict[str, float] = field(default_factory=dict)
    wicket_phase: dict[str, float] = field(default_factory=dict)
    wicket_is_latent: dict[str, bool] = field(default_factory=dict)

    total_local_energy: float = 0.0
    mean_local_energy: float = 0.0
    latent_count: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        # node-compatible aliases
        d["node_states"] = self.wicket_states
        d["node_confidences"] = self.wicket_confidences
        d["node_local_energy"] = self.wicket_local_energy
        d["node_phase"] = self.wicket_phase
        d["node_is_latent"] = self.wicket_is_latent
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "WorkloadSnapshot":
        d = dict(d)

        if "wicket_states" not in d and "node_states" in d:
            d["wicket_states"] = d["node_states"]

        if "wicket_confidences" not in d and "node_confidences" in d:
            d["wicket_confidences"] = d["node_confidences"]

        if "wicket_local_energy" not in d and "node_local_energy" in d:
            d["wicket_local_energy"] = d["node_local_energy"]

        if "wicket_phase" not in d and "node_phase" in d:
            d["wicket_phase"] = d["node_phase"]

        if "wicket_is_latent" not in d and "node_is_latent" in d:
            d["wicket_is_latent"] = d["node_is_latent"]

        # strip aliases before class init
        for alias in (
            "node_states",
            "node_confidences",
            "node_local_energy",
            "node_phase",
            "node_is_latent",
        ):
            d.pop(alias, None)

        return cls(**d)

    @property
    def node_states(self) -> dict[str, str]:
        return self.wicket_states


class DeltaStore:
    """
    Append-only store of workload snapshots and wicket/node transitions.

    Layout under DELTA_DIR:
      snapshots/<workload_id>.jsonl   — all snapshots for this workload
      transitions/<workload_id>.jsonl — all transitions for this workload
      index.jsonl                     — cross-workload index (latest per workload)

    The store is the memory of the environment over time.
    It is never compacted or overwritten — only appended.
    """

    def __init__(self, delta_dir: Path):
        self.delta_dir = delta_dir
        self.snapshots_dir = delta_dir / "snapshots"
        self.trans_dir = delta_dir / "transitions"
        self.index_path = delta_dir / "index.jsonl"
        self._ensure_dirs()

    def _ensure_dirs(self):
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.trans_dir.mkdir(parents=True, exist_ok=True)

    # ── Snapshot ingestion ────────────────────────────────────────────────────

    def ingest_projection(
        self,
        interp: dict,
        workload_id: str,
        domain: str,
        run_id: str,
        ts: str | None = None,
    ) -> list[WicketTransition]:
        """
        Ingest a completed projection result.
        Compares against the previous snapshot for this workload.
        Records the new snapshot and any transitions.
        Returns list of transitions detected.

        Backward compatible with current projection output while accepting
        richer optional fields:
        - confidence_by_node / confidence_by_wicket
        - local_energy_by_node / local_energy_by_wicket
        - phase_by_node / phase_by_wicket
        - latent_nodes
        """
        interp = canonical_interp_payload(interp)
        ts = ts or datetime.now(timezone.utc).isoformat()
        attack_path_id = interp.get("attack_path_id", "")

        wicket_states: dict[str, str] = {}

        for w in interp.get("realized", []):
            wicket_states[w] = "realized"
        for w in interp.get("blocked", []):
            wicket_states[w] = "blocked"
        for w in interp.get("unknown", []):
            wicket_states[w] = "unknown"

        # Catch any required wickets/nodes not in any list
        for w in interp.get("required_wickets", []):
            if w not in wicket_states:
                wicket_states[w] = "unknown"
        for w in interp.get("required_nodes", []):
            if w not in wicket_states:
                wicket_states[w] = "unknown"

        aprs = interp.get(
            "aprs",
            interp.get("lateral_score", interp.get("escape_score", 0.0))
        )
        classification = normalize_interp_classification(
            interp.get("classification", "unknown")
        )

        wicket_confidences = dict(
            interp.get("confidence_by_wicket", interp.get("confidence_by_node", {})) or {}
        )
        wicket_local_energy = dict(
            interp.get("local_energy_by_wicket", interp.get("local_energy_by_node", {})) or {}
        )
        wicket_phase = dict(
            interp.get("phase_by_wicket", interp.get("phase_by_node", {})) or {}
        )

        latent_nodes = set(interp.get("latent_nodes", []) or [])
        wicket_is_latent = {wid: (wid in latent_nodes) for wid in wicket_states}

        total_local_energy = round(sum(_float_or(v, 0.0) for v in wicket_local_energy.values()), 6)
        mean_local_energy = round(
            total_local_energy / len(wicket_states), 6
        ) if wicket_states else 0.0
        latent_count = sum(1 for _, is_latent in wicket_is_latent.items() if is_latent)

        snapshot = WorkloadSnapshot(
            workload_id=workload_id,
            domain=domain,
            attack_path_id=attack_path_id,
            run_id=run_id,
            ts=ts,
            wicket_states=wicket_states,
            aprs=float(aprs),
            classification=classification,
            wicket_confidences={k: _float_or(v, 0.0) for k, v in wicket_confidences.items()},
            wicket_local_energy={k: _float_or(v, 0.0) for k, v in wicket_local_energy.items()},
            wicket_phase={k: _float_or(v, 0.0) for k, v in wicket_phase.items()},
            wicket_is_latent={k: bool(v) for k, v in wicket_is_latent.items()},
            total_local_energy=total_local_energy,
            mean_local_energy=mean_local_energy,
            latent_count=latent_count,
        )

        prev = self._latest_snapshot(workload_id, attack_path_id)
        transitions: list[WicketTransition] = []

        if prev is not None:
            transitions = self._compute_transitions(prev, snapshot)
            if transitions:
                self._write_transitions(workload_id, transitions)
                for t in transitions:
                    log.info(
                        f"[delta] {workload_id} {t.wicket_id}: "
                        f"{t.from_state}→{t.to_state} ({t.meaning}) "
                        f"Δconf={t.confidence_delta:+.3f} "
                        f"ΔE={t.local_energy_delta:+.3f}"
                    )

        self._write_snapshot(workload_id, snapshot)
        self._update_index(snapshot)

        return transitions

    def _compute_transitions(
        self,
        prev: WorkloadSnapshot,
        curr: WorkloadSnapshot,
    ) -> list[WicketTransition]:
        transitions = []
        all_wickets = set(prev.wicket_states) | set(curr.wicket_states)
        aprs_delta = curr.aprs - prev.aprs

        for wid in all_wickets:
            from_state = prev.wicket_states.get(wid, "unknown")
            to_state = curr.wicket_states.get(wid, "unknown")
            meaning = TRANSITION_MEANINGS.get((from_state, to_state), "unknown")
            weight = SIGNAL_WEIGHT.get(meaning, 0.0)

            from_conf = _float_or(prev.wicket_confidences.get(wid, 0.0), 0.0)
            to_conf = _float_or(curr.wicket_confidences.get(wid, 0.0), 0.0)

            from_energy = _float_or(prev.wicket_local_energy.get(wid, 0.0), 0.0)
            to_energy = _float_or(curr.wicket_local_energy.get(wid, 0.0), 0.0)

            from_phase = _float_or(prev.wicket_phase.get(wid, 0.0), 0.0)
            to_phase = _float_or(curr.wicket_phase.get(wid, 0.0), 0.0)

            from_latent = bool(prev.wicket_is_latent.get(wid, False))
            to_latent = bool(curr.wicket_is_latent.get(wid, False))

            transitions.append(WicketTransition(
                workload_id=curr.workload_id,
                domain=curr.domain,
                wicket_id=wid,
                attack_path_id=curr.attack_path_id,
                from_state=from_state,
                to_state=to_state,
                from_run_id=prev.run_id,
                to_run_id=curr.run_id,
                from_ts=prev.ts,
                to_ts=curr.ts,
                meaning=meaning,
                signal_weight=weight,
                aprs_delta=round(aprs_delta, 6),
                from_confidence=round(from_conf, 6),
                to_confidence=round(to_conf, 6),
                confidence_delta=round(to_conf - from_conf, 6),
                from_local_energy=round(from_energy, 6),
                to_local_energy=round(to_energy, 6),
                local_energy_delta=round(to_energy - from_energy, 6),
                from_phase=round(from_phase, 6),
                to_phase=round(to_phase, 6),
                phase_delta=round(to_phase - from_phase, 6),
                from_is_latent=from_latent,
                to_is_latent=to_latent,
                latent_delta=(1 if to_latent else 0) - (1 if from_latent else 0),
            ))

        return transitions

    # ── Queries ───────────────────────────────────────────────────────────────

    def _latest_snapshot(self, workload_id: str, attack_path_id: str) -> WorkloadSnapshot | None:
        """Return the most recent snapshot for this workload+path, or None."""
        f = self.snapshots_dir / f"{_safe(workload_id)}.jsonl"
        if not f.exists():
            return None

        latest = None
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                s = WorkloadSnapshot.from_dict(json.loads(line))
                if s.attack_path_id == attack_path_id:
                    if latest is None or s.ts > latest.ts:
                        latest = s
            except Exception:
                pass
        return latest

    def workload_history(
        self, workload_id: str, attack_path_id: str | None = None
    ) -> list[WorkloadSnapshot]:
        """All snapshots for a workload, chronological."""
        f = self.snapshots_dir / f"{_safe(workload_id)}.jsonl"
        if not f.exists():
            return []

        snaps = []
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                s = WorkloadSnapshot.from_dict(json.loads(line))
                if attack_path_id is None or s.attack_path_id == attack_path_id:
                    snaps.append(s)
            except Exception:
                pass
        return sorted(snaps, key=lambda s: s.ts)

    def workload_transitions(
        self, workload_id: str, since: str | None = None
    ) -> list[WicketTransition]:
        """All transitions for a workload, optionally filtered by timestamp."""
        f = self.trans_dir / f"{_safe(workload_id)}.jsonl"
        if not f.exists():
            return []

        result = []
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                t = WicketTransition.from_dict(json.loads(line))
                if since is None or t.to_ts >= since:
                    result.append(t)
            except Exception:
                pass
        return sorted(result, key=lambda t: t.to_ts)

    def high_signal_transitions(
        self, since: str | None = None, min_weight: float = 0.8
    ) -> list[WicketTransition]:
        """
        Cross-workload: return all transitions with signal_weight >= min_weight.
        These are the events worth surfacing — new attack surface, regressions.
        """
        results = []
        for f in self.trans_dir.glob("*.jsonl"):
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    t = WicketTransition.from_dict(json.loads(line))
                    if t.signal_weight >= min_weight:
                        if since is None or t.to_ts >= since:
                            results.append(t)
                except Exception:
                    pass
        return sorted(results, key=lambda t: (t.to_ts, -t.signal_weight), reverse=True)

    def wicket_velocity(self, workload_id: str, wicket_id: str) -> dict:
        """
        How often has this wicket/node changed state on this workload?
        High velocity = environment is unstable or sensors are noisy.
        """
        transitions = [
            t for t in self.workload_transitions(workload_id)
            if t.wicket_id == wicket_id
            and t.meaning not in ("persistence_confirmed", "control_persists", "still_unknown")
        ]
        return {
            "workload_id": workload_id,
            "wicket_id": wicket_id,
            "node_id": wicket_id,
            "transition_count": len(transitions),
            "last_change": transitions[-1].to_ts if transitions else None,
            "last_meaning": transitions[-1].meaning if transitions else None,
            "mean_confidence_delta": round(
                sum(t.confidence_delta for t in transitions) / len(transitions), 6
            ) if transitions else 0.0,
            "mean_local_energy_delta": round(
                sum(t.local_energy_delta for t in transitions) / len(transitions), 6
            ) if transitions else 0.0,
        }

    def environment_summary(self) -> dict:
        """Cross-workload summary: expansions, regressions, remediations."""
        expansions = []
        regressions = []
        remediations = []

        for f in self.trans_dir.glob("*.jsonl"):
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    t = WicketTransition.from_dict(json.loads(line))
                    if t.meaning == "surface_expansion":
                        expansions.append(t)
                    elif t.meaning == "regression":
                        regressions.append(t)
                    elif t.meaning == "remediation":
                        remediations.append(t)
                except Exception:
                    pass

        workloads = set()
        for f in self.snapshots_dir.glob("*.jsonl"):
            workloads.add(f.stem)

        return {
            "workload_count": len(workloads),
            "surface_expansions": len(expansions),
            "regressions": len(regressions),
            "remediations": len(remediations),
            "last_expansion": expansions[-1].to_dict() if expansions else None,
            "last_regression": regressions[-1].to_dict() if regressions else None,
        }

    def all_workloads_latest(self) -> list[dict]:
        """Latest snapshot for every known workload."""
        seen: dict[str, dict] = {}
        if self.index_path.exists():
            for line in self.index_path.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    key = f"{entry['workload_id']}::{entry['attack_path_id']}"
                    seen[key] = entry
                except Exception:
                    pass
        return list(seen.values())

    # ── Persistence helpers ───────────────────────────────────────────────────

    def _write_snapshot(self, workload_id: str, snap: WorkloadSnapshot):
        f = self.snapshots_dir / f"{_safe(workload_id)}.jsonl"
        with f.open("a") as fh:
            fh.write(snap.to_json() + "\n")

    def _write_transitions(self, workload_id: str, transitions: list[WicketTransition]):
        f = self.trans_dir / f"{_safe(workload_id)}.jsonl"
        with f.open("a") as fh:
            for t in transitions:
                fh.write(t.to_json() + "\n")

    def _update_index(self, snap: WorkloadSnapshot):
        """Update the cross-workload index with latest snapshot metadata."""
        entry = {
            "workload_id": snap.workload_id,
            "domain": snap.domain,
            "attack_path_id": snap.attack_path_id,
            "ts": snap.ts,
            "aprs": snap.aprs,
            "classification": snap.classification,
            "total_local_energy": snap.total_local_energy,
            "mean_local_energy": snap.mean_local_energy,
            "latent_count": snap.latent_count,
        }
        with self.index_path.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def calibrate_confidence_weights(self) -> dict:
        """
        Learn confidence weight calibration from engagement history.

        Confidence weights are currently hand-tuned per sensor (evidence rank
        maps to a confidence value). This method uses DeltaStore's accumulated
        transition history to compute empirical calibration: for each evidence
        rank, what fraction of observations at that rank were later confirmed
        as realized (rather than remaining unknown or being superseded)?

        Method:
          1. Collect all U→R (surface_expansion) transitions — these are
             observations that were initially unknown and became realized.
             The evidence_rank at the time of first observation is the
             signal rank.
          2. For each rank, compute:
               precision = |confirmed_realized| / |all_observations_at_rank|
               This measures how often rank-k observations turn out to be real.
          3. The calibrated weight is:
               w_k = 0.5 + 0.5 * precision_k
             This maps precision ∈ [0,1] to weight ∈ [0.5,1.0], preserving
             the ordering while anchoring the uncalibrated prior at 0.5.

        Returns dict of calibration results per evidence rank with:
          precision:       fraction of observations confirmed realized
          calibrated_weight: recommended confidence weight for this rank
          n_confirmed:     count of confirmed realizations
          n_total:         total transitions at this rank
          delta_from_prior: how much calibrated weight differs from 0.5 prior

        If insufficient data (< 10 transitions per rank), returns the
        hand-tuned defaults and flags the rank as 'insufficient_data'.

        This result can be used to update the sensor confidence weights in
        skg_config.yaml or passed directly to FeedbackIngester.
        """
        # Collect all transitions from all workloads
        all_transitions: list[WicketTransition] = []
        for f in self.trans_dir.glob("*.jsonl"):
            for line in f.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    all_transitions.append(WicketTransition.from_dict(json.loads(line)))
                except Exception:
                    pass

        if not all_transitions:
            return {"status": "no_data", "calibration": {}}

        # Group by evidence_rank
        # evidence_rank is stored in transition metadata when available
        from collections import defaultdict
        rank_totals:    dict[int, int] = defaultdict(int)
        rank_confirmed: dict[int, int] = defaultdict(int)

        for t in all_transitions:
            # evidence_rank lives in the transition's metadata field if present
            rank = t.evidence_rank if hasattr(t, "evidence_rank") else None
            if rank is None:
                meta = getattr(t, "metadata", {}) or {}
                rank = meta.get("evidence_rank")
            if rank is None:
                continue
            try:
                rank = int(rank)
            except (ValueError, TypeError):
                continue

            rank_totals[rank] += 1
            # U→R transitions are confirmations
            if t.from_state == "unknown" and t.to_state == "realized":
                rank_confirmed[rank] += 1

        MIN_SAMPLES = 10
        # Hand-tuned defaults from Work 3 (prior to calibration)
        DEFAULT_WEIGHTS = {1: 0.95, 2: 0.80, 3: 0.70, 4: 0.60, 5: 0.50, 6: 0.40}

        calibration: dict = {}
        for rank in sorted(set(list(rank_totals.keys()) + list(DEFAULT_WEIGHTS.keys()))):
            n_total     = rank_totals.get(rank, 0)
            n_confirmed = rank_confirmed.get(rank, 0)
            default_w   = DEFAULT_WEIGHTS.get(rank, 0.5)

            if n_total < MIN_SAMPLES:
                calibration[rank] = {
                    "status":            "insufficient_data",
                    "n_total":           n_total,
                    "n_confirmed":       n_confirmed,
                    "precision":         None,
                    "calibrated_weight": default_w,
                    "default_weight":    default_w,
                    "delta_from_prior":  0.0,
                    "note":              f"Using default ({default_w:.2f}): "
                                         f"need ≥{MIN_SAMPLES} transitions, have {n_total}",
                }
            else:
                precision    = n_confirmed / n_total
                # w = 0.5 + 0.5 * precision maps [0,1] → [0.5,1.0]
                # This preserves monotone ordering while bounding from below at 0.5
                calibrated_w = round(0.5 + 0.5 * precision, 4)
                delta        = round(calibrated_w - default_w, 4)
                calibration[rank] = {
                    "status":            "calibrated",
                    "n_total":           n_total,
                    "n_confirmed":       n_confirmed,
                    "precision":         round(precision, 4),
                    "calibrated_weight": calibrated_w,
                    "default_weight":    default_w,
                    "delta_from_prior":  delta,
                    "note":              (
                        f"rank {rank}: precision={precision:.2%} → w={calibrated_w:.3f} "
                        f"({'↑' if delta > 0.01 else '↓' if delta < -0.01 else '≈'}"
                        f"{abs(delta):.3f} from default {default_w:.2f})"
                    ),
                }

        return {
            "status":       "ok",
            "n_transitions": len(all_transitions),
            "n_ranks":       len(calibration),
            "calibration":   calibration,
        }
