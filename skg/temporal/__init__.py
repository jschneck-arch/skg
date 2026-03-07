"""
skg.temporal
============
Temporal delta model for SKG.

Tracks state transitions between successive projections on the same workload.
A transition is a first-class event — not a side effect of projection, but
evidence about the *environment changing*.

Core concept
------------
A wicket's realization state is not a persistent label. It is a snapshot
of system state at a point in time under available evidence. When that state
changes between two projections, the delta is meaningful:

  unknown  → realized   : attack surface expansion (new evidence or new condition)
  realized → blocked    : remediation observed
  realized → unknown    : evidence decay (sensor lost visibility — itself a signal)
  blocked  → realized   : regression (control removed or bypassed)
  unknown  → blocked    : new control observed
  blocked  → unknown    : control evidence lost

The DeltaStore records every transition and provides:
  - Per-workload state history for any wicket
  - Cross-workload delta aggregation (how many workloads changed state today)
  - Velocity: rate of state change for a workload (high velocity = unstable environment)
  - Persistence: how long has a wicket been in its current state

These feed into:
  - The WorkloadGraph (cross-target inference)
  - The ObservationMemory (confidence calibration)
  - The daemon status / resonance surface
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

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
    "surface_expansion":      1.0,   # high signal — new attack surface
    "regression":             1.0,   # high signal — control removed
    "remediation":            0.8,   # strong — confirmed fix
    "evidence_decay":         0.6,   # medium — could be sensor gap or real change
    "control_observed":       0.5,
    "control_evidence_lost":  0.5,
    "persistence_confirmed":  0.2,
    "control_persists":       0.2,
    "still_unknown":          0.0,
}


@dataclass
class WicketTransition:
    """A single wicket state change between two projection runs."""
    workload_id:    str
    domain:         str
    wicket_id:      str
    attack_path_id: str
    from_state:     str          # realized | blocked | unknown
    to_state:       str
    from_run_id:    str
    to_run_id:      str
    from_ts:        str
    to_ts:          str
    meaning:        str          # from TRANSITION_MEANINGS
    signal_weight:  float        # from SIGNAL_WEIGHT
    aprs_delta:     float        # change in path score (positive = worse)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "WicketTransition":
        return cls(**d)


@dataclass
class WorkloadSnapshot:
    """The projection state of a single workload at a point in time."""
    workload_id:    str
    domain:         str
    attack_path_id: str
    run_id:         str
    ts:             str
    wicket_states:  dict[str, str]   # wicket_id → realized|blocked|unknown
    aprs:           float
    classification: str              # realized|not_realized|indeterminate

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "WorkloadSnapshot":
        return cls(**d)


class DeltaStore:
    """
    Append-only store of workload snapshots and wicket transitions.

    Layout under DELTA_DIR:
      snapshots/<workload_id>.jsonl   — all snapshots for this workload
      transitions/<workload_id>.jsonl — all transitions for this workload
      index.jsonl                     — cross-workload index (latest per workload)

    The store is the memory of the environment over time.
    It is never compacted or overwritten — only appended.
    """

    def __init__(self, delta_dir: Path):
        self.delta_dir     = delta_dir
        self.snapshots_dir = delta_dir / "snapshots"
        self.trans_dir     = delta_dir / "transitions"
        self.index_path    = delta_dir / "index.jsonl"
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
        Ingest a completed projection result (from INTERP_DIR).
        Compares against the previous snapshot for this workload.
        Records the new snapshot and any transitions.
        Returns list of transitions detected.
        """
        ts = ts or datetime.now(timezone.utc).isoformat()
        attack_path_id = interp.get("attack_path_id", "")

        # Build current wicket state map from projection output
        wicket_states: dict[str, str] = {}
        for w in interp.get("realized", []):
            wicket_states[w] = "realized"
        for w in interp.get("blocked", []):
            wicket_states[w] = "blocked"
        for w in interp.get("unknown", []):
            wicket_states[w] = "unknown"
        # Catch any required wickets not in any list
        for w in interp.get("required_wickets", []):
            if w not in wicket_states:
                wicket_states[w] = "unknown"

        aprs = interp.get("aprs", interp.get("lateral_score",
               interp.get("escape_score", 0.0)))
        classification = interp.get("classification", "indeterminate")

        snapshot = WorkloadSnapshot(
            workload_id=workload_id,
            domain=domain,
            attack_path_id=attack_path_id,
            run_id=run_id,
            ts=ts,
            wicket_states=wicket_states,
            aprs=float(aprs),
            classification=classification,
        )

        # Load previous snapshot to compute transitions
        prev = self._latest_snapshot(workload_id, attack_path_id)
        transitions: list[WicketTransition] = []

        if prev is not None:
            transitions = self._compute_transitions(prev, snapshot)
            if transitions:
                self._write_transitions(workload_id, transitions)
                for t in transitions:
                    log.info(
                        f"[delta] {workload_id} {t.wicket_id}: "
                        f"{t.from_state}→{t.to_state} ({t.meaning})"
                    )

        # Always append the new snapshot
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
            to_state   = curr.wicket_states.get(wid, "unknown")
            meaning    = TRANSITION_MEANINGS.get((from_state, to_state), "unknown")
            weight     = SIGNAL_WEIGHT.get(meaning, 0.0)

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
            ))

        return transitions

    # ── Queries ───────────────────────────────────────────────────────────────

    def _latest_snapshot(
        self, workload_id: str, attack_path_id: str
    ) -> WorkloadSnapshot | None:
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
        How often has this wicket changed state on this workload?
        High velocity = environment is unstable or sensors are noisy.
        """
        transitions = [
            t for t in self.workload_transitions(workload_id)
            if t.wicket_id == wicket_id
            and t.meaning not in ("persistence_confirmed", "control_persists", "still_unknown")
        ]
        return {
            "workload_id":    workload_id,
            "wicket_id":      wicket_id,
            "transition_count": len(transitions),
            "last_change":    transitions[-1].to_ts if transitions else None,
            "last_meaning":   transitions[-1].meaning if transitions else None,
        }

    def environment_summary(self) -> dict:
        """Cross-workload summary: surface expansion events, regressions, remediations."""
        expansions   = []
        regressions  = []
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
            "workload_count":    len(workloads),
            "surface_expansions": len(expansions),
            "regressions":        len(regressions),
            "remediations":       len(remediations),
            "last_expansion":     expansions[-1].to_dict() if expansions else None,
            "last_regression":    regressions[-1].to_dict() if regressions else None,
        }

    def all_workloads_latest(self) -> list[dict]:
        """Latest snapshot for every known workload."""
        result = []
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
            "workload_id":    snap.workload_id,
            "domain":         snap.domain,
            "attack_path_id": snap.attack_path_id,
            "ts":             snap.ts,
            "aprs":           snap.aprs,
            "classification": snap.classification,
        }
        with self.index_path.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")


def _safe(s: str) -> str:
    """Make a string safe for use as a filename."""
    return s.replace("/", "_").replace(":", "_").replace(" ", "_")[:120]
