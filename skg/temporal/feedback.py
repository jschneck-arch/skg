"""
skg.temporal.feedback
=====================
Feedback ingester — closes the loop from INTERP_DIR back into the
temporal delta model, workload graph, and observation memory.

This is the component that makes SKG learn from its own projections.

Pipeline
--------
1. Watch INTERP_DIR for new projection files
2. For each new file:
   a. Parse the projection result
   b. Ingest into DeltaStore → compute wicket transitions
   c. For each high-signal transition, propagate via WorkloadGraph
   d. For each confirmed wicket state, record outcomes in ObservationMemory
   e. Auto-discover workload relationships from the event stream
3. Record processed files in state to avoid re-processing

Called by the daemon's sensor loop tick (after sensors run, after projection):
  feedback_ingester.process_new_interps()

Can also be called manually:
  skg feedback process          # process any unprocessed interp files
  skg feedback status           # show delta/graph/obs memory stats
  skg feedback timeline <wid>   # show state history for a workload
  skg feedback surface          # show high-signal transitions across all workloads
  skg feedback graph add-edge <w1> <w2> <rel>  # manually add relationship
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from skg.temporal import DeltaStore, WicketTransition
from skg.graph import WorkloadGraph
from skg.core.paths import INTERP_DIR, EVENTS_DIR, SKG_STATE_DIR

log = logging.getLogger("skg.temporal.feedback")

FEEDBACK_STATE_FILE = SKG_STATE_DIR / "feedback.state.json"

# Domain name inference from interp file naming and content
DOMAIN_FROM_SCORE_KEY = {
    "aprs":          "aprs",
    "lateral_score": "ad_lateral",
    "escape_score":  "container_escape",
}


def _infer_domain(interp: dict, filename: str) -> str:
    for key, domain in DOMAIN_FROM_SCORE_KEY.items():
        if key in interp:
            return domain
    fname = filename.lower()
    if "lateral" in fname or "ad_" in fname:
        return "ad_lateral"
    if "escape" in fname or "container" in fname:
        return "container_escape"
    if "aprs" in fname or "log4j" in fname:
        return "aprs"
    if "host" in fname:
        return "host"
    return "unknown"


def _extract_workload_run(filename: str) -> tuple[str, str]:
    """
    Extract workload_id and run_id from interp filename.
    Convention: <domain>_<workload_id>_<run_id>.json
    or: host_<workload_id>_<run_id>.json
    """
    stem = Path(filename).stem
    parts = stem.split("_")
    if len(parts) >= 3:
        run_id     = parts[-1]
        workload_id = "_".join(parts[1:-1])
        return workload_id, run_id
    return stem, "unknown"


class FeedbackIngester:
    """
    Watches INTERP_DIR for new projection results and feeds them back
    into the temporal, graph, and observation memory systems.
    """

    def __init__(
        self,
        delta_store: DeltaStore,
        graph: WorkloadGraph,
        obs_memory,  # ObservationMemory (optional — None if resonance not loaded)
        interp_dir: Path = INTERP_DIR,
        events_dir: Path = EVENTS_DIR,
    ):
        self.delta  = delta_store
        self.graph  = graph
        self.obs    = obs_memory
        self.interp_dir = interp_dir
        self.events_dir = events_dir
        self._state = self._load_state()

    def _load_state(self) -> dict:
        if FEEDBACK_STATE_FILE.exists():
            try:
                return json.loads(FEEDBACK_STATE_FILE.read_text())
            except Exception:
                pass
        return {"processed_interps": [], "last_run": ""}

    def _save_state(self):
        FEEDBACK_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        FEEDBACK_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def process_new_interps(self) -> dict:
        """
        Process all unprocessed interp files in INTERP_DIR.
        Returns summary of what was processed.
        """
        if not self.interp_dir.exists():
            return {"processed": 0, "transitions": 0, "propagations": 0}

        processed_set = set(self._state["processed_interps"])
        new_files = [
            f for f in sorted(self.interp_dir.glob("*.json"))
            if f.name not in processed_set
        ]

        total_transitions = 0
        total_propagations = 0

        for interp_file in new_files:
            try:
                result = self._process_one(interp_file)
                total_transitions += result["transitions"]
                total_propagations += result["propagations"]
                processed_set.add(interp_file.name)
            except Exception as exc:
                log.error(f"Feedback: failed to process {interp_file.name}: {exc}", exc_info=True)

        self._state["processed_interps"] = list(processed_set)
        self._state["last_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state()

        # Also auto-discover graph edges from recent events
        self._auto_discover_edges()

        return {
            "processed": len(new_files),
            "transitions": total_transitions,
            "propagations": total_propagations,
        }

    def _process_one(self, interp_file: Path) -> dict:
        """Process a single projection interp file."""
        interp = json.loads(interp_file.read_text())

        workload_id, run_id = _extract_workload_run(interp_file.name)
        domain = _infer_domain(interp, interp_file.name)

        # Override workload_id from content if present
        workload_id = interp.get("workload_id", workload_id)

        ts = interp.get("computed_at", datetime.now(timezone.utc).isoformat())

        # 1. DeltaStore: detect state transitions
        transitions = self.delta.ingest_projection(
            interp=interp,
            workload_id=workload_id,
            domain=domain,
            run_id=run_id,
            ts=ts,
        )

        # 2. WorkloadGraph: propagate high-signal transitions
        propagations = 0
        for t in transitions:
            if t.signal_weight >= 0.8:  # only high-signal
                self.graph.propagate_transition(
                    source_workload=workload_id,
                    wicket_id=t.wicket_id,
                    domain=domain,
                    to_state=t.to_state,
                    signal_weight=t.signal_weight,
                )
                propagations += 1

        # Decay priors for this workload (it was just projected)
        self.graph.decay_priors(workload_id)

        # 3. ObservationMemory: close the loop on pending observations
        if self.obs is not None:
            self._close_observations(workload_id, interp, domain)

        log.info(
            f"[feedback] {interp_file.name}: "
            f"{len(transitions)} transitions, {propagations} propagated"
        )

        return {"transitions": len(transitions), "propagations": propagations}

    def _close_observations(self, workload_id: str, interp: dict, domain: str):
        """
        For each wicket with a confirmed state in this projection,
        find matching pending observations and record outcomes.
        """
        # Build realized/blocked/unknown maps from projection
        outcomes: dict[str, str] = {}
        for w in interp.get("realized", []):
            outcomes[w] = "realized"
        for w in interp.get("blocked", []):
            outcomes[w] = "blocked"
        for w in interp.get("unknown", []):
            outcomes[w] = "unknown"

        # Walk pending observations and close any matching this workload
        if not self.obs.pending_path.exists():
            return

        lines = self.obs.pending_path.read_text(errors="replace").splitlines()
        for line in lines:
            if not line.strip():
                continue
            try:
                from skg.resonance.observation_memory import ObservationRecord
                rec = ObservationRecord.from_dict(json.loads(line))
                if rec.workload_id == workload_id and rec.wicket_id in outcomes:
                    self.obs.record_outcome(rec.record_id, outcomes[rec.wicket_id])
            except Exception:
                pass

    def _auto_discover_edges(self):
        """
        Read recent event files and auto-discover workload relationships.
        Runs after each feedback cycle.
        """
        if not self.events_dir.exists():
            return
        # Read last 20 event files
        event_files = sorted(self.events_dir.glob("*.ndjson"))[-20:]
        events = []
        for f in event_files:
            for line in f.read_text(errors="replace").splitlines():
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
        if events:
            self.graph.infer_edges_from_events(events)

    def status(self) -> dict:
        return {
            "last_run":          self._state.get("last_run", ""),
            "processed_interps": len(self._state.get("processed_interps", [])),
            "delta":   self.delta.environment_summary(),
            "graph":   self.graph.status(),
            "obs":     self.obs.status() if self.obs else None,
        }

    def timeline(self, workload_id: str, attack_path_id: str | None = None) -> dict:
        """State history for a workload — for CLI output."""
        history = self.delta.workload_history(workload_id, attack_path_id)
        transitions = self.delta.workload_transitions(workload_id)

        return {
            "workload_id":   workload_id,
            "snapshot_count": len(history),
            "snapshots":     [s.to_dict() for s in history],
            "transitions":   [t.to_dict() for t in transitions],
            "graph_neighbors": self.graph.neighbors(workload_id),
        }

    def surface(self, min_weight: float = 0.8) -> dict:
        """High-signal transitions across all workloads."""
        transitions = self.delta.high_signal_transitions(min_weight=min_weight)
        return {
            "high_signal_transitions": [t.to_dict() for t in transitions[:50]],
            "total":                   len(transitions),
        }
