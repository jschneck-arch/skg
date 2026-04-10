from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from skg.temporal import DeltaStore, WicketTransition
from skg.graph import WorkloadGraph
from skg.identity import parse_workload_ref
from skg.kernel.pearls import Pearl, PearlLedger
from skg_core.config.paths import INTERP_DIR, EVENTS_DIR, SKG_STATE_DIR
from skg.temporal.interp import read_interp_payload

log = logging.getLogger("skg.temporal.feedback")

FEEDBACK_STATE_FILE = SKG_STATE_DIR / "feedback.state.json"

# Domain name inference from interp file naming and content
DOMAIN_FROM_SCORE_KEY = {
    "aprs":          "aprs",
    "lateral_score": "ad_lateral",
    "escape_score":  "container_escape",
}


def _infer_domain(interp: dict, filename: str) -> str:
    payload = interp.get("payload") if isinstance(interp.get("payload"), dict) else interp
    explicit = str(payload.get("domain") or interp.get("domain") or "").strip()
    if explicit:
        return explicit

    for key, domain in DOMAIN_FROM_SCORE_KEY.items():
        if key in payload:
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

    Convention examples:
      <domain>_<workload_id>_<run_id>.json
      host_<workload_id>_<run_id>.json
    """
    stem = Path(filename).stem
    if "__" in stem:
        parts = stem.split("__")
        if len(parts) >= 4:
            return parts[1], parts[-1]
    parts = stem.split("_")
    if len(parts) >= 3:
        run_id = parts[-1]
        workload_id = "_".join(parts[1:-1])
        return workload_id, run_id
    return stem, "unknown"


def _extract_target_hint(text: str) -> str:
    for tok in str(text or "").replace("[", " ").replace("]", " ").replace(",", " ").split():
        if tok.count(".") == 3:
            return tok.split(":")[0]
    return ""


def _transition_subject_id(t: WicketTransition) -> str:
    """
    Backward-compatible alias:
    existing graph code still expects wicket_id semantics,
    but temporal transitions are now also node-compatible.
    """
    return getattr(t, "node_id", t.wicket_id)


def _should_propagate_transition(t: WicketTransition) -> bool:
    """
    Conservative propagation rule.

    Current behavior remains mostly the same:
    - only high-signal transitions propagate

    But richer metadata can now be used as tie-break context later.
    """
    if t.signal_weight >= 0.8:
        return True
    return False


class FeedbackIngester:
    """
    Watches INTERP_DIR for new projection results and feeds them back
    into the temporal, graph, and observation memory systems.

    Important boundary:
    - feedback routes consequences
    - feedback does not define truth
    """

    def __init__(
        self,
        delta_store: DeltaStore,
        graph: WorkloadGraph,
        obs_memory,  # ObservationMemory (optional — None if resonance not loaded)
        interp_dir: Path = INTERP_DIR,
        events_dir: Path = EVENTS_DIR,
        pearls_path: Path = SKG_STATE_DIR / "pearls.jsonl",
    ):
        self.delta = delta_store
        self.graph = graph
        self.obs = obs_memory
        self.interp_dir = interp_dir
        self.events_dir = events_dir
        self.pearls = PearlLedger(pearls_path)
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
                log.error(
                    f"Feedback: failed to process {interp_file.name}: {exc}",
                    exc_info=True,
                )

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
        interp = read_interp_payload(interp_file)
        if not interp:
            raise ValueError(f"invalid interp payload: {interp_file.name}")

        workload_id, run_id = _extract_workload_run(interp_file.name)
        domain = _infer_domain(interp, interp_file.name)

        # Override workload_id from content if present
        workload_id = interp.get("workload_id", workload_id)
        run_id = interp.get("run_id", run_id)

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
            if _should_propagate_transition(t):
                subject_id = _transition_subject_id(t)

                self.graph.propagate_transition(
                    source_workload=workload_id,
                    wicket_id=subject_id,   # preserve current graph API
                    domain=domain,
                    to_state=t.to_state,
                    signal_weight=t.signal_weight,
                )

                # Cross-domain same-target coupling.
                # When a high-signal realization fires on this target,
                # adjacent domains on the same target see elevated priors.
                if t.to_state == "realized" and t.signal_weight >= 0.8:
                    self.graph.propagate_intra_target(
                        source_workload=workload_id,
                        source_domain=domain,
                        wicket_id=subject_id,
                        signal_weight=t.signal_weight,
                    )

                propagations += 1

                log.debug(
                    f"[feedback.propagate] {workload_id} {subject_id} "
                    f"{t.from_state}->{t.to_state} "
                    f"Δconf={getattr(t, 'confidence_delta', 0.0):+.3f} "
                    f"ΔE={getattr(t, 'local_energy_delta', 0.0):+.3f}"
                )

        # Decay priors for this workload (it was just projected)
        self.graph.decay_priors(workload_id)

        # Clear priors immediately for nodes that just resolved (U→R or U→B).
        # Gravity should stop pulling toward nodes that are no longer unknown.
        for t in transitions:
            if t.to_state in ("realized", "blocked"):
                subject_id = _transition_subject_id(t)
                self.graph.clear_prior(workload_id, subject_id)

        self._record_projection_pearl(workload_id, domain, run_id, interp, transitions)

        # 3. ObservationMemory: close the loop on pending observations
        if self.obs is not None:
            self._close_observations(workload_id, interp, domain)

        log.info(
            f"[feedback] {interp_file.name}: "
            f"{len(transitions)} transitions, {propagations} propagated"
        )

        return {"transitions": len(transitions), "propagations": propagations}

    def _record_projection_pearl(
        self,
        workload_id: str,
        domain: str,
        run_id: str,
        interp: dict,
        transitions: list[WicketTransition],
    ) -> None:
        parsed = parse_workload_ref(workload_id)
        identity_key = parsed.get("identity_key", "")
        manifestation_key = parsed.get("manifestation_key", "")
        attack_path_id = str(interp.get("attack_path_id", "") or "")
        classification = str(interp.get("classification", "unknown") or "unknown")

        state_changes = [
            {
                "workload_id": workload_id,
                "attack_path_id": t.attack_path_id,
                "wicket_id": t.wicket_id,
                "from": t.from_state,
                "to": t.to_state,
                "signal_weight": t.signal_weight,
                "confidence_delta": t.confidence_delta,
                "local_energy_delta": t.local_energy_delta,
            }
            for t in transitions
        ]

        observation_confirms = []
        for status in ("realized", "blocked"):
            for wicket_id in interp.get(status, []) or []:
                observation_confirms.append({
                    "workload_id": workload_id,
                    "attack_path_id": attack_path_id,
                    "wicket_id": wicket_id,
                    "status": status,
                })

        projection_changes = []
        if domain or attack_path_id or classification != "unknown":
            projection_changes.append({
                "kind": "projection_ingest",
                "added": [domain] if domain else [],
                "removed": [],
                "attack_path_id": attack_path_id,
                "classification": classification,
                "run_id": run_id,
            })

        if not (state_changes or observation_confirms or projection_changes):
            return

        total_energy = float(interp.get("total_energy", 0.0) or 0.0)
        if total_energy == 0.0:
            total_energy = sum(
                float((interp.get("unresolved_detail", {}) or {}).get(wid, {}).get("local_energy", 0.0) or 0.0)
                for wid in interp.get("unknown", []) or []
            )

        self.pearls.record(Pearl(
            state_changes=state_changes,
            observation_confirms=observation_confirms,
            projection_changes=projection_changes,
            energy_snapshot={
                "target_ip": identity_key,
                "workload_id": workload_id,
                "identity_key": identity_key,
                "manifestation_key": manifestation_key,
                "domain": domain,
                "run_id": run_id,
                "attack_path_id": attack_path_id,
                "classification": classification,
                "E": round(total_energy, 6),
                "decay_class": "operational" if (state_changes or observation_confirms) else "structural",
            },
            target_snapshot={
                "workload_id": workload_id,
                "identity_key": identity_key,
                "manifestation_key": manifestation_key,
                "domain": domain,
                "attack_path_id": attack_path_id,
            },
        ))

    def _close_observations(self, workload_id: str, interp: dict, domain: str):
        """
        For each wicket/node with a confirmed state in this projection,
        find matching pending observations and record outcomes.
        """
        outcomes: dict[str, str] = {}

        for w in interp.get("realized", []):
            outcomes[w] = "realized"
        for w in interp.get("blocked", []):
            outcomes[w] = "blocked"
        for w in interp.get("unknown", []):
            outcomes[w] = "unknown"

        if not self.obs.pending_path.exists():
            return

        lines = self.obs.pending_path.read_text(errors="replace").splitlines()
        workload_target = _extract_target_hint(workload_id)
        for line in lines:
            if not line.strip():
                continue
            try:
                from skg.resonance.observation_memory import ObservationRecord

                rec = ObservationRecord.from_dict(json.loads(line))
                rec_subject_id = getattr(rec, "node_id", getattr(rec, "wicket_id", ""))

                same_workload = rec.workload_id == workload_id
                same_target = False
                if workload_target:
                    same_target = (
                        workload_target in str(rec.workload_id)
                        or workload_target in str(rec.evidence_text)
                    )

                if (same_workload or same_target) and rec.domain == domain and rec_subject_id in outcomes:
                    self.obs.record_outcome(rec.record_id, outcomes[rec_subject_id])
            except Exception:
                pass

    def _auto_discover_edges(self):
        """
        Read recent event files and auto-discover workload relationships.
        Runs after each feedback cycle.
        """
        if not self.events_dir.exists():
            return

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
            "last_run": self._state.get("last_run", ""),
            "processed_interps": len(self._state.get("processed_interps", [])),
            "delta": self.delta.environment_summary(),
            "graph": self.graph.status(),
            "pearls": self.pearls.count(),
            "obs": self.obs.status() if self.obs else None,
        }

    def timeline(self, workload_id: str, attack_path_id: str | None = None) -> dict:
        """State history for a workload — for CLI output."""
        history = self.delta.workload_history(workload_id, attack_path_id)
        transitions = self.delta.workload_transitions(workload_id)

        return {
            "workload_id": workload_id,
            "snapshot_count": len(history),
            "snapshots": [s.to_dict() for s in history],
            "transitions": [t.to_dict() for t in transitions],
            "graph_neighbors": self.graph.neighbors(workload_id),
        }

    def surface(self, min_weight: float = 0.8) -> dict:
        """High-signal transitions across all workloads."""
        transitions = self.delta.high_signal_transitions(min_weight=min_weight)
        return {
            "high_signal_transitions": [t.to_dict() for t in transitions[:50]],
            "total": len(transitions),
        }
