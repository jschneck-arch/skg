"""
skg.sensors.context
===================
SensorContext — shared state injected into all sensors at runtime.

Provides sensors with:
  - WorkloadGraph priors (graph-adjusted confidence)
  - ObservationMemory calibration (history-adjusted confidence)
  - ObservationMemory.record_observation() (close the loop)

Without context (standalone mode), sensors use base confidence only.
With context (daemon mode), these systems inform the confidence field
on every envelope event emitted.

Conceptual note:
A wicket_id here is treated as a domain-specific condition identifier.
This module is backward-compatible with wicket_id while also supporting
node_id as a canonical alias.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from skg.sensors.confidence_calibrator import CALIBRATION_PATH, load_calibration

if TYPE_CHECKING:
    from skg.graph import WorkloadGraph
    from skg.resonance.observation_memory import ObservationMemory

log = logging.getLogger("skg.sensors.context")

# Blending weights — sensor evidence dominates, history/graph inform
HISTORY_WEIGHT = 0.35
GRAPH_WEIGHT   = 0.20
BASE_WEIGHT    = 0.45
# Sum = 1.0; if either system has no data, its weight redistributes to base


def _safe_condition_id(wicket_id: str | None = None, node_id: str | None = None) -> str:
    return node_id or wicket_id or ""


class SensorContext:
    """
    Shared intelligence context injected into sensors at daemon boot.

    Provides calibrated confidence by blending:
      1. sensor direct evidence
      2. historical confirmation rate
      3. cross-workload prior
    """

    def __init__(
        self,
        graph: "WorkloadGraph",
        obs_memory: "ObservationMemory | None",
    ):
        self.graph = graph
        self.obs = obs_memory
        self._calibration = None
        self._calibration_mtime = 0.0
        self._refresh_calibration(force=True)

    def _refresh_calibration(self, force: bool = False) -> None:
        try:
            current_mtime = CALIBRATION_PATH.stat().st_mtime if CALIBRATION_PATH.exists() else 0.0
        except OSError:
            current_mtime = 0.0
        if not force and current_mtime == self._calibration_mtime:
            return
        self._calibration = load_calibration(CALIBRATION_PATH)
        self._calibration_mtime = current_mtime

    def calibrate(
        self,
        base_confidence: float,
        evidence_text: str,
        wicket_id: str | None = None,
        domain: str = "",
        workload_id: str = "",
        k: int = 8,
        node_id: str | None = None,
        source_id: str = "",
    ) -> float:
        """
        Blend base_confidence with history and graph priors.
        Returns adjusted confidence in [0.0, 1.0].

        Backward compatible with wicket_id while supporting node_id.
        """
        condition_id = _safe_condition_id(wicket_id=wicket_id, node_id=node_id)
        self._refresh_calibration()

        sensor_confidence = base_confidence
        if self._calibration is not None and source_id:
            try:
                sensor_confidence = self._calibration.apply(source_id, base_confidence)
            except Exception as exc:
                log.debug(f"Calibration apply failed: {exc}")

        history_rate = None
        graph_prior = 0.0

        # Observation memory: historical confirmation rate
        if self.obs is not None:
            try:
                history_rate = self.obs.historical_confirmation_rate(
                    evidence_text=evidence_text,
                    wicket_id=condition_id,
                    domain=domain,
                    workload_id=workload_id,
                    k=k,
                )
            except Exception as exc:
                log.debug(f"ObsMemory calibrate failed: {exc}")

        # WorkloadGraph: prior for this workload+condition
        try:
            graph_prior = self.graph.get_prior(workload_id, wicket_id=condition_id)
        except Exception as exc:
            log.debug(f"Graph prior failed: {exc}")

        # Blend
        if history_rate is None and graph_prior == 0.0:
            return sensor_confidence

        hw = HISTORY_WEIGHT if history_rate is not None else 0.0
        gw = GRAPH_WEIGHT if graph_prior > 0.0 else 0.0
        bw = 1.0 - hw - gw

        result = (sensor_confidence * bw)
        if history_rate is not None:
            result += history_rate * hw
        result += graph_prior * gw

        adjusted = round(min(1.0, max(0.0, result)), 4)

        if adjusted != sensor_confidence:
            log.debug(
                f"[ctx] {workload_id}/{condition_id}: "
                f"base={base_confidence:.3f} sensor={sensor_confidence:.3f} hist={history_rate} "
                f"prior={graph_prior:.3f} → {adjusted:.3f}"
            )

        return adjusted

    def record(
        self,
        evidence_text: str,
        wicket_id: str | None = None,
        domain: str = "",
        source_kind: str = "",
        evidence_rank: int = 3,
        sensor_realized: bool | None = None,
        confidence: float = 0.0,
        workload_id: str = "",
        ts: str | None = None,
        node_id: str | None = None,
        local_energy_at_emit: float = 0.0,
        phase_at_emit: float = 0.0,
        is_latent_at_emit: bool = False,
    ) -> str | None:
        """
        Record a pending observation in ObservationMemory.
        Returns record_id (for future outcome matching) or None.

        Backward compatible with wicket_id while supporting node_id and
        optional richer substrate-side observation metadata.
        """
        if self.obs is None:
            return None

        condition_id = _safe_condition_id(wicket_id=wicket_id, node_id=node_id)

        try:
            return self.obs.record_observation(
                evidence_text=evidence_text,
                wicket_id=condition_id,
                domain=domain,
                source_kind=source_kind,
                evidence_rank=evidence_rank,
                sensor_realized=sensor_realized,
                confidence_at_emit=confidence,
                workload_id=workload_id,
                ts=ts,
                local_energy_at_emit=local_energy_at_emit,
                phase_at_emit=phase_at_emit,
                is_latent_at_emit=is_latent_at_emit,
            )
        except Exception as exc:
            log.debug(f"ObsMemory record failed: {exc}")
            return None
