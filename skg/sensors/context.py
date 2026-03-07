"""
skg.sensors.context
===================
SensorContext — shared state injected into all sensors at runtime.

Provides sensors with:
  - WorkloadGraph priors (graph-adjusted confidence)
  - ObservationMemory calibration (history-adjusted confidence)
  - FeedbackIngester.record_observation() (close the loop)

Without context (standalone mode), sensors use base confidence only.
With context (daemon mode), all three systems inform the confidence field
on every envelope event emitted.

Usage in a sensor:
    def _adjusted_confidence(
        self,
        base: float,
        evidence_text: str,
        wicket_id: str,
        domain: str,
        workload_id: str,
    ) -> float:
        if self._ctx is None:
            return base
        return self._ctx.calibrate(
            base, evidence_text, wicket_id, domain, workload_id
        )

    def _record(self, evidence_text, wicket_id, domain, source_kind,
                 rank, realized, confidence, workload_id):
        if self._ctx:
            self._ctx.record(
                evidence_text, wicket_id, domain, source_kind,
                rank, realized, confidence, workload_id
            )

The SensorContext is set on every sensor by SensorLoop after the
systems boot in SKGKernel.boot().
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skg.graph import WorkloadGraph
    from skg.resonance.observation_memory import ObservationMemory

log = logging.getLogger("skg.sensors.context")

# Blending weights — sensor evidence dominates, history/graph inform
HISTORY_WEIGHT = 0.35   # observation memory contribution
GRAPH_WEIGHT   = 0.20   # workload graph prior contribution
BASE_WEIGHT    = 0.45   # direct sensor evidence weight
# Sum = 1.0; if either system has no data, its weight redistributes to base


class SensorContext:
    """
    Shared intelligence context injected into sensors at daemon boot.
    Provides calibrated confidence by blending three signals:
      1. Sensor's direct evidence (base_confidence)
      2. Historical confirmation rate (ObservationMemory)
      3. Cross-workload prior (WorkloadGraph)
    """

    def __init__(
        self,
        graph: "WorkloadGraph",
        obs_memory: "ObservationMemory | None",
    ):
        self.graph = graph
        self.obs   = obs_memory

    def calibrate(
        self,
        base_confidence: float,
        evidence_text: str,
        wicket_id: str,
        domain: str,
        workload_id: str,
        k: int = 8,
    ) -> float:
        """
        Blend base_confidence with history and graph priors.
        Returns adjusted confidence in [0.0, 1.0].
        """
        history_rate = None
        graph_prior  = 0.0

        # Observation memory: historical confirmation rate
        if self.obs is not None:
            try:
                history_rate = self.obs.historical_confirmation_rate(
                    evidence_text, wicket_id, domain, k=k
                )
            except Exception as exc:
                log.debug(f"ObsMemory calibrate failed: {exc}")

        # WorkloadGraph: prior for this workload+wicket
        try:
            graph_prior = self.graph.get_prior(workload_id, wicket_id)
        except Exception as exc:
            log.debug(f"Graph prior failed: {exc}")

        # Blend
        if history_rate is None and graph_prior == 0.0:
            return base_confidence  # no adjustment — return as-is

        hw = HISTORY_WEIGHT if history_rate is not None else 0.0
        gw = GRAPH_WEIGHT   if graph_prior > 0.0 else 0.0
        bw = 1.0 - hw - gw

        result = (base_confidence * bw)
        if history_rate is not None:
            result += history_rate * hw
        result += graph_prior * gw

        adjusted = round(min(1.0, max(0.0, result)), 4)

        if adjusted != base_confidence:
            log.debug(
                f"[ctx] {workload_id}/{wicket_id}: "
                f"base={base_confidence:.3f} hist={history_rate} "
                f"prior={graph_prior:.3f} → {adjusted:.3f}"
            )

        return adjusted

    def record(
        self,
        evidence_text: str,
        wicket_id: str,
        domain: str,
        source_kind: str,
        evidence_rank: int,
        sensor_realized: bool | None,
        confidence: float,
        workload_id: str,
        ts: str | None = None,
    ) -> str | None:
        """
        Record a pending observation in ObservationMemory.
        Returns record_id (for future outcome matching) or None.
        """
        if self.obs is None:
            return None
        try:
            return self.obs.record_observation(
                evidence_text=evidence_text,
                wicket_id=wicket_id,
                domain=domain,
                source_kind=source_kind,
                evidence_rank=evidence_rank,
                sensor_realized=sensor_realized,
                confidence_at_emit=confidence,
                workload_id=workload_id,
                ts=ts,
            )
        except Exception as exc:
            log.debug(f"ObsMemory record failed: {exc}")
            return None
