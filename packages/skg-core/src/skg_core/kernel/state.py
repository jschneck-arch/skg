from __future__ import annotations

from dataclasses import dataclass

from skg_core.kernel.support import SupportContribution
from skg_core.substrate.node import TriState


@dataclass(slots=True)
class CollapseThresholds:
    realized: float = 1.0
    blocked: float = 1.0


class StateEngine:
    """Collapse aggregated support into canonical TriState verdicts."""

    def __init__(self, thresholds: CollapseThresholds | None = None) -> None:
        self.thresholds = thresholds or CollapseThresholds()

    def collapse(self, support: SupportContribution) -> TriState:
        if support.realized > self.thresholds.realized and support.realized > support.blocked:
            return TriState.REALIZED
        if support.blocked > self.thresholds.blocked and support.blocked >= support.realized:
            return TriState.BLOCKED
        return TriState.UNKNOWN
