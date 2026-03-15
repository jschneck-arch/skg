"""
skg.kernel.state
================
StateEngine — collapses aggregated support into a tri-state verdict.

TriState is the canonical encoding defined in skg.substrate.node.
It is re-exported here so callers that import from skg.kernel get
the same object as callers that import from skg.substrate.

Fix: previously the kernel defined TriState("R"/"B"/"U") while the
substrate defined TriState("realized"/"blocked"/"unknown"). They compared
unequal across the layer boundary. There is now exactly one TriState.
"""
from __future__ import annotations
from dataclasses import dataclass

# Single canonical source — substrate owns the definition
from skg.substrate.node import TriState  # noqa: F401  (re-exported)

from .support import SupportContribution


@dataclass(slots=True)
class CollapseThresholds:
    realized: float = 1.0
    blocked: float = 1.0


class StateEngine:
    def __init__(self, thresholds: CollapseThresholds | None = None) -> None:
        self.thresholds = thresholds or CollapseThresholds()

    def collapse(self, support: SupportContribution) -> TriState:
        r = support.realized
        b = support.blocked
        if r > self.thresholds.realized and r > b:
            return TriState.REALIZED
        if b > self.thresholds.blocked and b >= r:
            return TriState.BLOCKED
        return TriState.UNKNOWN
