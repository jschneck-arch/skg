from __future__ import annotations
from enum import Enum
from typing import Iterable

# TriState comes through kernel.state which re-exports from skg.substrate.node
from .state import TriState


class ProjectionState(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    INDETERMINATE = "INDETERMINATE"


class ProjectionEngine:
    def evaluate(self, node_states: Iterable[TriState]) -> ProjectionState:
        values = list(node_states)
        if any(v == TriState.BLOCKED for v in values):
            return ProjectionState.FALSE
        if values and all(v == TriState.REALIZED for v in values):
            return ProjectionState.TRUE
        return ProjectionState.INDETERMINATE
