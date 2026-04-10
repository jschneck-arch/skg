"""Core kernel mechanics: observations, support aggregation, and state collapse."""

from skg_core.kernel.observations import Observation, ObservationStore
from skg_core.kernel.state import CollapseThresholds, StateEngine
from skg_core.kernel.support import SupportContribution, SupportEngine

__all__ = [
    "CollapseThresholds",
    "Observation",
    "ObservationStore",
    "StateEngine",
    "SupportContribution",
    "SupportEngine",
]
