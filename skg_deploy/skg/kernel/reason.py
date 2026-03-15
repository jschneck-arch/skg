from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


@dataclass(slots=True)
class ReasonTrace:
    supporting_observations: List[str] = field(default_factory=list)
    blocking_observations: List[str] = field(default_factory=list)
    unresolved_dependencies: List[str] = field(default_factory=list)
    active_constraints: List[str] = field(default_factory=list)

    def materially_different(self, other: "ReasonTrace") -> bool:
        return (
            self.supporting_observations != other.supporting_observations
            or self.blocking_observations != other.blocking_observations
            or self.unresolved_dependencies != other.unresolved_dependencies
            or self.active_constraints != other.active_constraints
        )
