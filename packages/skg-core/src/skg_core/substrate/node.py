from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class TriState(str, Enum):
    """Canonical observational tri-state."""

    REALIZED = "realized"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class NodeState:
    """State of a single atomic condition."""

    node_id: str
    state: TriState
    confidence: float
    observed_at: str
    source_kind: str = ""
    pointer: str = ""
    notes: str = ""
    attributes: dict = field(default_factory=dict)
    local_energy: float = 0.0
    phase: float = 0.0
    is_latent: bool = False
    projection_sources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.observed_at:
            self.observed_at = datetime.now(timezone.utc).isoformat()

    @classmethod
    def unknown(cls, node_id: str) -> "NodeState":
        return cls(
            node_id=node_id,
            state=TriState.UNKNOWN,
            confidence=0.0,
            observed_at=datetime.now(timezone.utc).isoformat(),
            notes="No observation recorded.",
            attributes={"unresolved_reason": "unmeasured"},
        )

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "state": self.state.value,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "source_kind": self.source_kind,
            "pointer": self.pointer,
            "notes": self.notes,
            "attributes": dict(self.attributes),
            "local_energy": self.local_energy,
            "phase": self.phase,
            "is_latent": self.is_latent,
            "projection_sources": list(self.projection_sources),
        }


@dataclass(slots=True)
class Node:
    """Canonical declaration of a measurable condition."""

    node_id: str
    label: str
    description: str = ""
    domain: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "description": self.description,
            "domain": self.domain,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }
