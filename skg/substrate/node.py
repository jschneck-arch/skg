"""
skg.substrate.node
==================
Node — the atomic unit of the information field.

A Node is a measurable precondition in a domain.
In security: a wicket (HO-03, CE-01, AD-08).
In supply chain: a package vulnerability (CVE-2024-XXXX in lodash@4.17.20).
In genomics: a variant effect (BRCA1:c.5266dupC → loss of function).

The domain skin subclasses Node and adds domain-specific fields.
The substrate only cares about: id, tri-state, confidence, observed_at.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class TriState(str, Enum):
    """
    The three honest answers to an observational question.

    REALIZED: evidence confirms the condition holds.
    BLOCKED:  evidence confirms the condition cannot hold.
    UNKNOWN:  evidence is insufficient to determine either.

    UNKNOWN is a first-class answer, not a failure state.
    The system refuses to assert what it hasn't measured.
    """
    REALIZED = "realized"
    BLOCKED  = "blocked"
    UNKNOWN  = "unknown"


@dataclass
class NodeState:
    """
    The observed state of a Node at a point in time.
    Produced by sensors, consumed by the projection engine.
    """
    node_id:     str
    state:       TriState
    confidence:  float          # [0, 1] — certainty of the observation
    observed_at: str            # ISO timestamp
    source_kind: str = ""       # sensor type that produced this
    pointer:     str = ""       # URI to evidence
    notes:       str = ""       # human-readable detail
    attributes:  dict = field(default_factory=dict)

    @classmethod
    def unknown(cls, node_id: str) -> "NodeState":
        """Default state when no observation exists."""
        return cls(
            node_id=node_id,
            state=TriState.UNKNOWN,
            confidence=0.0,
            observed_at=datetime.now(timezone.utc).isoformat(),
            notes="No observation recorded.",
        )


@dataclass
class Node:
    """
    A measurable precondition in a domain manifold.

    The substrate defines the contract. The domain skin adds meaning.
    """
    node_id:     str            # unique identifier within domain
    label:       str            # human-readable name
    description: str = ""      # what this node measures
    domain:      str = ""      # which domain skin owns this node
    tags:        list = field(default_factory=list)
    metadata:    dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "node_id":     self.node_id,
            "label":       self.label,
            "description": self.description,
            "domain":      self.domain,
            "tags":        self.tags,
            "metadata":    self.metadata,
        }
