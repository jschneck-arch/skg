"""
skg.substrate.node
==================
Node — the atomic unit of the information field.

A Node is a measurable precondition in a domain.
In security: a wicket (HO-03, CE-01, AD-08).
In supply chain: a package vulnerability (CVE-2024-XXXX in lodash@4.17.20).
In genomics: a variant effect (BRCA1:c.5266dupC → loss of function).

The domain skin subclasses Node and adds domain-specific fields.
The substrate only cares about the canonical epistemic state of a node.

Backward-compatibility note:
This module preserves the original scalar-facing contract:
- id
- tri-state
- confidence
- observed_at

But it now carries richer substrate structure so the system can evolve
toward field / tensor-aware reasoning without breaking current callers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


DEFAULT_DIMENSIONS = 8


def _zero_vector(n: int = DEFAULT_DIMENSIONS) -> list[float]:
    return [0.0] * n


def _identity_matrix(n: int = DEFAULT_DIMENSIONS, scale: float = 0.0) -> list[list[float]]:
    m = [[0.0 for _ in range(n)] for _ in range(n)]
    if scale != 0.0:
        for i in range(n):
            m[i][i] = scale
    return m


def _zero_matrix(n: int = DEFAULT_DIMENSIONS) -> list[list[float]]:
    return _identity_matrix(n=n, scale=0.0)


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
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass
class NodeState:
    """
    The observed state of a Node at a point in time.
    Produced by sensors, consumed by the projection engine.

    Original scalar contract retained:
    - node_id
    - state
    - confidence
    - observed_at
    - source_kind
    - pointer
    - notes
    - attributes

    Extended substrate fields added for future field-aware engines:
    - confidence_vector
    - confidence_matrix
    - mass_matrix
    - damping_matrix
    - contradiction_vector
    - local_energy
    - phase
    - latent/projection metadata
    """
    node_id: str
    state: TriState
    confidence: float          # scalar compatibility layer
    observed_at: str           # ISO timestamp
    source_kind: str = ""      # sensor type that produced this
    pointer: str = ""          # URI to evidence
    notes: str = ""            # human-readable detail
    attributes: dict = field(default_factory=dict)

    # ---- reduced field-capable extensions ----
    dimension_count: int = DEFAULT_DIMENSIONS

    # confidence structure
    confidence_vector: list[float] = field(default_factory=_zero_vector)
    confidence_matrix: list[list[float]] = field(default_factory=_zero_matrix)

    # resistance / dynamics
    mass_matrix: list[list[float]] = field(default_factory=_zero_matrix)
    damping_matrix: list[list[float]] = field(default_factory=_zero_matrix)

    # contradiction / field state
    contradiction_vector: list[float] = field(default_factory=_zero_vector)
    local_energy: float = 0.0
    phase: float = 0.0

    # latent / projection provenance
    is_latent: bool = False
    projection_sources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ensure_dimensions()
        self.confidence = self._clamp01(self.confidence)
        if not self.observed_at:
            self.observed_at = datetime.now(timezone.utc).isoformat()

        # If richer fields are empty / zeroed, seed them from scalar confidence.
        if self._is_zero_vector(self.confidence_vector):
            self.confidence_vector = [self.confidence] * self.dimension_count

        if self._is_zero_matrix(self.confidence_matrix):
            self.confidence_matrix = self._diag_from_vector(self.confidence_vector)

    @classmethod
    def unknown(cls, node_id: str) -> "NodeState":
        """Default state when no observation exists."""
        return cls(
            node_id=node_id,
            state=TriState.UNKNOWN,
            confidence=0.0,
            observed_at=datetime.now(timezone.utc).isoformat(),
            notes="No observation recorded.",
            attributes={"unresolved_reason": "unmeasured"},
        )

    @staticmethod
    def _clamp01(value: float) -> float:
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return float(value)

    @staticmethod
    def _is_zero_vector(v: list[float]) -> bool:
        return all(float(x) == 0.0 for x in v)

    @staticmethod
    def _is_zero_matrix(m: list[list[float]]) -> bool:
        return all(float(x) == 0.0 for row in m for x in row)

    def _diag_from_vector(self, v: list[float]) -> list[list[float]]:
        n = len(v)
        m = [[0.0 for _ in range(n)] for _ in range(n)]
        for i, value in enumerate(v):
            m[i][i] = self._clamp01(value)
        return m

    def ensure_dimensions(self) -> None:
        """
        Normalize vector/matrix fields to dimension_count.

        Safe to call from migration code, loaders, and adapters.
        """
        n = int(self.dimension_count) if self.dimension_count > 0 else DEFAULT_DIMENSIONS
        self.dimension_count = n

        def norm_vector(v: list[float]) -> list[float]:
            v = list(v[:n]) + [0.0] * max(0, n - len(v))
            return [self._clamp01(x) for x in v]

        def norm_matrix(m: list[list[float]]) -> list[list[float]]:
            rows = []
            base = list(m[:n]) + ([[]] * max(0, n - len(m)))
            for row in base[:n]:
                row = list(row[:n]) + [0.0] * max(0, n - len(row))
                rows.append([float(x) for x in row])
            return rows

        self.confidence_vector = norm_vector(self.confidence_vector)
        self.contradiction_vector = norm_vector(self.contradiction_vector)
        self.confidence_matrix = norm_matrix(self.confidence_matrix)
        self.mass_matrix = norm_matrix(self.mass_matrix)
        self.damping_matrix = norm_matrix(self.damping_matrix)

    def scalar_confidence_from_vector(self) -> float:
        """
        Back-calculate a scalar confidence view from the confidence vector.
        """
        if not self.confidence_vector:
            return self.confidence
        return round(sum(self.confidence_vector) / len(self.confidence_vector), 6)

    def sync_scalar_confidence(self) -> None:
        """
        Update the legacy scalar confidence field from the richer vector state.
        """
        self.confidence = self.scalar_confidence_from_vector()

    def set_confidence_vector(self, values: list[float], sync_scalar: bool = True) -> None:
        """
        Convenience setter for future engines.
        """
        self.confidence_vector = list(values)
        self.ensure_dimensions()
        self.confidence_matrix = self._diag_from_vector(self.confidence_vector)
        if sync_scalar:
            self.sync_scalar_confidence()

    def as_dict(self) -> dict:
        """
        Serializable view of the node state.
        Keeps the original fields while exposing the richer substrate.
        """
        return {
            "node_id": self.node_id,
            "state": self.state.value if isinstance(self.state, TriState) else str(self.state),
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "source_kind": self.source_kind,
            "pointer": self.pointer,
            "notes": self.notes,
            "attributes": self.attributes,
            "dimension_count": self.dimension_count,
            "confidence_vector": self.confidence_vector,
            "confidence_matrix": self.confidence_matrix,
            "mass_matrix": self.mass_matrix,
            "damping_matrix": self.damping_matrix,
            "contradiction_vector": self.contradiction_vector,
            "local_energy": self.local_energy,
            "phase": self.phase,
            "is_latent": self.is_latent,
            "projection_sources": self.projection_sources,
        }


@dataclass
class Node:
    """
    A measurable precondition in a domain manifold.

    The substrate defines the contract. The domain skin adds meaning.
    """
    node_id: str            # unique identifier within domain
    label: str              # human-readable name
    description: str = ""   # what this node measures
    domain: str = ""        # which domain skin owns this node
    tags: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "description": self.description,
            "domain": self.domain,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class ViewNode:
    """
    Fresh present-tense view of a workload-local node context.

    `measured_now` is only what the current observer/projector collapsed.
    `memory_overlay` is advisory history from the pearl ledger.
    """
    identity_key: str
    manifestation_key: str
    domain: str
    attack_path_id: str
    classification: str
    score: float
    realized: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    computed_at: str = ""
    memory_overlay: dict = field(default_factory=dict)
    observed_tools: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "identity_key": self.identity_key,
            "manifestation_key": self.manifestation_key,
            "domain": self.domain,
            "attack_path_id": self.attack_path_id,
            "classification": self.classification,
            "score": self.score,
            "realized": list(self.realized),
            "blocked": list(self.blocked),
            "unknown": list(self.unknown),
            "computed_at": self.computed_at,
            "fresh_view": True,
            "measured_now": {
                "classification": self.classification,
                "realized": list(self.realized),
                "blocked": list(self.blocked),
                "unknown": list(self.unknown),
                "computed_at": self.computed_at,
                "observed_tools": dict(self.observed_tools or {}),
            },
            "memory_overlay": dict(self.memory_overlay or {}),
            "observed_tools": dict(self.observed_tools or {}),
        }
