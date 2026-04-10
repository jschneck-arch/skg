from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from skg_core.substrate.node import NodeState, TriState
from skg_core.substrate.path import PathScore


@dataclass(slots=True)
class SKGState:
    """Canonical workload snapshot from measured and projected substrate state."""

    workload_id: str
    nodes: dict[str, NodeState] = field(default_factory=dict)
    paths: dict[str, PathScore] = field(default_factory=dict)
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def unknown_ids(self) -> list[str]:
        return [node_id for node_id, state in self.nodes.items() if state.state == TriState.UNKNOWN]

    @property
    def realized_ids(self) -> list[str]:
        return [node_id for node_id, state in self.nodes.items() if state.state == TriState.REALIZED]

    @property
    def blocked_ids(self) -> list[str]:
        return [node_id for node_id, state in self.nodes.items() if state.state == TriState.BLOCKED]

    @property
    def E(self) -> float:
        total = len(self.nodes)
        if total == 0:
            return 0.0
        return round(len(self.unknown_ids) / total, 6)

    @property
    def realized_paths(self) -> list[str]:
        return [path_id for path_id, score in self.paths.items() if score.classification == "realized"]

    @property
    def indeterminate_paths(self) -> list[str]:
        return [path_id for path_id, score in self.paths.items() if score.classification == "indeterminate"]

    @classmethod
    def build(
        cls,
        workload_id: str,
        nodes: dict[str, NodeState],
        paths: dict[str, PathScore] | None = None,
    ) -> "SKGState":
        return cls(workload_id=workload_id, nodes=nodes, paths=paths or {})

    @classmethod
    def empty(cls, workload_id: str) -> "SKGState":
        return cls(workload_id=workload_id)

    def as_dict(self) -> dict:
        return {
            "workload_id": self.workload_id,
            "computed_at": self.computed_at,
            "E": self.E,
            "n_nodes": len(self.nodes),
            "n_realized": len(self.realized_ids),
            "n_blocked": len(self.blocked_ids),
            "n_unknown": len(self.unknown_ids),
            "unknown_ids": list(self.unknown_ids),
            "realized_ids": list(self.realized_ids),
            "blocked_ids": list(self.blocked_ids),
            "n_paths": len(self.paths),
            "realized_paths": list(self.realized_paths),
            "indeterminate_paths": list(self.indeterminate_paths),
            "nodes": {node_id: state.as_dict() for node_id, state in self.nodes.items()},
            "paths": {path_id: score.as_dict() for path_id, score in self.paths.items()},
        }
