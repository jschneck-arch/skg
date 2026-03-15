"""
skg.substrate.state
===================
SKGState — unified field snapshot for a workload at a point in time.

This wraps NodeState + PathScore into a single coherent object so that
the gravity planner, feedback ingester, and API layer all operate on
the same canonical state representation rather than separate dicts.

Usage:
    from skg.substrate.state import SKGState
    from skg.substrate.projection import project_path, load_states_from_events

    nodes  = load_states_from_events(events)
    scores = {path.path_id: project_path(path, nodes) for path in paths}
    state  = SKGState.build(workload_id, nodes, scores)

    print(state.E)           # field energy (Work 3 Section 4.2)
    print(state.unknown_ids) # unresolved node ids
    state.as_dict()          # serializable snapshot
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from skg.substrate.node import NodeState, TriState
from skg.substrate.path import PathScore


@dataclass
class SKGState:
    """
    Canonical unified state snapshot for a workload.

    nodes   — latest NodeState per node_id
    paths   — latest PathScore per path_id
    E       — field energy: |unknown| / |total nodes|  (Work 3 Section 4.2)
    """
    workload_id:  str
    nodes:        dict[str, NodeState]   = field(default_factory=dict)
    paths:        dict[str, PathScore]   = field(default_factory=dict)
    computed_at:  str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ── Derived observables ───────────────────────────────────────────────

    @property
    def unknown_ids(self) -> list[str]:
        return [nid for nid, ns in self.nodes.items()
                if ns.state == TriState.UNKNOWN]

    @property
    def realized_ids(self) -> list[str]:
        return [nid for nid, ns in self.nodes.items()
                if ns.state == TriState.REALIZED]

    @property
    def blocked_ids(self) -> list[str]:
        return [nid for nid, ns in self.nodes.items()
                if ns.state == TriState.BLOCKED]

    @property
    def E(self) -> float:
        """
        Field energy E = |unknown| / |total nodes|.  (Work 3 Section 4.2)
        E = 0.0 → fully determined.
        E = 1.0 → fully unknown (maximum gravitational pull).
        """
        n = len(self.nodes)
        if n == 0:
            return 0.0
        return round(len(self.unknown_ids) / n, 6)

    @property
    def realized_paths(self) -> list[str]:
        return [pid for pid, ps in self.paths.items()
                if ps.classification == "realized"]

    @property
    def indeterminate_paths(self) -> list[str]:
        return [pid for pid, ps in self.paths.items()
                if ps.classification == "indeterminate"]

    # ── Construction ─────────────────────────────────────────────────────

    @classmethod
    def build(
        cls,
        workload_id: str,
        nodes: dict[str, NodeState],
        paths: Optional[dict[str, PathScore]] = None,
    ) -> "SKGState":
        """Build a SKGState from already-computed nodes and path scores."""
        return cls(
            workload_id=workload_id,
            nodes=nodes,
            paths=paths or {},
        )

    @classmethod
    def empty(cls, workload_id: str) -> "SKGState":
        """Empty state — no observations recorded yet."""
        return cls(workload_id=workload_id)

    # ── Serialization ─────────────────────────────────────────────────────

    def as_dict(self) -> dict:
        return {
            "workload_id":       self.workload_id,
            "computed_at":       self.computed_at,
            "E":                 self.E,
            "n_nodes":           len(self.nodes),
            "n_realized":        len(self.realized_ids),
            "n_blocked":         len(self.blocked_ids),
            "n_unknown":         len(self.unknown_ids),
            "unknown_ids":       self.unknown_ids,
            "realized_ids":      self.realized_ids,
            "blocked_ids":       self.blocked_ids,
            "n_paths":           len(self.paths),
            "realized_paths":    self.realized_paths,
            "indeterminate_paths": self.indeterminate_paths,
            "nodes":             {nid: ns.as_dict() for nid, ns in self.nodes.items()},
            "paths":             {pid: ps.as_dict() for pid, ps in self.paths.items()},
        }
