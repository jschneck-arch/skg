"""
skg.substrate.path
==================
Path — an ordered sequence of Node preconditions.

A Path defines what must be true for a traversal to be possible.
In security: an attack path (host_ssh_initial_access_v1).
In supply chain: a compromise chain (upstream_package → transitive_dep → target).
In genomics: a disease pathway (variant → protein → phenotype).

PathScore is the output of the projection engine π applied to a Path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Path:
    """
    A sequence of required Node preconditions.
    All required nodes must be REALIZED for the path to be traversable.
    """
    path_id:          str
    required_nodes:   list[str]     # node_ids that must be realized
    domain:           str = ""
    description:      str = ""
    metadata:         dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "path_id":        self.path_id,
            "required_nodes": self.required_nodes,
            "domain":         self.domain,
            "description":    self.description,
        }


@dataclass
class PathScore:
    """
    Output of π applied to a Path given a set of NodeStates.

    score = |realized| / |required|
    E     = H(projection | telemetry) — residual uncertainty
    """
    path_id:        str
    score:          float           # [0, 1]
    classification: str             # realized / not_realized / indeterminate
    realized:       list[str]       # node_ids confirmed realized
    blocked:        list[str]       # node_ids confirmed blocked
    unknown:        list[str]       # node_ids with no sufficient evidence
    latest_status:  dict[str, str]  # node_id → tri-state
    unresolved_detail: dict[str, dict] = field(default_factory=dict)
    workload_id:    str = ""
    run_id:         str = ""
    computed_at:    str = ""

    @property
    def entropy(self) -> float:
        """
        E = H(projection | telemetry)
        Residual uncertainty: fraction of required nodes still unknown.
        E=0 means full knowledge. E=1 means no knowledge.
        """
        n = len(self.latest_status)
        if n == 0:
            return 1.0
        return round(len(self.unknown) / n, 6)

    def as_dict(self) -> dict:
        return {
            "path_id":        self.path_id,
            "score":          round(self.score, 6),
            "classification": self.classification,
            "realized":       self.realized,
            "blocked":        self.blocked,
            "unknown":        self.unknown,
            "latest_status":  self.latest_status,
            "unresolved_detail": self.unresolved_detail,
            "entropy":        self.entropy,
            "workload_id":    self.workload_id,
            "run_id":         self.run_id,
            "computed_at":    self.computed_at,
        }
