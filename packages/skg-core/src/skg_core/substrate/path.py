from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Path:
    """Ordered condition list required for traversability."""

    path_id: str
    required_nodes: list[str]
    domain: str = ""
    description: str = ""
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "required_nodes": list(self.required_nodes),
            "domain": self.domain,
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PathScore:
    """Projected state for a path against latest known node states."""

    path_id: str
    score: float
    classification: str
    realized: list[str]
    blocked: list[str]
    unknown: list[str]
    latest_status: dict[str, str]
    unresolved_detail: dict[str, dict] = field(default_factory=dict)
    workload_id: str = ""
    run_id: str = ""
    computed_at: str = ""

    @property
    def entropy(self) -> float:
        count = len(self.latest_status)
        if count == 0:
            return 1.0
        return round(len(self.unknown) / count, 6)

    def as_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "score": round(self.score, 6),
            "classification": self.classification,
            "realized": list(self.realized),
            "blocked": list(self.blocked),
            "unknown": list(self.unknown),
            "latest_status": dict(self.latest_status),
            "unresolved_detail": dict(self.unresolved_detail),
            "entropy": self.entropy,
            "workload_id": self.workload_id,
            "run_id": self.run_id,
            "computed_at": self.computed_at,
        }
