from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence


@dataclass(slots=True)
class ProjectorHealth:
    status: str
    details: dict[str, Any] = field(default_factory=dict)


class ProjectorContract(Protocol):
    """Universal projector contract; domain bundles provide implementations."""

    projector_name: str

    def project(
        self,
        events: Sequence[Mapping[str, Any]],
        context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        ...

    def health(self) -> ProjectorHealth:
        ...
