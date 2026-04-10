from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence


@dataclass(slots=True)
class AdapterHealth:
    status: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AdapterCheckpoint:
    token: str
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)


class AdapterContract(Protocol):
    """Universal adapter contract; domain bundles provide implementations."""

    adapter_name: str

    def collect(self, context: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        ...

    def map_events(self, raw_records: Sequence[Mapping[str, Any]]) -> Sequence[Mapping[str, Any]]:
        ...

    def health(self) -> AdapterHealth:
        ...

    def checkpoint(self) -> AdapterCheckpoint | None:
        ...
