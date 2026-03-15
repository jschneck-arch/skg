from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Pearl:
    state_changes: List[Dict[str, Any]] = field(default_factory=list)
    projection_changes: List[Dict[str, Any]] = field(default_factory=list)
    reason_changes: List[Dict[str, Any]] = field(default_factory=list)
    observation_refs: List[str] = field(default_factory=list)
    energy_snapshot: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: str(uuid4()))


class PearlLedger:
    def __init__(self) -> None:
        self._pearls: List[Pearl] = []

    def record(self, pearl: Pearl) -> None:
        self._pearls.append(pearl)

    def all(self) -> List[Pearl]:
        return list(self._pearls)
