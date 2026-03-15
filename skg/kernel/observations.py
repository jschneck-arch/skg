from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class Observation:
    instrument: str
    targets: List[str]
    context: str
    payload: Dict[str, Any]
    event_time: datetime
    observation_time: datetime = field(default_factory=utcnow)
    decay_class: str = "operational"
    artifact_refs: List[str] = field(default_factory=list)
    support_mapping: Dict[str, Dict[str, float]] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))


class ObservationStore:
    def __init__(self) -> None:
        self._observations: List[Observation] = []

    def add(self, obs: Observation) -> None:
        self._observations.append(obs)

    def all(self) -> List[Observation]:
        return list(self._observations)

    def by_target(self, target: str, context: Optional[str] = None) -> List[Observation]:
        result = [o for o in self._observations if target in o.targets]
        if context is not None:
            result = [o for o in result if o.context == context]
        return result
