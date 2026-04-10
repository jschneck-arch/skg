from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class Observation:
    instrument: str
    targets: list[str]
    context: str
    payload: dict[str, Any]
    event_time: datetime
    observation_time: datetime = field(default_factory=utcnow)
    decay_class: str = "operational"
    artifact_refs: list[str] = field(default_factory=list)
    support_mapping: dict[str, dict[str, float]] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    cycle_id: str = ""


class ObservationStore:
    def __init__(self) -> None:
        self._observations: list[Observation] = []

    def add(self, obs: Observation) -> None:
        self._observations.append(obs)

    def all(self) -> list[Observation]:
        return list(self._observations)

    def by_target(self, target: str, context: str | None = None) -> list[Observation]:
        result = [obs for obs in self._observations if target in obs.targets]
        if context is not None:
            result = [obs for obs in result if obs.context == context]
        return result
