from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable
import math

from .observations import Observation


DECAY_LAMBDAS = {
    "structural": 0.001,
    "operational": 0.01,
    "ephemeral": 0.1,
}


@dataclass(slots=True)
class SupportContribution:
    realized: float = 0.0
    blocked: float = 0.0


class SupportEngine:
    def __init__(self, now_fn=None) -> None:
        self.now_fn = now_fn or datetime.utcnow

    def weight(self, obs: Observation, as_of: datetime) -> float:
        dt = max((as_of - obs.observation_time.replace(tzinfo=None)).total_seconds(), 0.0)
        decay = DECAY_LAMBDAS.get(obs.decay_class, DECAY_LAMBDAS["operational"])
        return math.exp(-decay * dt / 3600.0)

    def aggregate(self, observations: Iterable[Observation], target: str, context: str, as_of: datetime) -> SupportContribution:
        realized = 0.0
        blocked = 0.0
        for obs in observations:
            if obs.context != context or target not in obs.targets:
                continue
            mapping = obs.support_mapping.get(target, {})
            w = self.weight(obs, as_of)
            realized += w * float(mapping.get("R", 0.0))
            blocked += w * float(mapping.get("B", 0.0))
        return SupportContribution(realized=realized, blocked=blocked)
