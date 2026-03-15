from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable
import math
from datetime import timezone

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
        # Use event_time (when evidence was collected), not observation_time (when ingested)
        obs_t = obs.event_time
        as_of_n = as_of
        if obs_t.tzinfo is not None and as_of_n.tzinfo is None:
            as_of_n = as_of_n.replace(tzinfo=timezone.utc)
        elif obs_t.tzinfo is None and as_of_n.tzinfo is not None:
            obs_t = obs_t.replace(tzinfo=timezone.utc)
        dt = max((as_of_n - obs_t).total_seconds(), 0.0)
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
