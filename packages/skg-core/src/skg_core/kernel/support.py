from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Mapping

from skg_core.kernel.observations import Observation


DECAY_LAMBDAS = {
    "structural": 0.001,
    "operational": 0.01,
    "ephemeral": 0.1,
}

DEFAULT_TTL_HOURS: dict[str, float | None] = {
    "structural": 24.0 * 30.0,
    "operational": 24.0 * 7.0,
    "ephemeral": 24.0,
}

INSTRUMENT_FAMILIES = {
    "nmap": "network_scan",
    "pcap": "packet_capture",
    "net_sensor": "packet_capture",
    "tshark": "packet_capture",
    "ssh_sensor": "host_access",
    "sysaudit": "host_runtime",
    "container_inspect": "container_runtime",
    "http_collector": "web_active",
    "auth_scanner": "web_active",
    "bloodhound": "graph_identity",
    "supply_chain": "package_structure",
    "nvd_feed": "vuln_intel",
    "msf_sensor": "exploit_runtime",
}


@dataclass(slots=True)
class SupportContribution:
    realized: float = 0.0
    blocked: float = 0.0
    unresolved: float = 0.0
    contradiction: float = 0.0
    decoherence: float = 0.0
    compatibility_score: float = 0.0
    compatibility_span: int = 0


def instrument_family(instrument: str) -> str:
    return INSTRUMENT_FAMILIES.get(instrument, instrument or "unknown")


class SupportEngine:
    """Aggregate observations into support values without runtime coupling."""

    def __init__(
        self,
        ttl_hours: Mapping[str, float | None] | None = None,
        now_fn=None,
    ) -> None:
        self.now_fn = now_fn or datetime.utcnow
        self._ttl_hours = dict(DEFAULT_TTL_HOURS)
        if ttl_hours:
            self._ttl_hours.update(ttl_hours)

    def ttl_for(self, obs: Observation) -> timedelta | None:
        hours = self._ttl_hours.get(obs.decay_class)
        if hours is None:
            return None
        try:
            hours_f = float(hours)
        except Exception:
            return None
        if hours_f <= 0.0:
            return timedelta(seconds=0)
        return timedelta(hours=hours_f)

    def is_expired(self, obs: Observation, as_of: datetime) -> bool:
        ttl = self.ttl_for(obs)
        if ttl is None:
            return False

        obs_time = obs.event_time
        as_of_time = as_of

        if obs_time.tzinfo is not None and as_of_time.tzinfo is None:
            as_of_time = as_of_time.replace(tzinfo=timezone.utc)
        elif obs_time.tzinfo is None and as_of_time.tzinfo is not None:
            obs_time = obs_time.replace(tzinfo=timezone.utc)

        return (as_of_time - obs_time) > ttl

    def weight(self, obs: Observation, as_of: datetime) -> float:
        if self.is_expired(obs, as_of):
            return 0.0

        obs_time = obs.event_time
        as_of_time = as_of

        if obs_time.tzinfo is not None and as_of_time.tzinfo is None:
            as_of_time = as_of_time.replace(tzinfo=timezone.utc)
        elif obs_time.tzinfo is None and as_of_time.tzinfo is not None:
            obs_time = obs_time.replace(tzinfo=timezone.utc)

        dt_seconds = max((as_of_time - obs_time).total_seconds(), 0.0)
        decay = DECAY_LAMBDAS.get(obs.decay_class, DECAY_LAMBDAS["operational"])
        return math.exp(-decay * dt_seconds / 3600.0)

    def aggregate(
        self,
        observations: Iterable[Observation],
        target: str,
        context: str,
        as_of: datetime,
    ) -> SupportContribution:
        realized = 0.0
        blocked = 0.0
        unresolved = 0.0
        raw_realized = 0.0
        raw_blocked = 0.0
        raw_unresolved = 0.0

        family_weights: dict[str, float] = {}
        observed_families: set[str] = set()
        observed_cycle_ids: set[str] = set()

        for obs in observations:
            if obs.context != context or target not in obs.targets:
                continue
            if self.is_expired(obs, as_of):
                continue

            mapping = obs.support_mapping.get(target, {})
            weight = self.weight(obs, as_of)
            family = instrument_family(obs.instrument)

            realized_part = float(mapping.get("R", 0.0))
            blocked_part = float(mapping.get("B", 0.0))
            unresolved_part = float(mapping.get("U", 0.0))

            if max(realized_part, blocked_part, unresolved_part) > 0.0:
                observed_families.add(family)
                if obs.cycle_id:
                    observed_cycle_ids.add(obs.cycle_id)

            realized += weight * realized_part
            blocked += weight * blocked_part
            unresolved += weight * unresolved_part

            raw_realized += realized_part
            raw_blocked += blocked_part
            raw_unresolved += unresolved_part

            family_weights[family] = family_weights.get(family, 0.0) + weight * max(
                realized_part,
                blocked_part,
                unresolved_part,
            )

        contradiction = min(realized, blocked)
        total_weight = sum(family_weights.values())
        active_families = {
            family: mass for family, mass in family_weights.items() if mass > 0.05
        }

        compatibility_span = (
            len(observed_cycle_ids) if observed_cycle_ids else len(observed_families)
        )

        if total_weight > 0.0 and compatibility_span > 0 and active_families:
            concentration = max(active_families.values()) / total_weight
            compatibility_score = max(
                0.0,
                min(1.0, 1.0 - concentration + (0.1 * (compatibility_span - 1))),
            )
        else:
            compatibility_score = 0.0

        raw_total = raw_realized + raw_blocked + raw_unresolved
        decayed_total = realized + blocked + unresolved

        if raw_total > 0.0:
            decoherence = max(0.0, raw_total - decayed_total) / raw_total
        else:
            decoherence = 0.0

        if compatibility_span <= 1 and raw_total > 0.0:
            decoherence += 0.15
        decoherence = max(0.0, min(1.0, decoherence))

        return SupportContribution(
            realized=realized,
            blocked=blocked,
            unresolved=unresolved,
            contradiction=contradiction,
            decoherence=decoherence,
            compatibility_score=compatibility_score,
            compatibility_span=compatibility_span,
        )
