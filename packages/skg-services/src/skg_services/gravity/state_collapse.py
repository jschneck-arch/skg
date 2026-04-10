"""Service-owned event-to-state collapse bridge.

This logic consumes observation events and produces substrate node states.
It is intentionally not part of skg-core substrate projection primitives.
"""
from __future__ import annotations

from skg_core.kernel.state import CollapseThresholds, StateEngine
from skg_core.kernel.support import SupportEngine
from skg_core.substrate.node import NodeState, TriState
from skg_protocol.observation_mapping import map_event_to_observation_mapping


def _target_for_events(events: list[dict]) -> str:
    for event in reversed(events):
        mapped = map_event_to_observation_mapping(event)
        if mapped is None:
            continue
        if mapped.targets:
            return str(mapped.targets[0])
    return "unknown"


def _best_support_observation(observations, target: str):
    return max(
        observations,
        key=lambda item: item[0].support_mapping.get(target, {}).get("R", 0.0)
        + item[0].support_mapping.get(target, {}).get("B", 0.0),
        default=None,
    )


def _unresolved_reason_for_support(contrib, observations: list) -> str:
    reason = "unmeasured"
    if any(bool(item[0].payload.get("is_latent", False)) for item in observations):
        reason = "latent"
    elif getattr(contrib, "contradiction", 0.0) > 0.0:
        reason = "conflicted"
    elif getattr(contrib, "decoherence", 0.0) > 0.0 and getattr(contrib, "unresolved", 0.0) > 0.0:
        reason = "decohered"
    elif getattr(contrib, "unresolved", 0.0) > 0.0 and not contrib.realized and not contrib.blocked:
        reason = "inconclusive"
    elif contrib.realized > 0.0 or contrib.blocked > 0.0:
        reason = "insufficient_support"

    if getattr(contrib, "compatibility_span", 0) <= 1 and getattr(contrib, "unresolved", 0.0) > 0.0:
        reason = "single_basis"
    return reason


def load_states_from_events(events: list[dict]) -> dict[str, NodeState]:
    states: dict[str, NodeState] = {}
    grouped: dict[str, list] = {}
    target = _target_for_events(events)

    for event in events:
        if event.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
            continue
        mapped = map_event_to_observation_mapping(event)
        if mapped is None:
            continue
        grouped.setdefault(mapped.context, []).append((mapped, event))

    if not grouped:
        return states

    support = SupportEngine()
    state_engine = StateEngine(CollapseThresholds(realized=0.5, blocked=0.5))

    for node_id, observations in grouped.items():
        obs_only = [item[0] for item in observations]
        as_of = max(obs.event_time for obs in obs_only)
        contrib = support.aggregate(obs_only, target, node_id, as_of)
        best = _best_support_observation(observations, target)
        if best is None:
            continue

        _, best_event = best
        payload = best_event.get("payload", {})
        evidence = best_event.get("provenance", {}).get("evidence", {})
        collapsed = state_engine.collapse(contrib)

        node_state = NodeState(
            node_id=node_id,
            state=collapsed,
            confidence=max(contrib.realized, contrib.blocked),
            observed_at=as_of.isoformat(),
            source_kind=evidence.get("source_kind", ""),
            pointer=evidence.get("pointer", ""),
            notes=payload.get("detail", "") or payload.get("notes", ""),
            attributes=dict(payload.get("attributes", {})),
        )

        node_state.attributes.update(
            {
                "phi_r": round(contrib.realized, 6),
                "phi_b": round(contrib.blocked, 6),
                "phi_u": round(getattr(contrib, "unresolved", 0.0), 6),
                "contradiction": round(getattr(contrib, "contradiction", 0.0), 6),
                "decoherence": round(getattr(contrib, "decoherence", 0.0), 6),
                "compatibility_score": round(getattr(contrib, "compatibility_score", 0.0), 6),
                "compatibility_span": int(getattr(contrib, "compatibility_span", 0) or 0),
                "support_basis": "aggregated_observation_support",
                "support_observation_count": len(obs_only),
                "unresolved_reason": _unresolved_reason_for_support(contrib, observations),
            }
        )

        node_state.local_energy = round(
            getattr(contrib, "unresolved", 0.0)
            + getattr(contrib, "contradiction", 0.0)
            + getattr(contrib, "decoherence", 0.0),
            6,
        )
        node_state.is_latent = any(bool(obs.payload.get("is_latent", False)) for obs in obs_only)

        states[node_id] = node_state

    return states


def load_states_from_events_priority(events: list[dict], required: list[str] | None = None) -> dict[str, NodeState]:
    all_obs: dict[str, list] = {}
    target = _target_for_events(events)

    for event in events:
        if event.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
            continue
        mapped = map_event_to_observation_mapping(event)
        if mapped is None:
            continue
        node_id = mapped.context
        if required and node_id not in required:
            continue
        all_obs.setdefault(node_id, []).append((mapped, event))

    states: dict[str, NodeState] = {}
    support = SupportEngine()
    state_engine = StateEngine(CollapseThresholds(realized=0.5, blocked=0.5))

    for node_id, observations in all_obs.items():
        obs_only = [item[0] for item in observations]
        as_of = max(obs.event_time for obs in obs_only)
        contrib = support.aggregate(obs_only, target, node_id, as_of)

        blocked_events = [
            item
            for item in observations
            if item[0].support_mapping.get(target, {}).get("B", 0.0) > 0.0
        ]
        if blocked_events:
            collapsed = TriState.BLOCKED
            best = _best_support_observation(blocked_events, target)
        else:
            collapsed = state_engine.collapse(contrib)
            best = _best_support_observation(observations, target)

        if best is None:
            continue

        _, best_event = best
        payload = best_event.get("payload", {})
        evidence = best_event.get("provenance", {}).get("evidence", {})

        node_state = NodeState(
            node_id=node_id,
            state=collapsed,
            confidence=max(contrib.realized, contrib.blocked),
            observed_at=as_of.isoformat(),
            source_kind=evidence.get("source_kind", ""),
            pointer=evidence.get("pointer", ""),
            notes=payload.get("detail", "") or payload.get("notes", ""),
            attributes=dict(payload.get("attributes", {})),
        )

        node_state.attributes.update(
            {
                "phi_r": round(contrib.realized, 6),
                "phi_b": round(contrib.blocked, 6),
                "phi_u": round(getattr(contrib, "unresolved", 0.0), 6),
                "contradiction": round(getattr(contrib, "contradiction", 0.0), 6),
                "decoherence": round(getattr(contrib, "decoherence", 0.0), 6),
                "compatibility_score": round(getattr(contrib, "compatibility_score", 0.0), 6),
                "compatibility_span": int(getattr(contrib, "compatibility_span", 0) or 0),
                "support_basis": "priority_support_aggregation",
                "support_observation_count": len(obs_only),
                "unresolved_reason": _unresolved_reason_for_support(contrib, observations),
            }
        )

        node_state.local_energy = round(
            getattr(contrib, "unresolved", 0.0)
            + getattr(contrib, "contradiction", 0.0)
            + getattr(contrib, "decoherence", 0.0),
            6,
        )
        node_state.is_latent = any(bool(obs.payload.get("is_latent", False)) for obs in obs_only)

        states[node_id] = node_state

    return states
