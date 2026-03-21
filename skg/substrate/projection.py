"""
skg.substrate.projection
========================
π — the projection engine.

Maps observation space (NodeStates) onto path space (PathScore).
This is the core of the λ–κ–π substrate.

The projection is:
  π: {NodeState} × Path → PathScore

It is deterministic, stateless, and domain-agnostic.
The same engine scores security attack paths and supply chain
compromise chains without modification.

Current scoring remains intentionally conservative:
  score = |realized| / |required|

classification:
  realized      — all required nodes realized
  not_realized  — at least one node blocked
  indeterminate — some unknown exists and no blocking evidence exists

E = H(projection | telemetry) ~ |unknown| / |required|

Backward-compatibility note:
This module preserves current public behavior while becoming aware of
richer NodeState structure (vector confidence, local energy, latent flags).
"""
from __future__ import annotations

from datetime import datetime, timezone

from skg.substrate.node import NodeState, TriState
from skg.substrate.path import Path, PathScore


def _safe_unknown(node_id: str) -> NodeState:
    return NodeState.unknown(node_id)


def _sync_legacy_confidence(ns: NodeState) -> None:
    """
    Keep scalar confidence aligned with richer node state if available.
    Safe no-op for older/simple states.
    """
    if hasattr(ns, "sync_scalar_confidence"):
        ns.sync_scalar_confidence()


def _node_energy(ns: NodeState) -> float:
    return float(getattr(ns, "local_energy", 0.0) or 0.0)


def _node_is_latent(ns: NodeState) -> bool:
    return bool(getattr(ns, "is_latent", False))


def _node_projection_sources(ns: NodeState) -> list[str]:
    return list(getattr(ns, "projection_sources", []) or [])


def _set_optional_pathscore_fields(ps: PathScore,
                                   states_by_id: dict[str, NodeState],
                                   required: list[str]) -> None:
    """
    Attach richer projection metadata only if the PathScore object can accept it.
    This keeps the patch safe across older dataclass definitions.
    """
    try:
        total_energy = round(sum(_node_energy(states_by_id[nid]) for nid in required), 6)
        latent_nodes = [nid for nid in required if _node_is_latent(states_by_id[nid])]
        projection_sources = {
            nid: _node_projection_sources(states_by_id[nid])
            for nid in required
            if _node_projection_sources(states_by_id[nid])
        }

        # Optional enrichments — only attach if setattr works on the object.
        setattr(ps, "total_energy", total_energy)
        setattr(ps, "latent_nodes", latent_nodes)
        setattr(ps, "projection_sources", projection_sources)
    except Exception:
        # Intentionally silent: PathScore may be strict/frozen/slots-based.
        pass


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


def project_path(path: Path,
                 states: dict[str, NodeState],
                 workload_id: str = "",
                 run_id: str = "") -> PathScore:
    """
    Apply projection π to a Path given a dict of NodeStates.

    states: node_id → NodeState (latest observation per node)
    Missing nodes are treated as UNKNOWN.

    Current behavior preserved:
    - score uses realized / required
    - classification remains tri-state honest
    - richer field state is observed but not yet used to alter scoring
    """
    required = path.required_nodes
    latest_status: dict[str, str] = {}
    realized: list[str] = []
    blocked: list[str] = []
    unknown: list[str] = []

    resolved_states: dict[str, NodeState] = {}

    for nid in required:
        ns = states.get(nid)
        if ns is None:
            ns = _safe_unknown(nid)

        _sync_legacy_confidence(ns)
        resolved_states[nid] = ns
        latest_status[nid] = ns.state.value

        if ns.state == TriState.REALIZED:
            realized.append(nid)
        elif ns.state == TriState.BLOCKED:
            blocked.append(nid)
        else:
            unknown.append(nid)

    score = round(len(realized) / len(required), 6) if required else 0.0
    classification = classify(realized, blocked, unknown, required)

    ps = PathScore(
        path_id=path.path_id,
        score=score,
        classification=classification,
        realized=realized,
        blocked=blocked,
        unknown=unknown,
        latest_status=latest_status,
        unresolved_detail={
            nid: {
                "reason": states.get(nid, _safe_unknown(nid)).attributes.get("unresolved_reason", "unmeasured"),
                "local_energy": round(_node_energy(states.get(nid, _safe_unknown(nid))), 6),
                "is_latent": _node_is_latent(states.get(nid, _safe_unknown(nid))),
            }
            for nid in unknown
        },
        workload_id=workload_id,
        run_id=run_id,
        computed_at=datetime.now(timezone.utc).isoformat(),
    )

    _set_optional_pathscore_fields(ps, resolved_states, required)
    return ps


def classify(realized: list[str],
             blocked: list[str],
             unknown: list[str],
             required: list[str]) -> str:
    """
    Tri-state classification of a path given its node states.

    realized      — all required nodes realized, path is traversable
    not_realized  — path is closed by confirmed blocking evidence
    indeterminate — insufficient evidence to determine traversability
    """
    if len(realized) == len(required):
        return "realized"

    # Work 3 semantics: any blocked precondition collapses the path.
    # Unknowns elsewhere do not re-open a path once a required node is blocked.
    if blocked:
        return "not_realized"

    return "indeterminate"


def _target_for_events(events: list[dict]) -> str:
    for ev in reversed(events):
        payload = ev.get("payload", {})
        target = payload.get("target_ip") or payload.get("workload_id")
        if target:
            return target.split("::")[-1]
    return "unknown"


def _best_support_observation(observations, target: str):
    return max(
        observations,
        key=lambda item: item[0].support_mapping.get(target, {}).get("R", 0.0)
        + item[0].support_mapping.get(target, {}).get("B", 0.0),
        default=None,
    )


def load_states_from_events(events: list[dict]) -> dict[str, NodeState]:
    """
    Build a NodeState dict from a list of event dicts.
    Collapse aggregated support per node_id into NodeState.

    Accepts both:
    - obs.attack.precondition
    - obs.substrate.node

    Supports both:
    - node_id
    - wicket_id

    Backward compatible with older event payloads while seeding richer
    substrate state when available.
    """
    from skg.kernel.adapters import event_to_observation
    from skg.kernel.state import CollapseThresholds, StateEngine
    from skg.kernel.support import SupportEngine

    states: dict[str, NodeState] = {}
    grouped: dict[str, list] = {}
    target = _target_for_events(events)

    for ev in events:
        if ev.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
            continue

        obs = event_to_observation(ev)
        if obs is None:
            continue
        grouped.setdefault(obs.context, []).append((obs, ev))

    if not grouped:
        return states

    support = SupportEngine()
    state_engine = StateEngine(CollapseThresholds(realized=0.5, blocked=0.5))

    for nid, observations in grouped.items():
        obs_only = [item[0] for item in observations]
        as_of = max(obs.event_time for obs in obs_only)
        contrib = support.aggregate(obs_only, target, nid, as_of)
        best = _best_support_observation(observations, target)

        if best is None:
            continue

        best_obs, best_event = best
        payload = best_event.get("payload", {})
        evidence = best_event.get("provenance", {}).get("evidence", {})
        collapsed = state_engine.collapse(contrib)

        ns = NodeState(
            node_id=nid,
            state=collapsed,
            confidence=max(contrib.realized, contrib.blocked),
            observed_at=as_of.isoformat(),
            source_kind=evidence.get("source_kind", ""),
            pointer=evidence.get("pointer", ""),
            notes=payload.get("detail", "") or payload.get("notes", ""),
            attributes=dict(payload.get("attributes", {})),
        )

        ns.attributes.update({
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
        })
        ns.local_energy = round(
            getattr(contrib, "unresolved", 0.0)
            + getattr(contrib, "contradiction", 0.0)
            + getattr(contrib, "decoherence", 0.0),
            6,
        )
        ns.is_latent = any(bool(obs.payload.get("is_latent", False)) for obs in obs_only)

        states[nid] = ns

    return states


def load_states_from_events_priority(
    events: list[dict],
    required: list[str] | None = None,
) -> dict[str, NodeState]:
    """
    Build a NodeState dict from events using priority merge: blocked > realized > unknown.

    This is the merge rule used by toolchain projectors (escape, lateral, web).
    When multiple observations exist for the same node, the highest-priority
    state wins regardless of timestamp:
        blocked   (highest — a confirmed block cannot be overridden by a realize)
        realized
        unknown   (lowest)

    If required is provided, only states for nodes in that list are returned.
    All other behavior (event types, field hints) is identical to load_states_from_events.
    """
    from skg.kernel.adapters import event_to_observation
    from skg.kernel.state import CollapseThresholds, StateEngine
    from skg.kernel.support import SupportEngine

    all_obs: dict[str, list] = {}
    target = _target_for_events(events)
    for ev in events:
        if ev.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
            continue
        obs = event_to_observation(ev)
        if obs is None:
            continue
        nid = obs.context
        if required and nid not in required:
            continue
        all_obs.setdefault(nid, []).append((obs, ev))

    states: dict[str, NodeState] = {}
    support = SupportEngine()
    state_engine = StateEngine(CollapseThresholds(realized=0.5, blocked=0.5))
    for nid, evs in all_obs.items():
        obs_only = [item[0] for item in evs]
        as_of = max(obs.event_time for obs in obs_only)
        contrib = support.aggregate(obs_only, target, nid, as_of)

        blocked_evs = [
            item for item in evs
            if item[0].support_mapping.get(target, {}).get("B", 0.0) > 0.0
        ]
        if blocked_evs:
            collapsed = TriState.BLOCKED
            best = _best_support_observation(blocked_evs, target)
        else:
            collapsed = state_engine.collapse(contrib)
            best = _best_support_observation(evs, target)

        if best is None:
            continue

        _best_obs, best_ev = best
        payload = best_ev.get("payload", {})
        prov = best_ev.get("provenance", {})
        evidence = prov.get("evidence", {})

        ns = NodeState(
            node_id=nid,
            state=collapsed,
            confidence=max(contrib.realized, contrib.blocked),
            observed_at=as_of.isoformat(),
            source_kind=evidence.get("source_kind", ""),
            pointer=evidence.get("pointer", ""),
            notes=payload.get("detail", "") or payload.get("notes", ""),
            attributes=dict(payload.get("attributes", {})),
        )
        ns.attributes.update({
            "phi_r": round(contrib.realized, 6),
            "phi_b": round(contrib.blocked, 6),
            "phi_u": round(getattr(contrib, "unresolved", 0.0), 6),
            "contradiction": round(getattr(contrib, "contradiction", 0.0), 6),
            "decoherence": round(getattr(contrib, "decoherence", 0.0), 6),
            "compatibility_score": round(getattr(contrib, "compatibility_score", 0.0), 6),
            "compatibility_span": int(getattr(contrib, "compatibility_span", 0) or 0),
            "support_basis": "priority_support_aggregation",
            "support_observation_count": len(obs_only),
            "unresolved_reason": _unresolved_reason_for_support(contrib, evs),
        })
        ns.local_energy = round(
            getattr(contrib, "unresolved", 0.0)
            + getattr(contrib, "contradiction", 0.0)
            + getattr(contrib, "decoherence", 0.0),
            6,
        )
        ns.is_latent = any(bool(obs.payload.get("is_latent", False)) for obs in obs_only)

        states[nid] = ns

    return states
