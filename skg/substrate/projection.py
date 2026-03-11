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
  not_realized  — at least one node blocked and no remaining unknowns
  indeterminate — some unknown exists, or mixed evidence remains

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
    not_realized  — path is closed by confirmed blocking evidence and no unknowns remain
    indeterminate — insufficient evidence to determine traversability
    """
    if len(realized) == len(required):
        return "realized"

    # Keep conservative semantics:
    # if any unknown remains, do not over-assert closure.
    if blocked and not unknown:
        return "not_realized"

    return "indeterminate"


def load_states_from_events(events: list[dict]) -> dict[str, NodeState]:
    """
    Build a NodeState dict from a list of event dicts.
    Latest observation per node_id wins (by observed_at timestamp).

    Accepts both:
    - obs.attack.precondition
    - obs.substrate.node

    Supports both:
    - node_id
    - wicket_id

    Backward compatible with older event payloads while seeding richer
    substrate state when available.
    """
    latest_ts: dict[str, str] = {}
    states: dict[str, NodeState] = {}

    for ev in events:
        if ev.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
            continue

        payload = ev.get("payload", {})
        prov = ev.get("provenance", {})

        # Support both wicket_id (security) and node_id (substrate)
        nid = payload.get("node_id") or payload.get("wicket_id", "")
        if not nid:
            continue

        obs_at = payload.get("observed_at") or ev.get("ts", "")
        if nid in latest_ts and obs_at <= latest_ts[nid]:
            continue

        latest_ts[nid] = obs_at

        status_str = payload.get("status", "unknown")
        try:
            state = TriState(status_str)
        except ValueError:
            state = TriState.UNKNOWN

        evidence = prov.get("evidence", {})

        ns = NodeState(
            node_id=nid,
            state=state,
            confidence=evidence.get("confidence", 0.5),
            observed_at=obs_at,
            source_kind=evidence.get("source_kind", ""),
            pointer=evidence.get("pointer", ""),
            notes=payload.get("notes", ""),
            attributes=payload.get("attributes", {}),
        )

        # Optional richer field hints from events, if present.
        if "confidence_vector" in evidence and hasattr(ns, "set_confidence_vector"):
            try:
                ns.set_confidence_vector(evidence.get("confidence_vector", []), sync_scalar=True)
            except Exception:
                pass

        if "local_energy" in evidence:
            try:
                ns.local_energy = float(evidence.get("local_energy", 0.0) or 0.0)
            except Exception:
                ns.local_energy = 0.0

        if "phase" in evidence:
            try:
                ns.phase = float(evidence.get("phase", 0.0) or 0.0)
            except Exception:
                ns.phase = 0.0

        if "is_latent" in payload:
            ns.is_latent = bool(payload.get("is_latent", False))

        if "projection_sources" in payload:
            try:
                ns.projection_sources = list(payload.get("projection_sources", []) or [])
            except Exception:
                ns.projection_sources = []

        states[nid] = ns

    return states
