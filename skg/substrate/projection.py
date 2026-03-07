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

Tri-state scoring:
  score = |realized| / |required|
  classification:
    realized      — all required nodes realized
    not_realized  — at least one node blocked
    indeterminate — some unknown, none blocked (or mixed)

E = H(projection | telemetry) = |unknown| / |required|
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from skg.substrate.node import NodeState, TriState
from skg.substrate.path import Path, PathScore


def project_path(path: Path,
                 states: dict[str, NodeState],
                 workload_id: str = "",
                 run_id: str = "") -> PathScore:
    """
    Apply projection π to a Path given a dict of NodeStates.

    states: node_id → NodeState (latest observation per node)
    Missing nodes are treated as UNKNOWN.
    """
    required = path.required_nodes
    latest_status = {}
    realized, blocked, unknown = [], [], []

    for nid in required:
        ns = states.get(nid)
        if ns is None:
            ns = NodeState.unknown(nid)
        latest_status[nid] = ns.state.value

        if ns.state == TriState.REALIZED:
            realized.append(nid)
        elif ns.state == TriState.BLOCKED:
            blocked.append(nid)
        else:
            unknown.append(nid)

    score = round(len(realized) / len(required), 6) if required else 0.0
    classification = classify(realized, blocked, unknown, required)

    return PathScore(
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


def classify(realized: list[str],
             blocked:  list[str],
             unknown:  list[str],
             required: list[str]) -> str:
    """
    Tri-state classification of a path given its node states.

    realized      — all required nodes realized, path is traversable
    not_realized  — at least one node blocked, path is closed
    indeterminate — insufficient evidence to determine traversability
    """
    if len(realized) == len(required):
        return "realized"
    if blocked and not unknown:
        return "not_realized"
    return "indeterminate"


def load_states_from_events(events: list[dict]) -> dict[str, NodeState]:
    """
    Build a NodeState dict from a list of event dicts.
    Latest observation per node_id wins (by observed_at timestamp).
    Accepts both obs.attack.precondition and obs.substrate.node event types.
    """
    latest_ts: dict[str, str] = {}
    states: dict[str, NodeState] = {}

    for ev in events:
        if ev.get("type") not in ("obs.attack.precondition",
                                   "obs.substrate.node"):
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
        states[nid] = NodeState(
            node_id=nid,
            state=state,
            confidence=evidence.get("confidence", 0.5),
            observed_at=obs_at,
            source_kind=evidence.get("source_kind", ""),
            pointer=evidence.get("pointer", ""),
            notes=payload.get("notes", ""),
            attributes=payload.get("attributes", {}),
        )

    return states
