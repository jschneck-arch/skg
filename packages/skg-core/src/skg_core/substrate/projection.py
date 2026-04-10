from __future__ import annotations

from datetime import datetime, timezone

from skg_core.substrate.node import NodeState, TriState
from skg_core.substrate.path import Path, PathScore


def classify(
    realized: list[str],
    blocked: list[str],
    unknown: list[str],
    required: list[str],
) -> str:
    """Tri-state path classification."""

    if len(realized) == len(required):
        return "realized"
    if blocked:
        return "not_realized"
    return "indeterminate"


def project_path(
    path: Path,
    states: dict[str, NodeState],
    workload_id: str = "",
    run_id: str = "",
) -> PathScore:
    """Project NodeStates onto a path score using conservative semantics."""

    required = list(path.required_nodes)
    latest_status: dict[str, str] = {}
    realized: list[str] = []
    blocked: list[str] = []
    unknown: list[str] = []

    for node_id in required:
        state = states.get(node_id) or NodeState.unknown(node_id)
        latest_status[node_id] = state.state.value
        if state.state == TriState.REALIZED:
            realized.append(node_id)
        elif state.state == TriState.BLOCKED:
            blocked.append(node_id)
        else:
            unknown.append(node_id)

    score = round(len(realized) / len(required), 6) if required else 0.0
    classification = classify(realized, blocked, unknown, required)

    unresolved_detail = {
        node_id: {
            "reason": (states.get(node_id) or NodeState.unknown(node_id)).attributes.get(
                "unresolved_reason", "unmeasured"
            ),
            "local_energy": round(float((states.get(node_id) or NodeState.unknown(node_id)).local_energy), 6),
            "is_latent": bool((states.get(node_id) or NodeState.unknown(node_id)).is_latent),
        }
        for node_id in unknown
    }

    return PathScore(
        path_id=path.path_id,
        score=score,
        classification=classification,
        realized=realized,
        blocked=blocked,
        unknown=unknown,
        latest_status=latest_status,
        unresolved_detail=unresolved_detail,
        workload_id=workload_id,
        run_id=run_id,
        computed_at=datetime.now(timezone.utc).isoformat(),
    )
