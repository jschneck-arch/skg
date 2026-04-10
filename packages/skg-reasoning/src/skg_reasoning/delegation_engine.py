from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from skg_protocol.contracts import AD_DELEGATION_CONTEXT_SCHEMA, validate_ad_delegation_context

from skg_reasoning.contracts import (
    DELEGATION_REASONING_SCHEMA,
    DELEGATION_REASONING_SLICE,
    DELEGATION_REASONING_REQUIRED_WICKETS,
    validate_delegation_reasoning_output,
)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text:
            try:
                return int(float(text))
            except ValueError:
                return 0
    return 0


def _canonical_status(*, status: Any, realized: Any) -> str:
    normalized = str(status or "").strip().lower()
    if normalized in {"realized", "blocked", "unknown"}:
        return normalized
    if realized is True:
        return "realized"
    if realized is False:
        return "blocked"
    return "unknown"


def _extract_canonical_posture(
    events: Sequence[Mapping[str, Any]] | Any,
) -> tuple[dict[str, str], str, str, int]:
    statuses = {wicket: "unknown" for wicket in DELEGATION_REASONING_REQUIRED_WICKETS}
    workload_id = ""
    run_id = ""
    consumed = 0

    rows = events if isinstance(events, list) else []
    for event in rows:
        envelope = _as_mapping(event)
        if str(envelope.get("type") or "") != "obs.attack.precondition":
            continue

        payload = _as_mapping(envelope.get("payload"))
        wicket_id = str(payload.get("wicket_id") or payload.get("node_id") or "")
        if wicket_id not in statuses:
            continue

        statuses[wicket_id] = _canonical_status(
            status=payload.get("status"),
            realized=payload.get("realized"),
        )
        consumed += 1

        if not workload_id:
            workload_id = str(payload.get("workload_id") or "")
        if not run_id:
            run_id = str(payload.get("run_id") or "")

    return statuses, workload_id, run_id, consumed


def _derive_path_pressure(
    *,
    posture_realized_count: int,
    active_count: int,
    stale_count: int,
    unknown_count: int,
    unknown_assumed_active: bool,
) -> str:
    if posture_realized_count <= 0:
        return "low"
    if active_count > 0:
        return "high"
    if stale_count > 0:
        return "medium"
    if unknown_count > 0 and unknown_assumed_active:
        return "medium"
    if unknown_count > 0:
        return "low"
    return "medium"


def _derive_value_pressure(*, ad06_status: str, ad08_status: str) -> str:
    if ad08_status == "realized":
        return "elevated"
    if ad06_status == "realized":
        return "elevated"
    if ad06_status == "unknown" and ad08_status == "unknown":
        return "unknown"
    return "baseline"


def _derive_attacker_usefulness(*, path_pressure: str, value_pressure: str) -> str:
    if path_pressure == "high" and value_pressure == "elevated":
        return "high"
    if path_pressure in {"high", "medium"} and value_pressure == "elevated":
        return "medium"
    if path_pressure == "unknown" or value_pressure == "unknown":
        return "unknown"
    if path_pressure == "low" and value_pressure == "baseline":
        return "low"
    return "medium"


def _confidence(
    *,
    context_status: str,
    consumed_event_count: int,
    ad06_status: str,
    ad08_status: str,
) -> float:
    if context_status == "realized":
        score = 0.86
    elif context_status == "blocked":
        score = 0.74
    else:
        score = 0.58

    if consumed_event_count == 0:
        score -= 0.25
    if ad06_status == "unknown":
        score -= 0.08
    if ad08_status == "unknown":
        score -= 0.08

    return max(0.0, min(0.99, round(score, 2)))


def evaluate_delegation_reasoning(
    events: Sequence[Mapping[str, Any]] | Any,
    delegation_context: Mapping[str, Any] | Any,
) -> dict[str, Any]:
    """
    Consume canonical AD-06/AD-08 posture events and AD-07 context contract,
    then produce derived reasoning output (path/value/usefulness).
    """

    context = _as_mapping(delegation_context)
    context_errors = validate_ad_delegation_context(context)
    if context_errors:
        raise ValueError(
            "Invalid AD-07 context contract for delegation reasoning: "
            + "; ".join(context_errors)
        )

    statuses, event_workload_id, event_run_id, consumed_count = _extract_canonical_posture(events)

    ad06_status = statuses["AD-06"]
    ad08_status = statuses["AD-08"]

    summary = _as_mapping(context.get("summary"))
    context_policy = _as_mapping(context.get("unknown_handling_policy"))
    recency_policy = _as_mapping(context.get("recency_policy"))

    active_count = _as_int(summary.get("active_count"))
    stale_count = _as_int(summary.get("stale_count"))
    unknown_count = _as_int(summary.get("unknown_count"))
    posture_realized_count = int(ad06_status == "realized") + int(ad08_status == "realized")
    unknown_assumed_active = bool(context_policy.get("unknown_last_logon_is_active"))

    path_pressure = _derive_path_pressure(
        posture_realized_count=posture_realized_count,
        active_count=active_count,
        stale_count=stale_count,
        unknown_count=unknown_count,
        unknown_assumed_active=unknown_assumed_active,
    )
    value_pressure = _derive_value_pressure(ad06_status=ad06_status, ad08_status=ad08_status)
    attacker_usefulness = _derive_attacker_usefulness(
        path_pressure=path_pressure,
        value_pressure=value_pressure,
    )
    confidence = _confidence(
        context_status=str(summary.get("status") or "unknown"),
        consumed_event_count=consumed_count,
        ad06_status=ad06_status,
        ad08_status=ad08_status,
    )

    workload_id = (
        event_workload_id
        or str(context.get("workload_id") or "")
    )
    run_id = (
        event_run_id
        or str(context.get("run_id") or "")
    )

    output = {
        "schema": DELEGATION_REASONING_SCHEMA,
        "slice": DELEGATION_REASONING_SLICE,
        "workload_id": workload_id,
        "run_id": run_id,
        "derived_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "canonical_wicket_status": {
                "AD-06": ad06_status,
                "AD-08": ad08_status,
            },
            "context_schema": AD_DELEGATION_CONTEXT_SCHEMA,
            "context_summary": {
                "status": str(summary.get("status") or "unknown"),
                "active_count": active_count,
                "stale_count": stale_count,
                "unknown_count": unknown_count,
            },
            "context_policy": {
                "stale_days": _as_int(recency_policy.get("stale_days")),
                "unknown_last_logon_is_active": unknown_assumed_active,
            },
        },
        "derived": {
            "path_pressure": path_pressure,
            "value_pressure": value_pressure,
            "attacker_usefulness": attacker_usefulness,
            "confidence": confidence,
            "explanation": [
                f"Canonical posture statuses: AD-06={ad06_status}, AD-08={ad08_status}.",
                "AD-07 service context applied for freshness/unknown handling; "
                f"active={active_count}, stale={stale_count}, unknown={unknown_count}.",
                f"Derived reasoning outcome: path_pressure={path_pressure}, "
                f"value_pressure={value_pressure}, attacker_usefulness={attacker_usefulness}.",
            ],
        },
        "deferred_reasoning": {
            "ad09_sensitive_target_reasoning_deferred": True,
            "attack_path_chaining_deferred": True,
            "runtime_transport_coupling_deferred": True,
        },
    }

    output_errors = validate_delegation_reasoning_output(output)
    if output_errors:
        raise RuntimeError(
            "Delegation reasoning output failed contract validation: "
            + "; ".join(output_errors)
        )

    return output


__all__ = ["evaluate_delegation_reasoning"]
