from __future__ import annotations

from typing import Any, Mapping


AD_DELEGATION_CONTEXT_SCHEMA = "skg.ad.delegation_context.v1"
AD_DELEGATION_CONTEXT_FILENAME = "ad07_delegation_context.json"
AD_DELEGATION_CONTEXT_WICKET_ID = "AD-07"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "schema",
    "wicket_id",
    "slice",
    "source_kind",
    "workload_id",
    "run_id",
    "observed_at",
    "recency_policy",
    "unknown_handling_policy",
    "activity_classification",
    "summary",
)

_REQUIRED_RECENCY_FIELDS = (
    "stale_days",
    "stale_threshold_seconds",
)

_REQUIRED_UNKNOWN_HANDLING_FIELDS = ("unknown_last_logon_is_active",)

_REQUIRED_ACTIVITY_FIELDS = (
    "total_unconstrained_non_dc",
    "active_unconstrained",
    "stale_unconstrained",
    "unknown_last_logon",
)

_REQUIRED_SUMMARY_FIELDS = (
    "status",
    "active_count",
    "stale_count",
    "unknown_count",
)

_ACTIVE_STATES = {"recent", "unknown_assumed_active"}
_STALE_STATES = {"stale"}
_UNKNOWN_STATES = {"unknown"}


def _validate_int_field(container: Mapping[str, Any], field: str) -> list[str]:
    value = container.get(field)
    if not isinstance(value, int):
        return [f"{field} must be an int"]
    if value < 0:
        return [f"{field} must be >= 0"]
    return []


def _validate_bool_field(container: Mapping[str, Any], field: str) -> list[str]:
    if not isinstance(container.get(field), bool):
        return [f"{field} must be a bool"]
    return []


def _validate_activity_rows(
    rows: Any,
    field_name: str,
    *,
    allowed_states: set[str],
    state_required: bool,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(rows, list):
        return [f"{field_name} must be a list"]

    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            errors.append(f"{field_name}[{index}] must be a mapping")
            continue

        name = row.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{field_name}[{index}].name must be a non-empty string")

        if "age_seconds" in row and row.get("age_seconds") is not None:
            age_seconds = row.get("age_seconds")
            if not isinstance(age_seconds, (int, float)):
                errors.append(f"{field_name}[{index}].age_seconds must be numeric or null")

        state = row.get("activity_state")
        if state_required and not isinstance(state, str):
            errors.append(f"{field_name}[{index}].activity_state must be a string")
            continue
        if isinstance(state, str) and state not in allowed_states:
            errors.append(
                f"{field_name}[{index}].activity_state invalid: "
                f"expected one of {sorted(allowed_states)}"
            )

    return errors


def validate_ad_delegation_context(payload: Mapping[str, Any] | Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ["ad_delegation_context must be a mapping"]

    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        if field not in payload:
            errors.append(f"missing field: {field}")

    schema = str(payload.get("schema") or "")
    if schema != AD_DELEGATION_CONTEXT_SCHEMA:
        errors.append(
            "invalid schema: expected "
            f"'{AD_DELEGATION_CONTEXT_SCHEMA}', got '{schema or 'missing'}'"
        )

    wicket_id = str(payload.get("wicket_id") or "")
    if wicket_id != AD_DELEGATION_CONTEXT_WICKET_ID:
        errors.append(
            "invalid wicket_id: expected "
            f"'{AD_DELEGATION_CONTEXT_WICKET_ID}', got '{wicket_id or 'missing'}'"
        )

    recency_policy = payload.get("recency_policy")
    if not isinstance(recency_policy, Mapping):
        errors.append("recency_policy must be a mapping")
    else:
        for field in _REQUIRED_RECENCY_FIELDS:
            if field not in recency_policy:
                errors.append(f"recency_policy missing field: {field}")
        for field in _REQUIRED_RECENCY_FIELDS:
            if field in recency_policy:
                errors.extend(_validate_int_field(recency_policy, field))

    unknown_policy = payload.get("unknown_handling_policy")
    if not isinstance(unknown_policy, Mapping):
        errors.append("unknown_handling_policy must be a mapping")
    else:
        for field in _REQUIRED_UNKNOWN_HANDLING_FIELDS:
            if field not in unknown_policy:
                errors.append(f"unknown_handling_policy missing field: {field}")
        for field in _REQUIRED_UNKNOWN_HANDLING_FIELDS:
            if field in unknown_policy:
                errors.extend(_validate_bool_field(unknown_policy, field))

    activity = payload.get("activity_classification")
    if not isinstance(activity, Mapping):
        errors.append("activity_classification must be a mapping")
    else:
        for field in _REQUIRED_ACTIVITY_FIELDS:
            if field not in activity:
                errors.append(f"activity_classification missing field: {field}")

        if "total_unconstrained_non_dc" in activity:
            errors.extend(_validate_int_field(activity, "total_unconstrained_non_dc"))

        if "active_unconstrained" in activity:
            errors.extend(
                _validate_activity_rows(
                    activity.get("active_unconstrained"),
                    "activity_classification.active_unconstrained",
                    allowed_states=_ACTIVE_STATES,
                    state_required=True,
                )
            )

        if "stale_unconstrained" in activity:
            errors.extend(
                _validate_activity_rows(
                    activity.get("stale_unconstrained"),
                    "activity_classification.stale_unconstrained",
                    allowed_states=_STALE_STATES,
                    state_required=True,
                )
            )

        if "unknown_last_logon" in activity:
            errors.extend(
                _validate_activity_rows(
                    activity.get("unknown_last_logon"),
                    "activity_classification.unknown_last_logon",
                    allowed_states=_UNKNOWN_STATES,
                    state_required=True,
                )
            )

    summary = payload.get("summary")
    if not isinstance(summary, Mapping):
        errors.append("summary must be a mapping")
    else:
        for field in _REQUIRED_SUMMARY_FIELDS:
            if field not in summary:
                errors.append(f"summary missing field: {field}")
        for field in ("active_count", "stale_count", "unknown_count"):
            if field in summary:
                errors.extend(_validate_int_field(summary, field))

        status = summary.get("status")
        if status not in {"realized", "blocked", "unknown"}:
            errors.append("summary.status must be one of: realized, blocked, unknown")

    return errors


def is_ad_delegation_context(payload: Mapping[str, Any] | Any) -> bool:
    return validate_ad_delegation_context(payload) == []


__all__ = [
    "AD_DELEGATION_CONTEXT_FILENAME",
    "AD_DELEGATION_CONTEXT_SCHEMA",
    "AD_DELEGATION_CONTEXT_WICKET_ID",
    "is_ad_delegation_context",
    "validate_ad_delegation_context",
]
