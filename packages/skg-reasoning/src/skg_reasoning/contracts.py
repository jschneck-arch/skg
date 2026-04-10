from __future__ import annotations

from typing import Any, Mapping

from skg_protocol.contracts import AD_DELEGATION_CONTEXT_SCHEMA


DELEGATION_REASONING_SCHEMA = "skg.reasoning.delegation_evaluation.v1"
DELEGATION_REASONING_SLICE = "delegation_reasoning_pilot_v1"
DELEGATION_REASONING_REQUIRED_WICKETS = ("AD-06", "AD-08")

_REQUIRED_TOP_LEVEL_FIELDS = (
    "schema",
    "slice",
    "workload_id",
    "run_id",
    "derived_at",
    "inputs",
    "derived",
    "deferred_reasoning",
)

_REQUIRED_INPUT_FIELDS = (
    "canonical_wicket_status",
    "context_schema",
    "context_summary",
    "context_policy",
)

_REQUIRED_CONTEXT_SUMMARY_FIELDS = (
    "status",
    "active_count",
    "stale_count",
    "unknown_count",
)

_REQUIRED_DERIVED_FIELDS = (
    "path_pressure",
    "value_pressure",
    "attacker_usefulness",
    "confidence",
    "explanation",
)

_REQUIRED_DEFERRED_FIELDS = (
    "ad09_sensitive_target_reasoning_deferred",
    "attack_path_chaining_deferred",
    "runtime_transport_coupling_deferred",
)

_ALLOWED_STATUS = {"realized", "blocked", "unknown"}
_ALLOWED_PATH_PRESSURE = {"low", "medium", "high", "unknown"}
_ALLOWED_VALUE_PRESSURE = {"baseline", "elevated", "unknown"}
_ALLOWED_ATTACKER_USEFULNESS = {"low", "medium", "high", "unknown"}


def _validate_non_negative_int(container: Mapping[str, Any], field: str) -> list[str]:
    value = container.get(field)
    if not isinstance(value, int):
        return [f"{field} must be an int"]
    if value < 0:
        return [f"{field} must be >= 0"]
    return []


def validate_delegation_reasoning_output(payload: Mapping[str, Any] | Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ["delegation_reasoning_output must be a mapping"]

    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        if field not in payload:
            errors.append(f"missing field: {field}")

    schema = str(payload.get("schema") or "")
    if schema != DELEGATION_REASONING_SCHEMA:
        errors.append(
            f"invalid schema: expected '{DELEGATION_REASONING_SCHEMA}', got '{schema or 'missing'}'"
        )

    if payload.get("events") is not None or payload.get("raw_events") is not None:
        errors.append("raw events must not be embedded in reasoning output")

    inputs = payload.get("inputs")
    if not isinstance(inputs, Mapping):
        errors.append("inputs must be a mapping")
    else:
        for field in _REQUIRED_INPUT_FIELDS:
            if field not in inputs:
                errors.append(f"inputs missing field: {field}")

        wicket_status = inputs.get("canonical_wicket_status")
        if not isinstance(wicket_status, Mapping):
            errors.append("inputs.canonical_wicket_status must be a mapping")
        else:
            for wicket in DELEGATION_REASONING_REQUIRED_WICKETS:
                status = wicket_status.get(wicket)
                if status not in _ALLOWED_STATUS:
                    errors.append(
                        f"inputs.canonical_wicket_status.{wicket} must be one of "
                        f"{sorted(_ALLOWED_STATUS)}"
                    )

        context_schema = str(inputs.get("context_schema") or "")
        if context_schema != AD_DELEGATION_CONTEXT_SCHEMA:
            errors.append(
                f"inputs.context_schema must be '{AD_DELEGATION_CONTEXT_SCHEMA}', got "
                f"'{context_schema or 'missing'}'"
            )

        context_summary = inputs.get("context_summary")
        if not isinstance(context_summary, Mapping):
            errors.append("inputs.context_summary must be a mapping")
        else:
            for field in _REQUIRED_CONTEXT_SUMMARY_FIELDS:
                if field not in context_summary:
                    errors.append(f"inputs.context_summary missing field: {field}")
            status = context_summary.get("status")
            if status not in _ALLOWED_STATUS:
                errors.append(
                    "inputs.context_summary.status must be one of "
                    f"{sorted(_ALLOWED_STATUS)}"
                )
            for field in ("active_count", "stale_count", "unknown_count"):
                if field in context_summary:
                    errors.extend(
                        _validate_non_negative_int(
                            context_summary,
                            field,
                        )
                    )

        context_policy = inputs.get("context_policy")
        if not isinstance(context_policy, Mapping):
            errors.append("inputs.context_policy must be a mapping")
        else:
            unknown_policy = context_policy.get("unknown_last_logon_is_active")
            if not isinstance(unknown_policy, bool):
                errors.append(
                    "inputs.context_policy.unknown_last_logon_is_active must be a bool"
                )

    derived = payload.get("derived")
    if not isinstance(derived, Mapping):
        errors.append("derived must be a mapping")
    else:
        for field in _REQUIRED_DERIVED_FIELDS:
            if field not in derived:
                errors.append(f"derived missing field: {field}")
        if derived.get("path_pressure") not in _ALLOWED_PATH_PRESSURE:
            errors.append(
                f"derived.path_pressure must be one of {sorted(_ALLOWED_PATH_PRESSURE)}"
            )
        if derived.get("value_pressure") not in _ALLOWED_VALUE_PRESSURE:
            errors.append(
                f"derived.value_pressure must be one of {sorted(_ALLOWED_VALUE_PRESSURE)}"
            )
        if derived.get("attacker_usefulness") not in _ALLOWED_ATTACKER_USEFULNESS:
            errors.append(
                "derived.attacker_usefulness must be one of "
                f"{sorted(_ALLOWED_ATTACKER_USEFULNESS)}"
            )

        confidence = derived.get("confidence")
        if not isinstance(confidence, (int, float)):
            errors.append("derived.confidence must be numeric")
        elif confidence < 0.0 or confidence > 1.0:
            errors.append("derived.confidence must be in [0.0, 1.0]")

        explanation = derived.get("explanation")
        if not isinstance(explanation, list):
            errors.append("derived.explanation must be a list")
        else:
            for index, row in enumerate(explanation):
                if not isinstance(row, str) or not row.strip():
                    errors.append(f"derived.explanation[{index}] must be a non-empty string")

    deferred = payload.get("deferred_reasoning")
    if not isinstance(deferred, Mapping):
        errors.append("deferred_reasoning must be a mapping")
    else:
        for field in _REQUIRED_DEFERRED_FIELDS:
            if deferred.get(field) is not True:
                errors.append(f"deferred_reasoning missing true flag: {field}")

    return errors


def is_delegation_reasoning_output(payload: Mapping[str, Any] | Any) -> bool:
    return validate_delegation_reasoning_output(payload) == []


__all__ = [
    "DELEGATION_REASONING_REQUIRED_WICKETS",
    "DELEGATION_REASONING_SCHEMA",
    "DELEGATION_REASONING_SLICE",
    "is_delegation_reasoning_output",
    "validate_delegation_reasoning_output",
]
