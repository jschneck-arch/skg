from __future__ import annotations

from typing import Any, Mapping


AD_DELEGATION_INPUT_SCHEMA = "skg.ad.delegation_input.v1"
AD_DELEGATION_INPUT_FILENAME = "ad_delegation_input.json"
AD_DELEGATION_INPUT_WICKET_IDS = ("AD-06", "AD-08")

_REQUIRED_TOP_LEVEL_FIELDS = (
    "schema",
    "slice",
    "source_kind",
    "workload_id",
    "run_id",
    "observed_at",
    "wicket_ids",
    "principal_rows",
    "unconstrained_non_dc_hosts",
    "protocol_transition_principals",
    "delegation_spn_edges",
    "summary",
    "deferred_coupling",
)

_REQUIRED_SUMMARY_FIELDS = (
    "status",
    "principal_count",
    "unconstrained_non_dc_count",
    "protocol_transition_count",
    "delegation_spn_edge_count",
)

_REQUIRED_DEFERRED_FLAGS = (
    "ad07_context_deferred",
    "ad09_sensitive_target_deferred",
    "path_value_reasoning_deferred",
)


def _validate_list_of_mappings(value: Any, field_name: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, list):
        return [f"{field_name} must be a list"]
    for index, row in enumerate(value):
        if not isinstance(row, Mapping):
            errors.append(f"{field_name}[{index}] must be a mapping")
    return errors


def validate_ad_delegation_input(payload: Mapping[str, Any] | Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ["ad_delegation_input must be a mapping"]

    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        if field not in payload:
            errors.append(f"missing field: {field}")

    schema = str(payload.get("schema") or "")
    if schema != AD_DELEGATION_INPUT_SCHEMA:
        errors.append(
            f"invalid schema: expected '{AD_DELEGATION_INPUT_SCHEMA}', got '{schema or 'missing'}'"
        )

    wicket_ids = payload.get("wicket_ids")
    if not isinstance(wicket_ids, list):
        errors.append("wicket_ids must be a list")
    else:
        observed = tuple(str(item) for item in wicket_ids)
        if observed != AD_DELEGATION_INPUT_WICKET_IDS:
            errors.append(
                "invalid wicket_ids: expected "
                f"{list(AD_DELEGATION_INPUT_WICKET_IDS)}, got {list(observed)}"
            )

    errors.extend(_validate_list_of_mappings(payload.get("principal_rows"), "principal_rows"))
    errors.extend(
        _validate_list_of_mappings(
            payload.get("unconstrained_non_dc_hosts"),
            "unconstrained_non_dc_hosts",
        )
    )
    errors.extend(
        _validate_list_of_mappings(
            payload.get("protocol_transition_principals"),
            "protocol_transition_principals",
        )
    )
    errors.extend(
        _validate_list_of_mappings(payload.get("delegation_spn_edges"), "delegation_spn_edges")
    )

    summary = payload.get("summary")
    if not isinstance(summary, Mapping):
        errors.append("summary must be a mapping")
    else:
        for field in _REQUIRED_SUMMARY_FIELDS:
            if field not in summary:
                errors.append(f"summary missing field: {field}")

    deferred_coupling = payload.get("deferred_coupling")
    if not isinstance(deferred_coupling, Mapping):
        errors.append("deferred_coupling must be a mapping")
    else:
        for flag in _REQUIRED_DEFERRED_FLAGS:
            if deferred_coupling.get(flag) is not True:
                errors.append(f"deferred_coupling missing true flag: {flag}")

    return errors


def is_ad_delegation_input(payload: Mapping[str, Any] | Any) -> bool:
    return validate_ad_delegation_input(payload) == []


__all__ = [
    "AD_DELEGATION_INPUT_FILENAME",
    "AD_DELEGATION_INPUT_SCHEMA",
    "AD_DELEGATION_INPUT_WICKET_IDS",
    "is_ad_delegation_input",
    "validate_ad_delegation_input",
]
