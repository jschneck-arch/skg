from __future__ import annotations

from typing import Any, Mapping


AD_TIERING_INPUT_SCHEMA = "skg.ad.tiering_input.v1"
AD_TIERING_INPUT_FILENAME = "ad22_tiering_input.json"
AD_TIERING_INPUT_WICKET_ID = "AD-22"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "schema",
    "wicket_id",
    "slice",
    "source_kind",
    "workload_id",
    "run_id",
    "observed_at",
    "session_rows",
    "computer_inventory_count",
    "summary",
)

_REQUIRED_SUMMARY_FIELDS = (
    "status",
    "observed_session_count",
    "non_tier0_session_count",
    "tier0_session_count",
    "unknown_tier_session_count",
)


def validate_ad_tiering_input(payload: Mapping[str, Any] | Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ["ad_tiering_input must be a mapping"]

    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        if field not in payload:
            errors.append(f"missing field: {field}")

    schema = str(payload.get("schema") or "")
    if schema != AD_TIERING_INPUT_SCHEMA:
        errors.append(
            f"invalid schema: expected '{AD_TIERING_INPUT_SCHEMA}', got '{schema or 'missing'}'"
        )

    wicket_id = str(payload.get("wicket_id") or "")
    if wicket_id != AD_TIERING_INPUT_WICKET_ID:
        errors.append(
            f"invalid wicket_id: expected '{AD_TIERING_INPUT_WICKET_ID}', got '{wicket_id or 'missing'}'"
        )

    session_rows = payload.get("session_rows")
    if session_rows is not None and not isinstance(session_rows, list):
        errors.append("session_rows must be a list")
    elif isinstance(session_rows, list):
        for idx, row in enumerate(session_rows):
            if not isinstance(row, Mapping):
                errors.append(f"session_rows[{idx}] must be a mapping")

    summary = payload.get("summary")
    if summary is not None and not isinstance(summary, Mapping):
        errors.append("summary must be a mapping")
    elif isinstance(summary, Mapping):
        for field in _REQUIRED_SUMMARY_FIELDS:
            if field not in summary:
                errors.append(f"summary missing field: {field}")

    return errors


def is_ad_tiering_input(payload: Mapping[str, Any] | Any) -> bool:
    return validate_ad_tiering_input(payload) == []


__all__ = [
    "AD_TIERING_INPUT_FILENAME",
    "AD_TIERING_INPUT_SCHEMA",
    "AD_TIERING_INPUT_WICKET_ID",
    "is_ad_tiering_input",
    "validate_ad_tiering_input",
]
