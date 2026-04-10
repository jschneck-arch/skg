from __future__ import annotations

from skg_protocol.contracts import (
    AD_TIERING_INPUT_FILENAME,
    AD_TIERING_INPUT_SCHEMA,
    AD_TIERING_INPUT_WICKET_ID,
    is_ad_tiering_input,
    validate_ad_tiering_input,
)


def test_validate_ad_tiering_input_accepts_canonical_payload() -> None:
    payload = {
        "schema": AD_TIERING_INPUT_SCHEMA,
        "wicket_id": AD_TIERING_INPUT_WICKET_ID,
        "slice": "ad22_baseline_tiering_core_input",
        "source_kind": "bloodhound.sessions",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad-tiering-contract",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "session_rows": [{"computer": "WS01.CONTOSO.LOCAL", "user": "DA@CONTOSO.LOCAL"}],
        "computer_inventory_count": 1,
        "summary": {
            "status": "realized",
            "observed_session_count": 1,
            "non_tier0_session_count": 1,
            "tier0_session_count": 0,
            "unknown_tier_session_count": 0,
        },
    }

    assert validate_ad_tiering_input(payload) == []
    assert is_ad_tiering_input(payload) is True
    assert AD_TIERING_INPUT_FILENAME == "ad22_tiering_input.json"


def test_validate_ad_tiering_input_rejects_wrong_schema_and_missing_summary_fields() -> None:
    payload = {
        "schema": "skg.ad.tiering_input.v0",
        "wicket_id": AD_TIERING_INPUT_WICKET_ID,
        "slice": "ad22_baseline_tiering_core_input",
        "source_kind": "bloodhound.sessions",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad-tiering-contract",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "session_rows": [],
        "computer_inventory_count": 0,
        "summary": {
            "status": "unknown",
        },
    }

    errors = validate_ad_tiering_input(payload)
    assert any("invalid schema" in error for error in errors)
    assert any("summary missing field: observed_session_count" in error for error in errors)
    assert is_ad_tiering_input(payload) is False
