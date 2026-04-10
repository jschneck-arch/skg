from __future__ import annotations

from skg_protocol.contracts import (
    AD_DELEGATION_CONTEXT_FILENAME,
    AD_DELEGATION_CONTEXT_SCHEMA,
    AD_DELEGATION_CONTEXT_WICKET_ID,
    is_ad_delegation_context,
    validate_ad_delegation_context,
)


def test_validate_ad_delegation_context_accepts_canonical_payload() -> None:
    payload = {
        "schema": AD_DELEGATION_CONTEXT_SCHEMA,
        "wicket_id": AD_DELEGATION_CONTEXT_WICKET_ID,
        "slice": "ad07_delegation_context_service_input",
        "source_kind": "bloodhound.delegation_context",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad07-contract",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "recency_policy": {
            "stale_days": 90,
            "stale_threshold_seconds": 7776000,
        },
        "unknown_handling_policy": {
            "unknown_last_logon_is_active": True,
        },
        "activity_classification": {
            "total_unconstrained_non_dc": 2,
            "active_unconstrained": [
                {"name": "WS01.CONTOSO.LOCAL", "activity_state": "recent", "age_seconds": 100.0}
            ],
            "stale_unconstrained": [
                {"name": "WS02.CONTOSO.LOCAL", "activity_state": "stale", "age_seconds": 999999.0}
            ],
            "unknown_last_logon": [
                {"name": "WS03.CONTOSO.LOCAL", "activity_state": "unknown", "age_seconds": None}
            ],
        },
        "summary": {
            "status": "realized",
            "active_count": 1,
            "stale_count": 1,
            "unknown_count": 1,
        },
    }

    assert validate_ad_delegation_context(payload) == []
    assert is_ad_delegation_context(payload) is True
    assert AD_DELEGATION_CONTEXT_FILENAME == "ad07_delegation_context.json"


def test_validate_ad_delegation_context_rejects_missing_explicit_policies() -> None:
    payload = {
        "schema": AD_DELEGATION_CONTEXT_SCHEMA,
        "wicket_id": AD_DELEGATION_CONTEXT_WICKET_ID,
        "slice": "ad07_delegation_context_service_input",
        "source_kind": "bloodhound.delegation_context",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad07-contract",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "recency_policy": {
            "stale_days": 90,
        },
        "unknown_handling_policy": {},
        "activity_classification": {
            "total_unconstrained_non_dc": 1,
            "active_unconstrained": [{"name": "WS01", "activity_state": "recent"}],
            "stale_unconstrained": [],
            "unknown_last_logon": [{"name": "WS02", "activity_state": "unknown"}],
        },
        "summary": {
            "status": "unknown",
            "active_count": 1,
            "stale_count": 0,
            "unknown_count": 1,
        },
    }

    errors = validate_ad_delegation_context(payload)
    assert any("recency_policy missing field: stale_threshold_seconds" in error for error in errors)
    assert any(
        "unknown_handling_policy missing field: unknown_last_logon_is_active" in error
        for error in errors
    )
    assert is_ad_delegation_context(payload) is False
