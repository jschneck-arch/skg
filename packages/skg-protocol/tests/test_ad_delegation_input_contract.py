from __future__ import annotations

from skg_protocol.contracts import (
    AD_DELEGATION_INPUT_FILENAME,
    AD_DELEGATION_INPUT_SCHEMA,
    AD_DELEGATION_INPUT_WICKET_IDS,
    is_ad_delegation_input,
    validate_ad_delegation_input,
)


def test_validate_ad_delegation_input_accepts_canonical_payload() -> None:
    payload = {
        "schema": AD_DELEGATION_INPUT_SCHEMA,
        "slice": "ad06_ad08_delegation_posture_core_input",
        "source_kind": "bloodhound.delegation",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad-delegation-contract",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "wicket_ids": list(AD_DELEGATION_INPUT_WICKET_IDS),
        "principal_rows": [{"name": "WS01.CONTOSO.LOCAL"}],
        "unconstrained_non_dc_hosts": [{"name": "WS01.CONTOSO.LOCAL"}],
        "protocol_transition_principals": [{"name": "APP01$"}],
        "delegation_spn_edges": [{"account": "APP01$", "service": "ldap"}],
        "summary": {
            "status": "realized",
            "principal_count": 1,
            "unconstrained_non_dc_count": 1,
            "protocol_transition_count": 1,
            "delegation_spn_edge_count": 1,
        },
        "deferred_coupling": {
            "ad07_context_deferred": True,
            "ad09_sensitive_target_deferred": True,
            "path_value_reasoning_deferred": True,
        },
    }

    assert validate_ad_delegation_input(payload) == []
    assert is_ad_delegation_input(payload) is True
    assert AD_DELEGATION_INPUT_FILENAME == "ad_delegation_input.json"


def test_validate_ad_delegation_input_rejects_ad07_ad09_wicket_coupling() -> None:
    payload = {
        "schema": AD_DELEGATION_INPUT_SCHEMA,
        "slice": "ad06_ad08_delegation_posture_core_input",
        "source_kind": "bloodhound.delegation",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad-delegation-contract",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "wicket_ids": ["AD-06", "AD-07", "AD-08", "AD-09"],
        "principal_rows": [],
        "unconstrained_non_dc_hosts": [],
        "protocol_transition_principals": [],
        "delegation_spn_edges": [],
        "summary": {
            "status": "unknown",
            "principal_count": 0,
            "unconstrained_non_dc_count": 0,
            "protocol_transition_count": 0,
            "delegation_spn_edge_count": 0,
        },
        "deferred_coupling": {
            "ad07_context_deferred": False,
            "ad09_sensitive_target_deferred": True,
            "path_value_reasoning_deferred": False,
        },
    }

    errors = validate_ad_delegation_input(payload)
    assert any("invalid wicket_ids" in error for error in errors)
    assert any("deferred_coupling missing true flag: ad07_context_deferred" in error for error in errors)
    assert any(
        "deferred_coupling missing true flag: path_value_reasoning_deferred" in error
        for error in errors
    )
    assert is_ad_delegation_input(payload) is False
