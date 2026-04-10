from __future__ import annotations

from skg_protocol.contracts import AD_DELEGATION_CONTEXT_SCHEMA
from skg_protocol.events import build_event_envelope, build_precondition_payload
from skg_reasoning import (
    DELEGATION_REASONING_SCHEMA,
    evaluate_delegation_reasoning,
    is_delegation_reasoning_output,
)


def _ad_precondition_event(*, wicket_id: str, status: str) -> dict:
    payload = build_precondition_payload(
        wicket_id=wicket_id,
        label=wicket_id,
        domain="ad",
        workload_id="ad::contoso.local",
        status=status,
        attack_path_id="ad_delegation_posture_baseline_v1",
        detail=f"{wicket_id} status={status}",
    )
    payload["run_id"] = "run-reasoning-1"
    return build_event_envelope(
        event_type="obs.attack.precondition",
        source_id="adapter.ad_delegation_posture",
        toolchain="ad",
        payload=payload,
        evidence_rank=2,
        source_kind="ad.delegation.snapshot",
        pointer=f"ad://contoso.local/{wicket_id.lower()}",
        confidence=0.9,
    )


def _ad07_context(
    *,
    active_count: int,
    stale_count: int,
    unknown_count: int,
    status: str = "realized",
    unknown_last_logon_is_active: bool = True,
) -> dict:
    return {
        "schema": AD_DELEGATION_CONTEXT_SCHEMA,
        "wicket_id": "AD-07",
        "slice": "ad07_delegation_context_service_input",
        "source_kind": "bloodhound.delegation_context",
        "workload_id": "ad::contoso.local",
        "run_id": "run-reasoning-1",
        "observed_at": "2026-04-04T00:00:00+00:00",
        "recency_policy": {
            "stale_days": 90,
            "stale_threshold_seconds": 7776000,
        },
        "unknown_handling_policy": {
            "unknown_last_logon_is_active": unknown_last_logon_is_active,
        },
        "activity_classification": {
            "total_unconstrained_non_dc": active_count + stale_count + unknown_count,
            "active_unconstrained": [
                {"name": f"ACTIVE-{idx}", "activity_state": "recent", "age_seconds": 1000.0}
                for idx in range(active_count)
            ],
            "stale_unconstrained": [
                {"name": f"STALE-{idx}", "activity_state": "stale", "age_seconds": 9999999.0}
                for idx in range(stale_count)
            ],
            "unknown_last_logon": [
                {"name": f"UNKNOWN-{idx}", "activity_state": "unknown", "age_seconds": None}
                for idx in range(unknown_count)
            ],
        },
        "summary": {
            "status": status,
            "active_count": active_count,
            "stale_count": stale_count,
            "unknown_count": unknown_count,
        },
    }


def test_evaluate_delegation_reasoning_consumes_canonical_inputs() -> None:
    output = evaluate_delegation_reasoning(
        [
            _ad_precondition_event(wicket_id="AD-06", status="realized"),
            _ad_precondition_event(wicket_id="AD-08", status="realized"),
        ],
        _ad07_context(active_count=2, stale_count=0, unknown_count=0),
    )

    assert output["schema"] == DELEGATION_REASONING_SCHEMA
    assert output["inputs"]["canonical_wicket_status"]["AD-06"] == "realized"
    assert output["inputs"]["canonical_wicket_status"]["AD-08"] == "realized"
    assert output["inputs"]["context_schema"] == AD_DELEGATION_CONTEXT_SCHEMA
    assert output["derived"]["path_pressure"] == "high"
    assert output["derived"]["value_pressure"] == "elevated"
    assert output["derived"]["attacker_usefulness"] == "high"
    assert output["deferred_reasoning"]["ad09_sensitive_target_reasoning_deferred"] is True
    assert "events" not in output
    assert "raw_events" not in output
    assert is_delegation_reasoning_output(output) is True


def test_evaluate_delegation_reasoning_returns_low_when_posture_blocked() -> None:
    output = evaluate_delegation_reasoning(
        [
            _ad_precondition_event(wicket_id="AD-06", status="blocked"),
            _ad_precondition_event(wicket_id="AD-08", status="blocked"),
        ],
        _ad07_context(
            active_count=0,
            stale_count=0,
            unknown_count=0,
            status="blocked",
            unknown_last_logon_is_active=False,
        ),
    )

    assert output["derived"]["path_pressure"] == "low"
    assert output["derived"]["value_pressure"] == "baseline"
    assert output["derived"]["attacker_usefulness"] == "low"
    assert output["derived"]["confidence"] <= 0.9


def test_evaluate_delegation_reasoning_rejects_invalid_context_contract() -> None:
    invalid_context = {
        "schema": AD_DELEGATION_CONTEXT_SCHEMA,
        "wicket_id": "AD-07",
    }

    try:
        evaluate_delegation_reasoning([], invalid_context)
    except ValueError as exc:
        message = str(exc)
        assert "Invalid AD-07 context contract" in message
        assert "missing field:" in message
    else:
        raise AssertionError("expected ValueError for invalid AD-07 context payload")
