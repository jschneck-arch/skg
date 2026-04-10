from __future__ import annotations

from skg_domain_web.adapters.web_auth_assessment.run import map_auth_assessment_to_events


def test_auth_assessment_realized_for_default_credentials() -> None:
    events = map_auth_assessment_to_events(
        {
            "auth_attempted": True,
            "authenticated": True,
            "username": "admin",
            "used_default_credential": True,
            "detail": "Default credential accepted for admin",
        },
        attack_path_id="web_sqli_to_shell_v1",
        run_id="rid-auth-realized",
        workload_id="web::demo.local",
    )

    assert len(events) == 1
    event = events[0]
    assert event["type"] == "obs.attack.precondition"
    assert event["payload"]["wicket_id"] == "WB-10"
    assert event["payload"]["status"] == "realized"


def test_auth_assessment_blocked_for_non_default_auth() -> None:
    events = map_auth_assessment_to_events(
        {
            "auth_attempted": True,
            "authenticated": True,
            "username": "operator",
            "used_default_credential": False,
            "detail": "Authentication succeeded with non-default credentials",
        },
        attack_path_id="web_sqli_to_shell_v1",
        run_id="rid-auth-blocked",
        workload_id="web::demo.local",
    )

    assert len(events) == 1
    event = events[0]
    assert event["payload"]["wicket_id"] == "WB-10"
    assert event["payload"]["status"] == "blocked"
