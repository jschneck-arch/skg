from __future__ import annotations

import json
from pathlib import Path

from skg_domain_web.adapters.web_surface_fingerprint.run import map_surface_profile_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_web" / "fixtures"


def test_surface_fingerprint_maps_phase1_signals_to_wickets() -> None:
    profile = json.loads((FIXTURES / "web_surface_profile.json").read_text(encoding="utf-8"))

    events = map_surface_profile_to_events(
        profile,
        attack_path_id="web_initial_access_v1",
        run_id="run-surface-1",
        workload_id="web::demo.local",
    )

    by_wicket = {event["payload"]["wicket_id"]: event for event in events}

    assert by_wicket["WB-01"]["payload"]["status"] == "realized"
    assert by_wicket["WB-02"]["payload"]["status"] == "realized"
    assert by_wicket["WB-19"]["payload"]["status"] == "realized"
    assert by_wicket["WB-18"]["payload"]["status"] == "realized"
    assert by_wicket["WB-17"]["payload"]["status"] == "blocked"

    assert all(event.get("type") == "obs.attack.precondition" for event in events)
    assert all(event.get("source", {}).get("toolchain") == "skg-web-toolchain" for event in events)


def test_surface_fingerprint_marks_plain_http_as_tls_risk() -> None:
    profile = {
        "base_url": "http://demo.local",
        "scheme": "http",
        "host": "demo.local",
        "port": 80,
        "reachable": True,
        "response_headers": {},
    }

    events = map_surface_profile_to_events(
        profile,
        attack_path_id="web_surface_v1",
        run_id="run-surface-http",
        workload_id="web::demo.local",
    )

    wb17 = next(event for event in events if event["payload"]["wicket_id"] == "WB-17")
    assert wb17["payload"]["status"] == "realized"
    assert "plain HTTP" in wb17["payload"]["detail"]
