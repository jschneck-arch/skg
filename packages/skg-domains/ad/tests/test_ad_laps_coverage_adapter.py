from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_laps_coverage.run import map_laps_coverage_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_laps_coverage_to_events_emits_realized_when_no_laps_present() -> None:
    inventory = json.loads((FIXTURES / "ad_laps_coverage_inventory.json").read_text(encoding="utf-8"))

    events = map_laps_coverage_to_events(
        inventory,
        attack_path_id="ad_laps_coverage_baseline_v1",
        run_id="run-ad-laps-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-LP-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-LP-02"]["payload"]["status"] == "realized"
    assert all(event.get("type") == "obs.attack.precondition" for event in events)


def test_map_laps_coverage_to_events_emits_blocked_when_all_observed_have_laps() -> None:
    events = map_laps_coverage_to_events(
        {
            "computers": [
                {
                    "Properties": {
                        "name": "WS10.EXAMPLE.LOCAL",
                        "enabled": True,
                        "isdc": False,
                        "haslaps": True,
                    }
                },
                {
                    "attributes": {
                        "dNSHostName": "WS11.EXAMPLE.LOCAL",
                        "enabled": True,
                        "isdc": False,
                        "msLAPS-Password": "present",
                    }
                },
            ]
        },
        attack_path_id="ad_laps_coverage_baseline_v1",
        run_id="run-ad-laps-2",
        workload_id="ad::example.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-LP-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-LP-02"]["payload"]["status"] == "blocked"


def test_map_laps_coverage_to_events_emits_unknown_when_unobserved_or_indeterminate() -> None:
    events_unobserved = map_laps_coverage_to_events(
        {},
        attack_path_id="ad_laps_coverage_baseline_v1",
        run_id="run-ad-laps-3",
        workload_id="ad::unknown.local",
    )
    by_wicket_unobserved = {event.get("payload", {}).get("wicket_id"): event for event in events_unobserved}
    assert by_wicket_unobserved["AD-LP-01"]["payload"]["status"] == "unknown"
    assert by_wicket_unobserved["AD-LP-02"]["payload"]["status"] == "unknown"

    events_indeterminate = map_laps_coverage_to_events(
        {
            "computers": [
                {
                    "Properties": {
                        "name": "WS12.EXAMPLE.LOCAL",
                        "enabled": True,
                        "isdc": False,
                    }
                }
            ]
        },
        attack_path_id="ad_laps_coverage_baseline_v1",
        run_id="run-ad-laps-4",
        workload_id="ad::example.local",
    )
    by_wicket_indeterminate = {event.get("payload", {}).get("wicket_id"): event for event in events_indeterminate}
    assert by_wicket_indeterminate["AD-LP-01"]["payload"]["status"] == "realized"
    assert by_wicket_indeterminate["AD-LP-02"]["payload"]["status"] == "unknown"
