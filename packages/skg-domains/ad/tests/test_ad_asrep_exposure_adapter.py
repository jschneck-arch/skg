from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_asrep_exposure.run import map_asrep_exposure_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_asrep_exposure_to_events_emits_realized_when_asrep_accounts_present() -> None:
    inventory = json.loads((FIXTURES / "ad_asrep_exposure_inventory.json").read_text(encoding="utf-8"))

    events = map_asrep_exposure_to_events(
        inventory,
        attack_path_id="ad_asrep_exposure_baseline_v1",
        run_id="run-ad-asrep-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-AS-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-AS-02"]["payload"]["status"] == "realized"
    assert all(event.get("type") == "obs.attack.precondition" for event in events)


def test_map_asrep_exposure_to_events_emits_blocked_when_observed_but_none_exposed() -> None:
    events = map_asrep_exposure_to_events(
        {
            "users": [
                {
                    "Properties": {
                        "name": "alice@EXAMPLE.LOCAL",
                        "enabled": True,
                        "dontreqpreauth": False,
                    }
                }
            ]
        },
        attack_path_id="ad_asrep_exposure_baseline_v1",
        run_id="run-ad-asrep-2",
        workload_id="ad::example.local",
    )
    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-AS-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-AS-02"]["payload"]["status"] == "blocked"


def test_map_asrep_exposure_to_events_emits_unknown_when_unobserved() -> None:
    events = map_asrep_exposure_to_events(
        {},
        attack_path_id="ad_asrep_exposure_baseline_v1",
        run_id="run-ad-asrep-3",
        workload_id="ad::unknown.local",
    )
    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-AS-01"]["payload"]["status"] == "unknown"
    assert by_wicket["AD-AS-02"]["payload"]["status"] == "unknown"
