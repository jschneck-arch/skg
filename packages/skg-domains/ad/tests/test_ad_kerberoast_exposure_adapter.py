from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_kerberoast_exposure.run import (
    map_kerberoast_exposure_to_events,
)


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_kerberoast_exposure_to_events_emits_realized_wickets() -> None:
    inventory = json.loads((FIXTURES / "ad_kerberoast_exposure_inventory.json").read_text(encoding="utf-8"))

    events = map_kerberoast_exposure_to_events(
        inventory,
        attack_path_id="ad_kerberoast_exposure_baseline_v1",
        run_id="run-ad-kr-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-KR-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-KR-02"]["payload"]["status"] == "realized"
    assert all(event.get("type") == "obs.attack.precondition" for event in events)


def test_map_kerberoast_exposure_to_events_blocks_rc4_when_only_aes() -> None:
    events = map_kerberoast_exposure_to_events(
        {
            "users": [
                {
                    "Properties": {
                        "name": "svc_aes@EXAMPLE.LOCAL",
                        "enabled": True,
                        "hasspn": True,
                        "supportedencryptiontypes": 16,
                    }
                }
            ]
        },
        attack_path_id="ad_kerberoast_exposure_baseline_v1",
        run_id="run-ad-kr-2",
        workload_id="ad::example.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-KR-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-KR-02"]["payload"]["status"] == "blocked"


def test_map_kerberoast_exposure_to_events_unknown_when_unobserved() -> None:
    events = map_kerberoast_exposure_to_events(
        {},
        attack_path_id="ad_kerberoast_exposure_baseline_v1",
        run_id="run-ad-kr-3",
        workload_id="ad::unknown.local",
    )
    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-KR-01"]["payload"]["status"] == "unknown"
    assert by_wicket["AD-KR-02"]["payload"]["status"] == "unknown"
