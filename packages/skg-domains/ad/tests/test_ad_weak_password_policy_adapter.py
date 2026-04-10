from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_weak_password_policy.run import (
    map_weak_password_policy_to_events,
)


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_weak_password_policy_to_events_emits_realized_when_weak() -> None:
    inventory = json.loads((FIXTURES / "ad_weak_password_policy_inventory.json").read_text(encoding="utf-8"))

    events = map_weak_password_policy_to_events(
        inventory,
        attack_path_id="ad_weak_password_policy_v1",
        run_id="run-ad-wp-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-WP-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-WP-02"]["payload"]["status"] == "realized"
    assert all(event.get("type") == "obs.attack.precondition" for event in events)


def test_map_weak_password_policy_to_events_emits_blocked_when_strong() -> None:
    events = map_weak_password_policy_to_events(
        {
            "domain_policy": {
                "attributes": {
                    "name": "example.local",
                    "minPwdLength": 14,
                }
            }
        },
        attack_path_id="ad_weak_password_policy_v1",
        run_id="run-ad-wp-2",
        workload_id="ad::example.local",
    )
    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-WP-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-WP-02"]["payload"]["status"] == "blocked"


def test_map_weak_password_policy_to_events_emits_unknown_when_unobserved() -> None:
    events = map_weak_password_policy_to_events(
        {},
        attack_path_id="ad_weak_password_policy_v1",
        run_id="run-ad-wp-3",
        workload_id="ad::unknown.local",
    )
    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-WP-01"]["payload"]["status"] == "unknown"
    assert by_wicket["AD-WP-02"]["payload"]["status"] == "unknown"
