from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_privileged_membership.run import (
    map_privileged_memberships_to_events,
)


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_privileged_memberships_to_events_emits_canonical_ad_wickets() -> None:
    inventory = json.loads((FIXTURES / "ad_privileged_membership_inventory.json").read_text(encoding="utf-8"))

    events = map_privileged_memberships_to_events(
        inventory,
        attack_path_id="ad_privilege_relationship_mapping_v1",
        run_id="run-ad-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}

    assert by_wicket["AD-PR-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-PR-02"]["payload"]["status"] == "realized"
    assert by_wicket["AD-PR-03"]["payload"]["status"] == "realized"

    assert all(event.get("type") == "obs.attack.precondition" for event in events)
    assert all(event.get("source", {}).get("toolchain") == "ad" for event in events)


def test_map_privileged_memberships_handles_missing_privileged_groups() -> None:
    events = map_privileged_memberships_to_events(
        {"users": [], "groups": [{"Properties": {"name": "HELPDESK"}, "Members": []}]},
        attack_path_id="ad_privilege_relationship_mapping_v1",
        run_id="run-ad-2",
        workload_id="ad::example.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-PR-01"]["payload"]["status"] == "blocked"
    assert by_wicket["AD-PR-02"]["payload"]["status"] == "unknown"
    assert by_wicket["AD-PR-03"]["payload"]["status"] == "unknown"
