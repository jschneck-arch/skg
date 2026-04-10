from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_credential_hints.run import map_credential_hints_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_credential_hints_to_events_emits_expected_wickets() -> None:
    inventory = json.loads((FIXTURES / "ad_credential_hint_inventory.json").read_text(encoding="utf-8"))

    events = map_credential_hints_to_events(
        inventory,
        attack_path_id="ad_password_hint_exposure_v1",
        run_id="run-ad-cred-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-CH-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-CH-02"]["payload"]["status"] == "realized"

    hint_rows = by_wicket["AD-CH-01"]["payload"]["attributes"]["credential_hints"]
    assert any(str(row.get("name")) == "svc_sql@CONTOSO.LOCAL" for row in hint_rows)
    assert all(event.get("type") == "obs.attack.precondition" for event in events)


def test_map_credential_hints_to_events_returns_unknown_enabled_human_when_no_hints() -> None:
    events = map_credential_hints_to_events(
        {
            "users": [{"Properties": {"name": "alice@CONTOSO.LOCAL", "enabled": True, "description": ""}}],
            "computers": [],
        },
        attack_path_id="ad_password_hint_exposure_v1",
        run_id="run-ad-cred-2",
        workload_id="ad::contoso.local",
    )
    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-CH-01"]["payload"]["status"] == "blocked"
    assert by_wicket["AD-CH-02"]["payload"]["status"] == "unknown"
