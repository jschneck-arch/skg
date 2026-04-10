from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_tiering_posture.run import (
    map_tiering_posture_file_to_events,
    map_tiering_posture_to_events,
)


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_tiering_posture_to_events_emits_realized_for_non_tier0_privileged_sessions() -> None:
    payload = json.loads((FIXTURES / "ad_tiering_posture_input.json").read_text(encoding="utf-8"))

    events = map_tiering_posture_to_events(
        payload,
        attack_path_id="ad_privileged_session_tiering_baseline_v1",
        run_id="run-ad-ti-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-TI-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-22"]["payload"]["status"] == "realized"


def test_map_tiering_posture_to_events_emits_blocked_when_all_privileged_sessions_are_tier0() -> None:
    payload = {
        "schema": "skg.ad.tiering_input.v1",
        "wicket_id": "AD-22",
        "slice": "ad22_baseline_tiering_core_input",
        "source_kind": "bloodhound.sessions",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad-ti-2",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "computer_inventory_count": 1,
        "summary": {
            "status": "blocked",
            "observed_session_count": 2,
            "non_tier0_session_count": 0,
            "tier0_session_count": 2,
            "unknown_tier_session_count": 0,
            "non_tier0_sessions": [],
            "tier0_sessions": [{"computer": "DC01.CONTOSO.LOCAL"}],
            "unknown_tier_sessions": [],
        },
        "session_rows": [{"computer": "DC01.CONTOSO.LOCAL", "user": "DA@CONTOSO.LOCAL"}],
    }

    events = map_tiering_posture_to_events(
        payload,
        attack_path_id="ad_privileged_session_tiering_baseline_v1",
        run_id="run-ad-ti-2",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-TI-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-22"]["payload"]["status"] == "blocked"


def test_map_tiering_posture_file_to_events_emits_unknown_when_sidecar_is_missing_schema(tmp_path: Path) -> None:
    payload_path = tmp_path / "ad22_missing_schema.json"
    payload_path.write_text(json.dumps({"summary": {"observed_session_count": 1}}, indent=2), encoding="utf-8")
    events = map_tiering_posture_file_to_events(
        payload_path,
        attack_path_id="ad_privileged_session_tiering_baseline_v1",
        run_id="run-ad-ti-3",
        workload_id="ad::unknown.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-TI-01"]["payload"]["status"] == "unknown"
    assert by_wicket["AD-22"]["payload"]["status"] == "unknown"
