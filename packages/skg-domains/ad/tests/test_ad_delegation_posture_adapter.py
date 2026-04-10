from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_delegation_posture.run import (
    map_delegation_posture_file_to_events,
    map_delegation_posture_to_events,
)


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_map_delegation_posture_to_events_emits_realized_for_ad06_and_ad08() -> None:
    payload = json.loads((FIXTURES / "ad_delegation_posture_input.json").read_text(encoding="utf-8"))

    events = map_delegation_posture_to_events(
        payload,
        attack_path_id="ad_delegation_posture_baseline_v1",
        run_id="run-ad-dg-1",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-06"]["payload"]["status"] == "realized"
    assert by_wicket["AD-08"]["payload"]["status"] == "realized"


def test_map_delegation_posture_to_events_emits_blocked_when_principals_observed_without_posture_hits() -> None:
    payload = {
        "schema": "skg.ad.delegation_input.v1",
        "slice": "ad06_ad08_delegation_posture_core_input",
        "source_kind": "bloodhound.delegation",
        "workload_id": "ad::contoso.local",
        "run_id": "run-ad-dg-2",
        "observed_at": "2026-04-03T00:00:00+00:00",
        "wicket_ids": ["AD-06", "AD-08"],
        "principal_rows": [{"name": "WS11.CONTOSO.LOCAL"}],
        "unconstrained_non_dc_hosts": [],
        "protocol_transition_principals": [],
        "delegation_spn_edges": [],
        "summary": {
            "status": "blocked",
            "principal_count": 1,
            "unconstrained_non_dc_count": 0,
            "protocol_transition_count": 0,
            "delegation_spn_edge_count": 0,
        },
        "deferred_coupling": {
            "ad07_context_deferred": True,
            "ad09_sensitive_target_deferred": True,
            "path_value_reasoning_deferred": True,
        },
    }

    events = map_delegation_posture_to_events(
        payload,
        attack_path_id="ad_delegation_posture_baseline_v1",
        run_id="run-ad-dg-2",
        workload_id="ad::contoso.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-06"]["payload"]["status"] == "blocked"
    assert by_wicket["AD-08"]["payload"]["status"] == "blocked"


def test_map_delegation_posture_file_to_events_emits_unknown_when_sidecar_schema_is_invalid(
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "ad_delegation_invalid_schema.json"
    payload_path.write_text(
        json.dumps(
            {
                "schema": "skg.ad.delegation_input.v0",
                "wicket_ids": ["AD-06", "AD-08"],
                "summary": {"principal_count": 1},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    events = map_delegation_posture_file_to_events(
        payload_path,
        attack_path_id="ad_delegation_posture_baseline_v1",
        run_id="run-ad-dg-3",
        workload_id="ad::unknown.local",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["AD-06"]["payload"]["status"] == "unknown"
    assert by_wicket["AD-08"]["payload"]["status"] == "unknown"
