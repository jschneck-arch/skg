from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_delegation_posture.run import (
    map_delegation_posture_file_to_events,
    map_delegation_posture_to_events,
)
from skg_domain_ad.projectors.ad.run import compute_ad, project_events_to_artifact


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_ad_delegation_posture_adapter_to_projector_e2e(tmp_path: Path) -> None:
    input_path = FIXTURES / "ad_delegation_posture_input.json"

    events = map_delegation_posture_file_to_events(
        input_path,
        attack_path_id="ad_delegation_posture_baseline_v1",
        run_id="run-ad-delegation-e2e",
        workload_id="ad::contoso.local",
    )

    out_path = tmp_path / "interp" / "ad_delegation_posture_baseline.json"
    result = project_events_to_artifact(
        events,
        attack_path_id="ad_delegation_posture_baseline_v1",
        out_path=out_path,
        run_id="run-ad-delegation-e2e",
        workload_id="ad::contoso.local",
    )

    assert out_path.exists()
    payload = result.get("payload", {})
    assert payload.get("classification") == "realized"
    assert payload.get("ad_score") == 1.0

    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written.get("payload", {}).get("classification") == "realized"


def test_ad_delegation_posture_projection_not_realized_when_ad08_is_blocked() -> None:
    events = map_delegation_posture_to_events(
        {
            "schema": "skg.ad.delegation_input.v1",
            "slice": "ad06_ad08_delegation_posture_core_input",
            "source_kind": "bloodhound.delegation",
            "workload_id": "ad::contoso.local",
            "run_id": "run-ad-delegation-clean",
            "observed_at": "2026-04-03T00:00:00+00:00",
            "wicket_ids": ["AD-06", "AD-08"],
            "principal_rows": [{"name": "WS11.CONTOSO.LOCAL"}],
            "unconstrained_non_dc_hosts": [{"name": "WS11.CONTOSO.LOCAL"}],
            "protocol_transition_principals": [],
            "delegation_spn_edges": [],
            "summary": {
                "status": "blocked",
                "principal_count": 1,
                "unconstrained_non_dc_count": 1,
                "protocol_transition_count": 0,
                "delegation_spn_edge_count": 0,
            },
            "deferred_coupling": {
                "ad07_context_deferred": True,
                "ad09_sensitive_target_deferred": True,
                "path_value_reasoning_deferred": True,
            },
        },
        attack_path_id="ad_delegation_posture_baseline_v1",
        run_id="run-ad-delegation-clean",
        workload_id="ad::contoso.local",
    )

    result = compute_ad(
        events,
        {},
        "ad_delegation_posture_baseline_v1",
        run_id="run-ad-delegation-clean",
        workload_id="ad::contoso.local",
    )
    assert result.get("payload", {}).get("classification") == "not_realized"
