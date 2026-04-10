from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_tiering_posture.run import (
    map_tiering_posture_file_to_events,
    map_tiering_posture_to_events,
)
from skg_domain_ad.projectors.ad.run import compute_ad, project_events_to_artifact


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_ad_tiering_posture_adapter_to_projector_e2e(tmp_path: Path) -> None:
    input_path = FIXTURES / "ad_tiering_posture_input.json"

    events = map_tiering_posture_file_to_events(
        input_path,
        attack_path_id="ad_privileged_session_tiering_baseline_v1",
        run_id="run-ad-tiering-e2e",
        workload_id="ad::contoso.local",
    )

    out_path = tmp_path / "interp" / "ad_tiering_posture_baseline.json"
    result = project_events_to_artifact(
        events,
        attack_path_id="ad_privileged_session_tiering_baseline_v1",
        out_path=out_path,
        run_id="run-ad-tiering-e2e",
        workload_id="ad::contoso.local",
    )

    assert out_path.exists()
    payload = result.get("payload", {})
    assert payload.get("classification") == "realized"
    assert payload.get("ad_score") == 1.0

    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written.get("payload", {}).get("classification") == "realized"


def test_ad_tiering_posture_projection_not_realized_when_ad22_is_blocked() -> None:
    events = map_tiering_posture_to_events(
        {
            "schema": "skg.ad.tiering_input.v1",
            "wicket_id": "AD-22",
            "slice": "ad22_baseline_tiering_core_input",
            "source_kind": "bloodhound.sessions",
            "workload_id": "ad::contoso.local",
            "run_id": "run-ad-tiering-clean",
            "observed_at": "2026-04-03T00:00:00+00:00",
            "computer_inventory_count": 1,
            "summary": {
                "status": "blocked",
                "observed_session_count": 1,
                "non_tier0_session_count": 0,
                "tier0_session_count": 1,
                "unknown_tier_session_count": 0,
            },
            "session_rows": [{"computer": "DC01.CONTOSO.LOCAL", "user": "DA@CONTOSO.LOCAL"}],
        },
        attack_path_id="ad_privileged_session_tiering_baseline_v1",
        run_id="run-ad-tiering-clean",
        workload_id="ad::contoso.local",
    )

    result = compute_ad(
        events,
        {},
        "ad_privileged_session_tiering_baseline_v1",
        run_id="run-ad-tiering-clean",
        workload_id="ad::contoso.local",
    )
    assert result.get("payload", {}).get("classification") == "not_realized"
