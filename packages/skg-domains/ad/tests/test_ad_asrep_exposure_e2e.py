from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_asrep_exposure.run import map_asrep_exposure_to_events
from skg_domain_ad.projectors.ad.run import compute_ad, project_events_to_artifact


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"


def test_ad_asrep_exposure_adapter_to_projector_e2e(tmp_path: Path) -> None:
    inventory = json.loads((FIXTURES / "ad_asrep_exposure_inventory.json").read_text(encoding="utf-8"))
    events = map_asrep_exposure_to_events(
        inventory,
        attack_path_id="ad_asrep_exposure_baseline_v1",
        run_id="run-ad-asrep-e2e",
        workload_id="ad::contoso.local",
    )

    out_path = tmp_path / "interp" / "ad_asrep_exposure_baseline.json"
    result = project_events_to_artifact(
        events,
        attack_path_id="ad_asrep_exposure_baseline_v1",
        out_path=out_path,
        run_id="run-ad-asrep-e2e",
        workload_id="ad::contoso.local",
    )

    assert out_path.exists()
    payload = result.get("payload", {})
    assert payload.get("classification") == "realized"
    assert payload.get("ad_score") == 1.0

    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written.get("payload", {}).get("classification") == "realized"


def test_ad_asrep_projection_not_realized_when_no_asrep_accounts() -> None:
    events = map_asrep_exposure_to_events(
        {
            "users": [
                {
                    "Properties": {
                        "name": "sam@EXAMPLE.LOCAL",
                        "enabled": True,
                        "dontreqpreauth": False,
                    }
                }
            ]
        },
        attack_path_id="ad_asrep_exposure_baseline_v1",
        run_id="run-ad-asrep-none",
        workload_id="ad::example.local",
    )

    result = compute_ad(
        events,
        {},
        "ad_asrep_exposure_baseline_v1",
        run_id="run-ad-asrep-none",
        workload_id="ad::example.local",
    )
    assert result.get("payload", {}).get("classification") == "not_realized"
