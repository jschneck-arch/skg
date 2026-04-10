from __future__ import annotations

import json
from pathlib import Path

from skg_domain_web.adapters.web_path_inventory.run import map_findings_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_web" / "fixtures"


def test_map_findings_to_events_emits_canonical_web_wickets() -> None:
    findings = json.loads((FIXTURES / "web_path_findings.json").read_text(encoding="utf-8"))

    events = map_findings_to_events(
        findings,
        attack_path_id="web_initial_access_v1",
        run_id="run-web-1",
        workload_id="web::demo.local",
    )

    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}

    assert "WB-01" in wicket_ids
    assert "WB-05" in wicket_ids
    assert "WB-09" in wicket_ids
    assert all(event.get("type") == "obs.attack.precondition" for event in events)
    assert all(event.get("source", {}).get("toolchain") == "skg-web-toolchain" for event in events)
