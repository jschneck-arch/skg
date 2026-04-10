from __future__ import annotations

import json
from pathlib import Path

from skg_domain_web.adapters.web_nikto_findings.run import map_nikto_findings_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_web" / "fixtures"


def test_nikto_mapping_emits_expected_wickets() -> None:
    findings = json.loads((FIXTURES / "web_nikto_findings.json").read_text(encoding="utf-8"))

    events = map_nikto_findings_to_events(
        findings,
        attack_path_id="web_surface_v1",
        run_id="run-nikto-1",
        workload_id="web::demo.local",
    )

    by_wicket = {event["payload"]["wicket_id"]: event for event in events}

    assert "WB-41" in by_wicket
    assert "WB-17" in by_wicket
    assert "WB-02" in by_wicket

    assert by_wicket["WB-41"]["payload"]["status"] == "realized"
    assert by_wicket["WB-17"]["payload"]["status"] == "realized"
    assert by_wicket["WB-02"]["payload"]["status"] == "realized"

    assert all(event.get("source", {}).get("toolchain") == "skg-web-toolchain" for event in events)
