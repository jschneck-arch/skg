from __future__ import annotations

import json
from pathlib import Path

from skg_domain_host.adapters.host_winrm_assessment.run import map_winrm_assessments_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_host" / "fixtures"


def test_map_winrm_assessments_to_events_emits_connectivity_auth_and_admin_wickets() -> None:
    assessments = json.loads((FIXTURES / "host_winrm_assessment.json").read_text(encoding="utf-8"))

    events = map_winrm_assessments_to_events(
        assessments,
        attack_path_id="host_winrm_initial_access_v1",
        run_id="run-host-winrm-1",
        workload_id="winrm::192.168.56.30",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}

    assert by_wicket["HO-04"]["payload"]["status"] == "realized"
    assert by_wicket["HO-05"]["payload"]["status"] == "realized"
    assert by_wicket["HO-10"]["payload"]["status"] == "realized"
    assert by_wicket["HO-09"]["payload"]["status"] == "realized"

    assert all(event.get("type") == "obs.attack.precondition" for event in events)
    assert all(event.get("source", {}).get("toolchain") == "skg-host-toolchain" for event in events)


def test_map_winrm_assessments_to_events_marks_auth_failure_blocked() -> None:
    events = map_winrm_assessments_to_events(
        [
            {
                "host": "10.10.10.60",
                "port": 5985,
                "username": "Administrator",
                "winrm_exposed": True,
                "credential_valid": False,
                "is_admin": None,
            }
        ],
        attack_path_id="host_winrm_initial_access_v1",
        run_id="run-host-winrm-2",
        workload_id="winrm::10.10.10.60",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["HO-05"]["payload"]["status"] == "blocked"
