from __future__ import annotations

import json
from pathlib import Path

from skg_domain_host.adapters.host_ssh_assessment.run import map_ssh_assessments_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_host" / "fixtures"


def test_map_ssh_assessments_to_events_emits_initial_access_and_privesc_wickets() -> None:
    assessments = json.loads((FIXTURES / "host_ssh_assessment.json").read_text(encoding="utf-8"))

    events = map_ssh_assessments_to_events(
        assessments,
        attack_path_id="host_linux_privesc_sudo_v1",
        run_id="run-host-ssh-1",
        workload_id="ssh::192.168.56.20",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}

    assert by_wicket["HO-01"]["payload"]["status"] == "realized"
    assert by_wicket["HO-02"]["payload"]["status"] == "realized"
    assert by_wicket["HO-03"]["payload"]["status"] == "realized"
    assert by_wicket["HO-10"]["payload"]["status"] == "realized"
    assert by_wicket["HO-06"]["payload"]["status"] == "realized"
    assert by_wicket["HO-12"]["payload"]["status"] == "realized"

    assert all(event.get("type") == "obs.attack.precondition" for event in events)
    assert all(event.get("source", {}).get("toolchain") == "skg-host-toolchain" for event in events)


def test_map_ssh_assessments_to_events_marks_invalid_credentials_blocked() -> None:
    events = map_ssh_assessments_to_events(
        [
            {
                "host": "10.10.10.50",
                "port": 22,
                "username": "root",
                "auth_type": "password",
                "reachable": True,
                "ssh_exposed": True,
                "credential_valid": False,
            }
        ],
        attack_path_id="host_ssh_initial_access_v1",
        run_id="run-host-ssh-2",
        workload_id="ssh::10.10.10.50",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["HO-03"]["payload"]["status"] == "blocked"
