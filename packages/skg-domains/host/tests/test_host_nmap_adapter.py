from __future__ import annotations

import json
from pathlib import Path

from skg_domain_host.adapters.host_nmap_profile.run import map_nmap_profiles_to_events


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_host" / "fixtures"


def test_map_nmap_profiles_to_events_emits_canonical_host_wickets() -> None:
    profiles = json.loads((FIXTURES / "host_nmap_profiles.json").read_text(encoding="utf-8"))

    events = map_nmap_profiles_to_events(
        profiles,
        attack_path_id="host_network_exploit_v1",
        run_id="run-host-1",
        workload_id="host::192.168.56.10",
    )

    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}

    assert "HO-01" in wicket_ids
    assert "HO-02" in wicket_ids
    assert "HO-19" in wicket_ids
    assert "HO-25" in wicket_ids
    assert all(event.get("type") == "obs.attack.precondition" for event in events)
    assert all(event.get("source", {}).get("toolchain") == "skg-host-toolchain" for event in events)


def test_map_nmap_profiles_to_events_emits_unknown_when_no_exploit_hit() -> None:
    profiles = [
        {
            "host": "10.10.10.10",
            "host_up": True,
            "open_ports": [
                {
                    "port": 22,
                    "proto": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.3",
                    "scripts": {"ssh2-enum-algos": "safe"},
                }
            ],
        }
    ]

    events = map_nmap_profiles_to_events(
        profiles,
        attack_path_id="host_network_exploit_v1",
        run_id="run-host-2",
        workload_id="host::10.10.10.10",
    )

    ho25 = [event for event in events if event.get("payload", {}).get("wicket_id") == "HO-25"]
    assert ho25
    assert ho25[0].get("payload", {}).get("status") == "unknown"
