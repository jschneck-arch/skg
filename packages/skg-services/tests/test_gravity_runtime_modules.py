from __future__ import annotations

import json
from pathlib import Path

from skg_core.substrate.node import TriState
from skg_protocol.events import build_event_envelope, build_precondition_payload
from skg_registry import DomainRegistry
from skg_services.gravity.domain_runtime import load_daemon_domains_from_inventory
from skg_services.gravity.event_writer import emit_events
from skg_services.gravity.observation_loading import load_observations_for_node
from skg_services.gravity.path_policy import build_service_path_policy
from skg_services.gravity.projector_runtime import project_event_file
from skg_services.gravity.state_collapse import (
    load_states_from_events,
    load_states_from_events_priority,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_event_writer_emits_ndjson_with_run_id(tmp_path: Path) -> None:
    event = {
        "type": "obs.attack.precondition",
        "payload": {"wicket_id": "HO-01"},
    }

    ids = emit_events([event], tmp_path, source_tag="host", run_id="rid01")

    assert len(ids) == 1
    assert event["id"] == ids[0]

    outputs = sorted(tmp_path.glob("*_host_rid01.ndjson"))
    assert len(outputs) == 1

    lines = outputs[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["id"] == ids[0]


def test_build_service_path_policy_prefers_env() -> None:
    policy = build_service_path_policy(
        env={
            "SKG_ROOT": "/tmp/skg-root",
            "SKG_STATE_DIR": "/tmp/skg-state",
            "SKG_CONFIG_DIR": "/tmp/skg-config",
            "MSF_DIR": "/tmp/skg-msf",
            "BH_DIR": "/tmp/skg-bh",
        },
        cwd=Path("/tmp/ignored"),
    )

    assert str(policy.root_dir) == "/tmp/skg-root"
    assert str(policy.state_dir) == "/tmp/skg-state"
    assert str(policy.config_dir) == "/tmp/skg-config"
    assert str(policy.msf_dir) == "/tmp/skg-msf"
    assert str(policy.bloodhound_dir) == "/tmp/skg-bh"


def test_domain_runtime_filters_and_applies_defaults(tmp_path: Path) -> None:
    inventory = [
        {
            "name": "host",
            "runtime": "legacy-toolchain",
            "dir": tmp_path / "skg-host-toolchain",
            "daemon_native": True,
        },
        {
            "name": "web",
            "runtime": "domain-pack",
            "dir": tmp_path / "packages" / "skg-domains" / "web",
            "daemon_native": False,
        },
    ]

    domains = load_daemon_domains_from_inventory(inventory)

    assert "host" in domains
    assert domains["host"]["cli"] == "skg_host.py"
    assert domains["host"]["default_path"] == "host_ssh_initial_access_v1"
    assert "web" not in domains


def test_observation_loading_scans_and_deduplicates(tmp_path: Path) -> None:
    discovery_dir = tmp_path / "discovery"
    events_dir = tmp_path / "events"
    discovery_dir.mkdir(parents=True, exist_ok=True)
    events_dir.mkdir(parents=True, exist_ok=True)

    _write(
        discovery_dir / "gravity_http_10.0.0.5_runA.ndjson",
        "\n".join(
            [
                json.dumps({"id": "id-1", "payload": {"target_ip": "10.0.0.5"}}),
                json.dumps({"id": "id-2", "payload": {"target_ip": "10.0.0.5"}}),
            ]
        )
        + "\n",
    )

    _write(
        events_dir / "events.ndjson",
        "\n".join(
            [
                json.dumps({"id": "id-1", "payload": {"target_ip": "10.0.0.5"}}),
                json.dumps({"id": "id-3", "payload": {"target_ip": "10.0.0.5"}}),
            ]
        )
        + "\n",
    )

    def mapper(event: dict, cycle_id: str):
        return (event.get("id"), cycle_id)

    rows = load_observations_for_node(
        node_key="10.0.0.5",
        discovery_dir=discovery_dir,
        events_dir=events_dir,
        mapper=mapper,
    )

    ids = [row[0] for row in rows]
    assert ids.count("id-1") == 1
    assert set(ids) == {"id-1", "id-2", "id-3"}


def test_state_collapse_loaders_return_expected_states() -> None:
    ev_realized = build_event_envelope(
        event_type="obs.attack.precondition",
        source_id="sensor.ssh_collect",
        toolchain="host",
        payload=build_precondition_payload(
            wicket_id="HO-01",
            workload_id="ssh::10.0.0.5",
            status="realized",
        ),
        evidence_rank=1,
        source_kind="sensor",
        pointer="ssh://10.0.0.5",
        confidence=0.95,
    )
    ev_unknown = build_event_envelope(
        event_type="obs.attack.precondition",
        source_id="sensor.ssh_collect",
        toolchain="host",
        payload=build_precondition_payload(
            wicket_id="HO-02",
            workload_id="ssh::10.0.0.5",
            status="unknown",
        ),
        evidence_rank=1,
        source_kind="sensor",
        pointer="ssh://10.0.0.5",
        confidence=0.70,
    )

    states = load_states_from_events([ev_realized, ev_unknown])

    assert states["HO-01"].state == TriState.REALIZED
    assert states["HO-02"].state == TriState.UNKNOWN

    ev_blocked = build_event_envelope(
        event_type="obs.attack.precondition",
        source_id="sensor.ssh_collect",
        toolchain="host",
        payload=build_precondition_payload(
            wicket_id="HO-03",
            workload_id="ssh::10.0.0.5",
            status="blocked",
        ),
        evidence_rank=1,
        source_kind="sensor",
        pointer="ssh://10.0.0.5",
        confidence=0.80,
    )
    ev_realized_same = build_event_envelope(
        event_type="obs.attack.precondition",
        source_id="sensor.ssh_collect",
        toolchain="host",
        payload=build_precondition_payload(
            wicket_id="HO-03",
            workload_id="ssh::10.0.0.5",
            status="realized",
        ),
        evidence_rank=1,
        source_kind="sensor",
        pointer="ssh://10.0.0.5",
        confidence=0.99,
    )

    priority_states = load_states_from_events_priority(
        [ev_realized_same, ev_blocked],
        required=["HO-03"],
    )

    assert priority_states["HO-03"].state == TriState.BLOCKED


def test_projector_runtime_projects_events_from_registry_domain(monkeypatch, tmp_path: Path) -> None:
    domains_root = tmp_path / "packages" / "skg-domains"
    domain_dir = domains_root / "host"

    _write(
        domain_dir / "domain.yaml",
        """
name: host
runtime: domain-pack
status: active
compatibility:
  protocol: "1.0"
components:
  adapters: adapters
  projectors: projectors
  policies: policies
contracts:
  catalogs: contracts/catalogs
metadata:
  default_path: host_ssh_initial_access_v1
""".strip(),
    )

    _write(
        domain_dir / "contracts" / "catalogs" / "host_catalog.json",
        json.dumps(
            {
                "attack_paths": {
                    "host_ssh_initial_access_v1": {
                        "required_wickets": ["HO-01"]
                    }
                }
            }
        ),
    )

    _write(
        domain_dir / "projectors" / "host" / "run.py",
        """
import argparse
import json
from pathlib import Path


def compute_host(events, catalog, attack_path_id, run_id=None, workload_id=None):
    return {
        "classification": "realized",
        "host_score": 1.0,
        "payload": {
            "classification": "realized",
            "host_score": 1.0,
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_file", required=True)
    parser.add_argument("--out", dest="out_file", required=True)
    parser.add_argument("--attack-path-id", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--workload-id")
    args = parser.parse_args()

    payload = {
        "classification": "realized",
        "host_score": 1.0,
    }
    Path(args.out_file).write_text(json.dumps(payload), encoding="utf-8")
""".strip()
        + "\n",
    )

    event = build_event_envelope(
        event_type="obs.attack.precondition",
        source_id="sensor.ssh_collect",
        toolchain="host",
        payload=build_precondition_payload(
            wicket_id="HO-01",
            workload_id="ssh::10.0.0.5",
            status="realized",
            attack_path_id="host_ssh_initial_access_v1",
        ),
        evidence_rank=1,
        source_kind="sensor",
        pointer="ssh://10.0.0.5",
        confidence=0.95,
    )

    events_file = tmp_path / "events.ndjson"
    _write(events_file, json.dumps(event) + "\n")

    from skg_services.gravity import projector_runtime

    monkeypatch.setattr(
        projector_runtime,
        "_registry_domains",
        lambda: DomainRegistry.discover([domains_root, tmp_path]).list_domains(),
    )

    outputs = project_event_file(events_file, tmp_path / "interp", run_id="run01")

    assert len(outputs) == 1
    out = outputs[0]
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload.get("classification") == "realized"
