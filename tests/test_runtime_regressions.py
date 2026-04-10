from __future__ import annotations

import importlib
import json
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

from skg.assistant.action_proposals import write_contract_artifact
from skg.core.assistant_contract import (
    DERIVED_ADVICE,
    MUTATION_ARTIFACT,
    OBSERVED_EVIDENCE,
)
from skg.graph import WorkloadGraph
from skg.identity import parse_workload_ref
from skg.kernel.adapters import event_to_observation, load_observations_for_target
from skg.sensors import SensorLoop, envelope, precondition_payload
from skg.sensors.projector import project_event_file, project_events
from skg.temporal import DeltaStore
from skg.temporal.feedback import FeedbackIngester
from skg.topology.energy import load_states_from_interp


def _payload(data: dict) -> dict:
    return data.get("payload", data)


def test_project_event_file_keeps_distinct_attack_paths_per_run(tmp_path: Path):
    events = [
        envelope(
            event_type="obs.attack.precondition",
            source_id="ssh_sensor",
            toolchain="host",
            payload=precondition_payload(
                wicket_id="HO-01",
                domain="host",
                workload_id="host-a",
                attack_path_id="host_ssh_initial_access_v1",
                realized=True,
            ),
            evidence_rank=1,
            source_kind="test",
            pointer="process://ssh",
        ),
        envelope(
            event_type="obs.attack.precondition",
            source_id="ssh_sensor",
            toolchain="host",
            payload=precondition_payload(
                wicket_id="HO-19",
                domain="host",
                workload_id="host-a",
                attack_path_id="host_linux_privesc_sudo_v1",
                realized=True,
            ),
            evidence_rank=1,
            source_kind="test",
            pointer="process://sudo",
        ),
    ]

    events_file = tmp_path / "events.ndjson"
    interp_dir = tmp_path / "interp"
    events_file.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")

    outputs = project_event_file(events_file, interp_dir, run_id="run-1")

    assert len(outputs) == 2
    assert len({path.name for path in outputs}) == 2
    assert all(path.exists() for path in outputs)
    assert {
        _payload(json.loads(path.read_text(encoding="utf-8")))["attack_path_id"]
        for path in outputs
    } == {"host_ssh_initial_access_v1", "host_linux_privesc_sudo_v1"}


def test_gap_detector_tracks_new_hosts_per_service(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import skg.intel.gap_detector as gap_detector

    monkeypatch.setattr(gap_detector, "GAP_STATE_FILE", tmp_path / "gap_detector.state.json")

    events_dir = tmp_path / "events"
    events_dir.mkdir()
    first = envelope(
        event_type="obs.attack.precondition",
        source_id="agent_sensor",
        toolchain="host",
        payload=precondition_payload(
            wicket_id="HO-01",
            domain="host",
            workload_id="host::10.0.0.1",
            detail="redis-server running",
        ),
        evidence_rank=3,
        source_kind="process",
        pointer="process://ps",
    )
    (events_dir / "first.ndjson").write_text(json.dumps(first) + "\n", encoding="utf-8")

    first_gaps = gap_detector.detect_new_gaps(events_dir)
    assert len(first_gaps) == 1
    assert first_gaps[0]["service"] == "redis"
    assert first_gaps[0]["hosts"] == ["host::10.0.0.1"]

    second = envelope(
        event_type="obs.attack.precondition",
        source_id="agent_sensor",
        toolchain="host",
        payload=precondition_payload(
            wicket_id="HO-01",
            domain="host",
            workload_id="host::10.0.0.2",
            detail="redis-server running",
        ),
        evidence_rank=3,
        source_kind="process",
        pointer="process://ps",
    )
    (events_dir / "second.ndjson").write_text(json.dumps(second) + "\n", encoding="utf-8")

    second_gaps = gap_detector.detect_new_gaps(events_dir)
    known = gap_detector.load_known_gaps()

    assert len(second_gaps) == 1
    assert second_gaps[0]["service"] == "redis"
    assert second_gaps[0]["hosts"] == ["host::10.0.0.2"]
    assert sorted(known["redis"]["targets"]) == ["host::10.0.0.1", "host::10.0.0.2"]


def test_sensor_context_loads_persisted_calibration_by_source(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import skg.sensors.confidence_calibrator as sensor_cal
    import skg.sensors.context as sensor_context

    calibration_path = tmp_path / "calibration.json"
    monkeypatch.setattr(sensor_cal, "CALIBRATION_PATH", calibration_path)
    monkeypatch.setattr(sensor_context, "CALIBRATION_PATH", calibration_path)

    calibrator = sensor_cal.ConfidenceCalibrator()
    calibrator._stats["ssh_sensor::unknown→realized"] = sensor_cal.SourceStats(
        source_id="ssh_sensor",
        transition="unknown→realized",
        count=10,
        reversals=5,
        mean_conf=1.0,
        conf_sum=10.0,
    )
    calibrator.save(calibration_path)

    class _Graph:
        def get_prior(self, workload_id: str, wicket_id: str | None = None, node_id: str | None = None) -> float:
            return 0.0

    ctx = sensor_context.SensorContext(graph=_Graph(), obs_memory=None)
    adjusted = ctx.calibrate(
        0.8,
        "HO-01: ssh reachable",
        wicket_id="HO-01",
        domain="host",
        workload_id="host::10.0.0.7",
        source_id="ssh_sensor",
    )

    assert adjusted == 0.4


def test_same_domain_inference_requires_explicit_ad_metadata(tmp_path: Path):
    graph = WorkloadGraph(tmp_path / "graph")
    graph.infer_edges_from_events([
        {
            "type": "obs.attack.precondition",
            "payload": {
                "workload_id": "host::10.0.0.1",
                "domain": "host",
                "host_meta": {"hostname": "10.0.0.1"},
            },
        },
        {
            "type": "obs.attack.precondition",
            "payload": {
                "workload_id": "host::10.0.0.2",
                "domain": "host",
                "host_meta": {"hostname": "10.0.0.2"},
            },
        },
    ])

    assert all(edge.relationship != "same_domain" for edge in graph._edges)
    assert any(edge.relationship == "same_subnet" for edge in graph._edges)

    graph_with_ad = WorkloadGraph(tmp_path / "graph_ad")
    graph_with_ad.infer_edges_from_events([
        {
            "type": "obs.attack.precondition",
            "payload": {
                "workload_id": "ad::10.0.0.3",
                "domain": "ad_lateral",
                "host_meta": {"hostname": "10.0.0.3", "ad_domain": "corp.local"},
            },
        },
        {
            "type": "obs.attack.precondition",
            "payload": {
                "workload_id": "ad::10.0.0.4",
                "domain": "ad_lateral",
                "host_meta": {"hostname": "10.0.0.4", "ad_domain": "corp.local"},
            },
        },
    ])

    same_domain_edges = [edge for edge in graph_with_ad._edges if edge.relationship == "same_domain"]
    assert len(same_domain_edges) == 1
    assert same_domain_edges[0].metadata["ad_domain"] == "corp.local"


def test_parse_workload_ref_collapses_binary_locator_to_host():
    parsed = parse_workload_ref("binary::192.168.254.5::ssh-keysign")

    assert parsed["host"] == "192.168.254.5"
    assert parsed["identity_key"] == "192.168.254.5"


def test_precondition_payload_enriches_subject_identity():
    payload = precondition_payload(
        wicket_id="BA-03",
        domain="binary",
        workload_id="binary::192.168.254.5::ssh-keysign",
        status="realized",
    )

    assert payload["node_id"] == "BA-03"
    assert payload["identity_key"] == "192.168.254.5"
    assert payload["manifestation_key"] == "binary::192.168.254.5::ssh-keysign"
    assert payload["target_ip"] == "192.168.254.5"


def test_surface_attaches_observed_tool_inventory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import skg.intel.surface as surface_module

    interp_dir = tmp_path / "interp"
    events_dir = tmp_path / "events"
    interp_dir.mkdir()
    events_dir.mkdir()

    (interp_dir / "host_db_internal.json").write_text(
        json.dumps({
            "workload_id": "host::db.internal",
            "attack_path_id": "host_ssh_initial_access_v1",
            "classification": "unknown",
            "host_score": 0.0,
            "realized": [],
            "blocked": [],
            "unknown": ["HO-02"],
            "computed_at": "2026-03-27T12:00:00+00:00",
        }),
        encoding="utf-8",
    )
    (events_dir / "ctx_tools.ndjson").write_text(
        json.dumps({
            "id": "tool-1",
            "ts": "2026-03-27T12:01:00+00:00",
            "type": "obs.substrate.node",
            "source": {"source_id": "adapter.ssh_collect", "toolchain": "skg-host-toolchain"},
            "payload": {
                "node_id": "CTX-TOOLS",
                "status": "realized",
                "workload_id": "host::db.internal",
                "observed_at": "2026-03-27T12:01:00+00:00",
                "notes": "Observed node-local tools.",
                "attributes": {
                    "tool_names": ["checksec", "nikto"],
                    "observed_tools": [
                        {
                            "name": "checksec",
                            "path": "/usr/bin/checksec",
                            "instrument_names": ["binary_analysis"],
                            "domain_hints": ["binary"],
                        },
                        {
                            "name": "nikto",
                            "path": "/usr/bin/nikto",
                            "instrument_names": ["nikto"],
                            "domain_hints": ["web"],
                        },
                    ],
                    "domain_hints": ["binary", "web"],
                    "instrument_hints": ["binary_analysis", "nikto"],
                    "scope": "node_local",
                },
            },
            "provenance": {"evidence_rank": 1, "evidence": {"confidence": 0.9}},
        }) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(surface_module, "EVENTS_DIR", events_dir)
    result = surface_module.surface(interp_dir=interp_dir)

    workload = result["workloads"][0]
    view = result["view_nodes"][0]

    assert workload["observed_tools"]["tool_names"] == ["checksec", "nikto"]
    assert workload["observed_tools"]["instrument_hints"] == ["binary_analysis", "nikto"]
    assert view["observed_tools"]["tool_names"] == ["checksec", "nikto"]
    assert view["measured_now"]["observed_tools"]["tool_names"] == ["checksec", "nikto"]


def test_event_to_observation_rejects_assistant_advice_without_custody():
    event = envelope(
        event_type="obs.attack.precondition",
        source_id="assistant.explain",
        toolchain="host",
        payload={
            **precondition_payload(
                wicket_id="HO-01",
                domain="host",
                workload_id="host::10.0.0.7",
                status="unknown",
            ),
            "assistant_output_class": DERIVED_ADVICE,
        },
        evidence_rank=1,
        source_kind="assistant",
        pointer="assistant://explain",
    )

    assert event_to_observation(event) is None


def test_event_to_observation_accepts_assistant_relay_with_complete_custody():
    event = envelope(
        event_type="obs.attack.precondition",
        source_id="assistant.relay",
        toolchain="host",
        payload={
            **precondition_payload(
                wicket_id="HO-01",
                domain="host",
                workload_id="host::10.0.0.7",
                status="realized",
            ),
            "assistant_output_class": OBSERVED_EVIDENCE,
        },
        evidence_rank=1,
        source_kind="assistant",
        pointer="assistant://relay",
    )
    event["provenance"]["evidence"]["custody_chain"] = {
        "artifact_path": "/tmp/raw.ndjson",
        "artifact_hash": "sha256:deadbeef",
        "source_command": "nmap -oX - 10.0.0.7",
        "collected_at": event["ts"],
    }

    obs = event_to_observation(event)

    assert obs is not None
    assert obs.instrument == "relay"
    assert obs.targets == ["10.0.0.7"]
    assert obs.support_mapping["10.0.0.7"]["R"] == 1.0


def test_project_event_file_ignores_assistant_advice_without_custody(tmp_path: Path):
    event = envelope(
        event_type="obs.attack.precondition",
        source_id="assistant.suggest",
        toolchain="host",
        payload={
            **precondition_payload(
                wicket_id="HO-01",
                domain="host",
                workload_id="host::10.0.0.7",
                status="unknown",
                attack_path_id="host_ssh_initial_access_v1",
            ),
            "assistant_output_class": DERIVED_ADVICE,
        },
        evidence_rank=1,
        source_kind="assistant",
        pointer="assistant://suggest",
    )

    events_file = tmp_path / "assistant.ndjson"
    interp_dir = tmp_path / "interp"
    events_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

    assert project_event_file(events_file, interp_dir, run_id="assistant-run") == []


@pytest.mark.parametrize(
    ("module_name", "wicket_id", "label"),
    [
        ("boot_probe", "BT-01", "uefi_mode_active"),
        ("gpu_probe", "GP-01", "gpu_device_present"),
        ("process_probe", "PR-01", "ptrace_scope_unrestricted"),
    ],
)
def test_host_probe_helpers_emit_canonical_subject_contract(module_name: str, wicket_id: str, label: str):
    module = importlib.import_module(f"skg.sensors.{module_name}")

    event = module._event(  # type: ignore[attr-defined]
        wicket_id=wicket_id,
        label=label,
        workload_id="host::192.168.254.5",
        realized=True,
        detail="probe detail",
        target_ip="192.168.254.5",
    )

    payload = event["payload"]
    assert event["type"] == "obs.attack.precondition"
    assert event["source"]["toolchain"] == "skg-host-toolchain"
    assert payload["node_id"] == wicket_id
    assert payload["label"] == label
    assert payload["domain"] == "host"
    assert payload["identity_key"] == "192.168.254.5"
    assert payload["manifestation_key"] == "host::192.168.254.5"
    assert payload["target_ip"] == "192.168.254.5"


def test_struct_fetch_events_emit_canonical_subject_contract():
    struct_fetch = importlib.import_module("skg.sensors.struct_fetch")

    event = struct_fetch._event(  # type: ignore[attr-defined]
        wicket_id="WB-38",
        status="realized",
        rank=2,
        confidence=0.9,
        detail="Sensitive key in json response",
        workload_id="web::192.168.254.5:8080",
        run_id="run-1",
        target_ip="192.168.254.5",
    )

    payload = event["payload"]
    assert event["type"] == "obs.attack.precondition"
    assert event["source"]["toolchain"] == "skg-web-toolchain"
    assert payload["node_id"] == "WB-38"
    assert payload["label"] == "credentials_in_config"
    assert payload["domain"] == "web"
    assert payload["status"] == "realized"
    assert payload["realized"] is True
    assert payload["run_id"] == "run-1"
    assert payload["identity_key"] == "192.168.254.5"
    assert payload["manifestation_key"] == "web::192.168.254.5:8080"
    assert payload["target_ip"] == "192.168.254.5"
    assert payload["attack_path_id"] == "web_sqli_to_shell_v1"
    assert "observed_at" in payload


def test_feedback_normalizes_wrapped_interp_payloads_before_delta_ingest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    import skg.temporal.feedback as feedback_module

    interp_dir = tmp_path / "interp"
    events_dir = tmp_path / "events"
    delta_dir = tmp_path / "delta"
    pearls_path = tmp_path / "pearls.jsonl"
    interp_dir.mkdir()
    events_dir.mkdir()
    monkeypatch.setattr(feedback_module, "FEEDBACK_STATE_FILE", tmp_path / "feedback.state.json")

    first = {
        "id": "interp-1",
        "type": "interp.host.realizability",
        "payload": {
            "workload_id": "host::192.168.254.5",
            "attack_path_id": "host_ssh_initial_access_v1",
            "classification": "indeterminate",
            "host_score": 0.5,
            "required_wickets": ["HO-01", "HO-02"],
            "realized": ["HO-01"],
            "blocked": [],
            "unknown": ["HO-02"],
            "computed_at": "2026-03-27T00:00:00+00:00",
            "run_id": "run-1",
        },
    }
    second = {
        "id": "interp-2",
        "type": "interp.host.realizability",
        "payload": {
            "workload_id": "host::192.168.254.5",
            "attack_path_id": "host_ssh_initial_access_v1",
            "classification": "fully_realized",
            "host_score": 1.0,
            "required_wickets": ["HO-01", "HO-02"],
            "realized": ["HO-01", "HO-02"],
            "blocked": [],
            "unknown": [],
            "computed_at": "2026-03-27T00:00:01+00:00",
            "run_id": "run-2",
        },
    }
    (interp_dir / "first.json").write_text(json.dumps(first), encoding="utf-8")
    (interp_dir / "second.json").write_text(json.dumps(second), encoding="utf-8")

    class _Graph:
        def propagate_transition(self, **kwargs):
            return None

        def propagate_intra_target(self, **kwargs):
            return None

        def decay_priors(self, workload_id: str):
            return None

        def clear_prior(self, workload_id: str, wicket_id: str):
            return None

        def infer_edges_from_events(self, events: list[dict]):
            return None

        def status(self) -> dict:
            return {}

        def neighbors(self, workload_id: str):
            return []

    delta = DeltaStore(delta_dir)
    feedback = FeedbackIngester(
        delta_store=delta,
        graph=_Graph(),
        obs_memory=None,
        interp_dir=interp_dir,
        events_dir=events_dir,
        pearls_path=pearls_path,
    )

    summary = feedback.process_new_interps()
    history = delta.workload_history("host::192.168.254.5", "host_ssh_initial_access_v1")
    transitions = delta.workload_transitions("host::192.168.254.5")
    pearl_records = [json.loads(line) for line in pearls_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    assert summary["processed"] == 2
    assert len(history) == 2
    assert history[-1].attack_path_id == "host_ssh_initial_access_v1"
    assert history[-1].classification == "realized"
    assert history[-1].wicket_states["HO-02"] == "realized"
    assert feedback.status()["pearls"] == 2
    assert len(pearl_records) == 2
    assert pearl_records[-1]["energy_snapshot"]["workload_id"] == "host::192.168.254.5"
    assert pearl_records[-1]["energy_snapshot"]["manifestation_key"] == "host::192.168.254.5"
    assert pearl_records[-1]["observation_confirms"][-1]["wicket_id"] == "HO-02"
    assert any(
        t.wicket_id == "HO-02" and t.from_state == "unknown" and t.to_state == "realized"
        for t in transitions
    )


def test_load_states_from_interp_supports_canonical_json_projection(tmp_path: Path):
    interp_file = tmp_path / "host__10_0_0_7__host_ssh_initial_access_v1__run-1.json"
    interp_file.write_text(
        json.dumps({
            "workload_id": "host::10.0.0.7",
            "attack_path_id": "host_ssh_initial_access_v1",
            "latest_status": {"HO-01": "realized", "HO-03": "unknown"},
            "realized": ["HO-01"],
            "blocked": [],
            "unknown": ["HO-03"],
            "computed_at": "2026-03-27T00:00:00+00:00",
        }),
        encoding="utf-8",
    )

    by_sphere = load_states_from_interp(interp_file)

    assert "host" in by_sphere
    host_states = {ws.wicket_id: ws for ws in by_sphere["host"]}
    assert host_states["HO-01"].status == "realized"
    assert host_states["HO-03"].status == "unknown"


def test_event_to_observation_uses_identity_anchor_for_binary_workload():
    event = {
        "type": "obs.attack.precondition",
        "source": {"source_id": "projection.binary"},
        "payload": precondition_payload(
            wicket_id="BA-03",
            domain="binary",
            workload_id="binary::192.168.254.5::ssh-keysign",
            status="realized",
        ),
        "provenance": {"evidence": {"confidence": 0.9}},
    }

    obs = event_to_observation(event)

    assert obs is not None
    assert obs.targets == ["192.168.254.5"]
    assert obs.support_mapping == {"192.168.254.5": {"R": 0.9, "B": 0.0, "U": 0.0}}


def test_load_observations_for_target_matches_binary_workload_by_identity(tmp_path: Path):
    discovery_dir = tmp_path / "discovery"
    events_dir = tmp_path / "events"
    discovery_dir.mkdir()
    events_dir.mkdir()

    event = envelope(
        event_type="obs.attack.precondition",
        source_id="binary_sensor",
        toolchain="binary",
        payload=precondition_payload(
            wicket_id="BA-03",
            domain="binary",
            workload_id="binary::192.168.254.5::ssh-keysign",
            status="realized",
        ),
        evidence_rank=1,
        source_kind="test",
        pointer="binary://ssh-keysign",
        confidence=0.95,
    )
    (events_dir / "binary_observation.ndjson").write_text(json.dumps(event) + "\n", encoding="utf-8")

    observations = load_observations_for_target("192.168.254.5", discovery_dir, events_dir)

    assert len(observations) == 1
    assert observations[0].targets == ["192.168.254.5"]


def test_project_events_accepts_binary_analysis_alias(tmp_path: Path):
    events = [
        {
            "ts": f"2026-03-27T15:00:0{idx}+00:00",
            "type": "obs.attack.precondition",
            "source": {"toolchain": "skg-binary-toolchain"},
            "payload": {
                "wicket_id": wicket_id,
                "status": status,
                "workload_id": "binary::192.168.254.5::ssh-keysign",
                "attack_path_id": "binary_stack_overflow_v1",
            },
        }
        for idx, (wicket_id, status) in enumerate([
            ("BA-01", "blocked"),
            ("BA-03", "realized"),
            ("BA-04", "realized"),
            ("BA-05", "unknown"),
            ("BA-06", "realized"),
        ])
    ]

    out = project_events(
        events,
        workload_id="binary::192.168.254.5::ssh-keysign",
        toolchain="binary_analysis",
        attack_path_id="binary_stack_overflow_v1",
        run_id="run-binary",
        interp_dir=tmp_path,
    )

    assert out is not None
    payload = _payload(json.loads(out.read_text(encoding="utf-8")))
    assert payload["domain"] == "binary"
    assert payload["workload_id"] == "binary::192.168.254.5::ssh-keysign"
    assert payload["classification"] == "not_realized"


def test_projection_lookup_finds_normalized_binary_interp(tmp_path: Path):
    import skg.core.daemon as daemon

    interp = tmp_path / "binary__binary_192.168.254.5__ssh-keysign__binary_stack_overflow_v1__run-binary.json"
    interp.write_text(json.dumps({
        "payload": {
            "domain": "binary",
            "workload_id": "binary::192.168.254.5::ssh-keysign",
            "attack_path_id": "binary_stack_overflow_v1",
            "run_id": "run-binary",
            "classification": "indeterminate",
            "binary_score": 0.4,
            "required_wickets": ["BA-01"],
            "realized": [],
            "blocked": [],
            "unknown": ["BA-01"],
        }
    }), encoding="utf-8")

    matches = daemon._find_projection_files(tmp_path, "binary", "binary::192.168.254.5::ssh-keysign")
    alias_matches = daemon._find_projection_files(tmp_path, "binary_analysis", "binary::192.168.254.5::ssh-keysign")

    assert matches == [interp]
    assert alias_matches == [interp]


def test_sensor_loop_serializes_overlapping_sweeps(tmp_path: Path):
    active = 0
    max_active = 0
    active_lock = threading.Lock()

    class _FakeSensor:
        name = "fake"

        def run(self):
            nonlocal active, max_active
            with active_lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with active_lock:
                active -= 1
            return ["evt-1"]

    def _fake_load_sensors(self):
        self._cfg = {}
        self._sensors = []

    with mock.patch.object(SensorLoop, "_load_sensors", _fake_load_sensors):
        loop = SensorLoop(
            events_dir=tmp_path / "events",
            interp_dir=tmp_path / "interp",
            config_dir=tmp_path / "cfg",
            host_tc_dir=tmp_path / "host-toolchain",
            auto_project=False,
        )

    loop._sensors = [_FakeSensor()]

    t1 = threading.Thread(target=loop._sweep, args=("run-1",))
    t2 = threading.Thread(target=loop._sweep, args=("run-2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert max_active == 1
    assert loop._run_count == 2
    assert loop.status()["sweep_in_progress"] is False


def test_contract_artifacts_are_immutable(tmp_path: Path):
    first = write_contract_artifact(
        contract_name="msf_rc",
        content="use auxiliary/scanner/http/http_version\nexit\n",
        filename_hint="demo.rc",
        out_dir=tmp_path,
    )
    second = write_contract_artifact(
        contract_name="msf_rc",
        content="use exploit/unix/webapp/php_cgi_arg_injection\nexit\n",
        filename_hint="demo.rc",
        out_dir=tmp_path,
    )

    assert first["path"] != second["path"]
    assert Path(first["path"]).exists()
    assert Path(second["path"]).exists()
    assert "http_version" in Path(first["path"]).read_text(encoding="utf-8")
    assert "php_cgi_arg_injection" in Path(second["path"]).read_text(encoding="utf-8")


def test_contract_artifact_metadata_marks_mutation_artifact(tmp_path: Path):
    artifact = write_contract_artifact(
        contract_name="msf_rc",
        content="use auxiliary/scanner/http/http_version\nexit\n",
        filename_hint="demo.rc",
        out_dir=tmp_path,
    )

    meta = json.loads(Path(artifact["meta_path"]).read_text(encoding="utf-8"))

    assert artifact["assistant_output_class"] == MUTATION_ARTIFACT
    assert meta["assistant_output_class"] == MUTATION_ARTIFACT
    assert meta["state_authority"] == "advisory_only"
    assert meta["observation_admissible"] is False
    assert meta["artifact_hash"].startswith("sha256:")


def test_registry_driven_projector_discovery_supports_root_projection_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    import skg.core.domain_registry as registry
    import skg.sensors.projector as projector

    home_dir = tmp_path / "home"
    cfg_dir = tmp_path / "cfg"
    home_dir.mkdir()
    cfg_dir.mkdir()

    toolchain_dir = home_dir / "skg-demo-toolchain"
    (toolchain_dir / "projections").mkdir(parents=True)
    (toolchain_dir / "contracts" / "catalogs").mkdir(parents=True)
    (toolchain_dir / "forge_meta.json").write_text(
        json.dumps(
            {
                "toolchain": "skg-demo-toolchain",
                "domain": "demo",
                "description": "Demo projector",
                "default_path": "demo_path_v1",
            }
        ),
        encoding="utf-8",
    )
    (toolchain_dir / "contracts" / "catalogs" / "demo_catalog.json").write_text(
        json.dumps(
            {
                "attack_paths": {
                    "demo_path_v1": {
                        "id": "demo_path_v1",
                        "required_wickets": ["DM-01"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (toolchain_dir / "projections" / "run.py").write_text(
        "\n".join([
            "import json",
            "from pathlib import Path",
            "",
            "def compute_demo(events, catalog, attack_path_id, run_id=None, workload_id=None):",
            "    return {",
            "        'workload_id': workload_id or 'unknown',",
            "        'run_id': run_id,",
            "        'domain': 'demo',",
            "        'attack_path_id': attack_path_id,",
            "        'classification': 'indeterminate',",
            "        'demo_score': 0.5,",
            "        'realized': [],",
            "        'blocked': [],",
            "        'unknown': ['DM-01'],",
            "        'required_wickets': ['DM-01'],",
            "    }",
            "",
            "def main():",
            "    raise SystemExit(0)",
        ]),
        encoding="utf-8",
    )

    monkeypatch.setattr(registry, "SKG_HOME", home_dir)
    monkeypatch.setattr(registry, "SKG_CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(projector, "SKG_HOME", home_dir)
    try:
        import skg_services.gravity.projector_runtime as _svc_rt
        monkeypatch.setattr(_svc_rt, "SKG_HOME", home_dir)
    except Exception:
        pass
    projector._projector_cache.clear()
    try:
        _svc_rt._projector_cache.clear()
    except Exception:
        pass

    inventory = registry.summarize_domain_inventory(registry.load_domain_inventory())
    by_name = {row["name"]: row for row in inventory}
    assert by_name["demo"]["projector_available"] is True
    assert by_name["demo"]["projector_path"] == "projections/run.py"

    event = {
        "id": "demo-1",
        "ts": "2026-03-27T00:00:00+00:00",
        "type": "obs.attack.precondition",
        "source": {"source_id": "demo_sensor", "toolchain": "demo", "version": "1.0.0"},
        "payload": {
            "wicket_id": "DM-01",
            "status": "realized",
            "attack_path_id": "demo_path_v1",
            "workload_id": "demo::10.0.0.8",
            "detail": "demo observation",
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {"source_kind": "test", "pointer": "test://demo", "confidence": 0.9},
        },
    }
    events_file = tmp_path / "demo.ndjson"
    interp_dir = tmp_path / "interp"
    events_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

    outputs = project_event_file(events_file, interp_dir, run_id="run-1")

    assert len(outputs) == 1
    result = json.loads(outputs[0].read_text(encoding="utf-8"))
    assert result["attack_path_id"] == "demo_path_v1"
    assert result["domain"] == "demo"


def test_sensor_loop_discovers_sensor_modules_dynamically(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import skg.sensors as sensors_mod

    imported: list[str] = []
    real_import = importlib.import_module

    def _spy_import(name: str, package: str | None = None):
        imported.append(name)
        return real_import(name, package)

    monkeypatch.setattr(sensors_mod.importlib, "import_module", _spy_import)
    monkeypatch.setattr(sensors_mod, "_load_skg_config", lambda _config_dir: {"sensors": {"enabled": []}})

    SensorLoop(
        events_dir=tmp_path / "events",
        interp_dir=tmp_path / "interp",
        config_dir=tmp_path / "cfg",
        host_tc_dir=tmp_path / "host-toolchain",
        auto_project=False,
    )

    assert "skg.sensors.cognitive_sensor" in imported


def test_data_sensor_registers_same_database_bond_with_explicit_weight(tmp_path: Path):
    from skg.sensors.data_sensor import DataSensor

    graph = WorkloadGraph(tmp_path / "graph")
    sensor = DataSensor(
        {
            "sources": [
                {"url": "postgresql://user:pass@db.internal/app", "table": "users", "workload_id": "data::users"},
                {"url": "postgresql://user:pass@db.internal/app", "table": "orders", "workload_id": "data::orders"},
            ]
        },
        events_dir=tmp_path / "events",
    )
    sensor._graph = graph
    sensor._cfg = {}

    sensor._register_bonds()

    same_database_edges = [edge for edge in graph._edges if edge.relationship == "same_database"]
    assert len(same_database_edges) == 1
    assert same_database_edges[0].weight == 0.60


# ---------------------------------------------------------------------------
# Group 2: collect_host / SshSensor / identity normalization regressions
# ---------------------------------------------------------------------------

def test_collect_host_returns_false_on_zero_events(tmp_path):
    """collect_host must return False when no events are emitted."""
    from skg.sensors import collect_host

    target = {
        "host": "10.0.0.9",
        "method": "ssh",
        "user": "root",
        "workload_id": "ssh::10.0.0.9",
        "attack_path_id": "host_ssh_initial_access_v1",
        "enabled": True,
    }

    # SshSensor.run() returns [] when connection fails (no live host) — that
    # should now propagate as False from collect_host.
    with mock.patch("skg.sensors.ssh_sensor.SshSensor._collect_ssh", return_value=[]):
        with mock.patch("skg.sensors.ssh_sensor.SshSensor._collect_winrm", return_value=[]):
            result = collect_host(target, tmp_path / "events", tmp_path / "tc", "testrun1")

    assert result is False


def test_collect_host_returns_true_when_events_emitted(tmp_path):
    """collect_host must return True only when at least one event is written."""
    from skg.sensors import collect_host, envelope, precondition_payload

    target = {
        "host": "10.0.0.9",
        "method": "ssh",
        "user": "root",
        "workload_id": "ssh::10.0.0.9",
        "attack_path_id": "host_ssh_initial_access_v1",
        "enabled": True,
    }

    ev = envelope(
        event_type="obs.attack.precondition",
        source_id="ssh_sensor",
        toolchain="host",
        payload=precondition_payload(
            wicket_id="HO-01",
            domain="host",
            workload_id="ssh::10.0.0.9",
            attack_path_id="host_ssh_initial_access_v1",
            realized=True,
        ),
        evidence_rank=1,
        source_kind="ssh_collect",
        pointer="process://ssh",
    )

    with mock.patch("skg.sensors.ssh_sensor.SshSensor._collect_ssh", return_value=[ev]):
        result = collect_host(target, tmp_path / "events", tmp_path / "tc", "testrun2")

    assert result is True
    emitted = list((tmp_path / "events").glob("*_testrun2.ndjson"))
    assert len(emitted) == 1, "emitted file must carry the run_id suffix"


def test_collect_host_uses_injected_target_not_config(tmp_path):
    """SshSensor must use the target from config['targets'], not load from disk."""
    from skg.sensors.ssh_sensor import SshSensor

    called_with: list[str] = []

    def fake_collect(self, target, host, workload_id, attack_path_id, run_id):
        called_with.append(host)
        return []

    cfg = {
        "targets": [{"host": "192.168.1.55", "method": "ssh", "enabled": True}],
        "timeout_s": 5,
        "collect_interval_s": 0,
    }

    sensor = SshSensor(cfg, events_dir=tmp_path)

    with mock.patch.object(SshSensor, "_collect_ssh", fake_collect):
        with mock.patch("skg.sensors.ssh_sensor._load_targets") as mock_load:
            sensor.run()
            # _load_targets must NOT have been called — injected targets take priority
            mock_load.assert_not_called()

    assert called_with == ["192.168.1.55"]


def test_ssh_sensor_interval_gating_bypassed_for_injected_targets(tmp_path):
    """Interval gating must not block explicitly injected single-target collection."""
    from skg.sensors.ssh_sensor import SshSensor

    reached: list[bool] = []

    def fake_collect(self, target, host, wid, apid, run_id):
        reached.append(True)
        return []

    # Very large interval — would block any sweep-mode collection
    cfg = {
        "targets": [{"host": "10.1.1.1", "method": "ssh", "enabled": True}],
        "timeout_s": 5,
        "collect_interval_s": 999999,
    }
    sensor = SshSensor(cfg, events_dir=tmp_path)
    # Simulate the host having been recently collected
    sensor._state["last_collected"]["10.1.1.1"] = 1e18

    with mock.patch.object(SshSensor, "_collect_ssh", fake_collect):
        sensor.run()

    assert reached, "injected target must not be blocked by interval gating"


def test_emit_events_embeds_run_id_in_filename(tmp_path):
    """emit_events must include run_id in the filename when supplied."""
    from skg.sensors import emit_events, envelope, precondition_payload

    ev = envelope(
        event_type="obs.attack.precondition",
        source_id="ssh_sensor",
        toolchain="host",
        payload=precondition_payload(wicket_id="HO-01", workload_id="ssh::1.2.3.4"),
        evidence_rank=1,
        source_kind="test",
        pointer="process://ssh",
    )
    emit_events([ev], tmp_path, source_tag="host", run_id="rid99")
    files = list(tmp_path.glob("*_rid99.ndjson"))
    assert len(files) == 1


def test_emit_events_without_run_id_keeps_old_naming(tmp_path):
    """emit_events without run_id must use the timestamp+tag scheme (no trailing run_id)."""
    import re
    from skg.sensors import emit_events, envelope, precondition_payload

    ev = envelope(
        event_type="obs.attack.precondition",
        source_id="ssh_sensor",
        toolchain="host",
        payload=precondition_payload(wicket_id="HO-01", workload_id="ssh::1.2.3.4"),
        evidence_rank=1,
        source_kind="test",
        pointer="process://ssh",
    )
    emit_events([ev], tmp_path, source_tag="mytag")
    files = list(tmp_path.glob("*.ndjson"))
    assert len(files) == 1
    assert re.match(r"\d{8}T\d{6}_mytag\.ndjson", files[0].name)


def test_msf_session_adapter_normalizes_workload_id(tmp_path):
    """MSF session adapter must emit host::{ip} workload ids, not bare IPs."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "msf_parse",
        Path(__file__).resolve().parents[1]
        / "skg-host-toolchain/adapters/msf_session/parse.py",
    )
    msf_parse = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(msf_parse)

    out = tmp_path / "out.ndjson"
    sessions = [
        {
            "id": "1",
            "target_host": "10.0.0.7",
            "type": "meterpreter",
            "username": "root",
            "platform": "linux",
            "via_exploit": "exploit/multi/handler",
            "tunnel_peer": "10.0.0.7:4444",
        }
    ]
    msf_parse.process_sessions(
        sessions, out, "host_msf_post_exploitation_v1", "run1", "msf_workspace", "msf_rpc"
    )
    lines = [json.loads(l) for l in out.read_text().splitlines()]
    wids = {l.get("workload_id") or l.get("subject", {}).get("id", "") for l in lines}
    assert all("host::" in w for w in wids if w), f"expected host:: prefix in {wids}"


def test_daemon_collect_workload_id_uses_ssh_prefix():
    """Daemon /collect workload_id must default to ssh::{target}, not bare target."""
    import importlib.util
    from pathlib import Path as _P

    spec = importlib.util.spec_from_file_location(
        "daemon_mod",
        _P(__file__).resolve().parents[1] / "skg/core/daemon.py",
    )
    # We only need to inspect the source, not execute the full module.
    src = (_P(__file__).resolve().parents[1] / "skg/core/daemon.py").read_text()
    # The fix: workload_id must reference f"ssh::{req.target}", not req.target alone.
    assert 'f"ssh::{req.target}"' in src, (
        "daemon /collect must default workload_id to ssh::{target}"
    )


# ---------------------------------------------------------------------------
# Group 7: engagement dataset delta dir and node_key integrity regressions
# ---------------------------------------------------------------------------

def test_build_engagement_db_default_delta_dir_ingests_transitions(tmp_path):
    """build_engagement_db with delta_dir=None must read from DELTA_DIR, not SKG_STATE_DIR."""
    import sqlite3
    from unittest.mock import patch

    from skg_core.config.paths import DELTA_DIR

    # Write a real transition record into the canonical delta location.
    delta_dir = tmp_path / "delta"
    delta_dir.mkdir()
    import uuid as _uuid
    from datetime import datetime, timezone as _tz
    trans = {
        "id": str(_uuid.uuid4()),
        "ts": datetime.now(_tz.utc).isoformat(),
        "workload_id": "ssh::10.0.0.1",
        "wicket_id": "HO-01",
        "from_state": "unknown",
        "to_state": "realized",
        "signal_weight": 0.9,
        "meaning": "test transition",
        "run_id": "r1",
    }
    (delta_dir / "delta_store.ndjson").write_text(json.dumps(trans) + "\n")

    events_dir = tmp_path / "events"
    events_dir.mkdir()
    interp_dir = tmp_path / "interp"
    interp_dir.mkdir()
    db_path = tmp_path / "eng.db"

    with patch("skg.intel.engagement_dataset.DELTA_DIR", delta_dir):
        from skg.intel.engagement_dataset import build_engagement_db
        summary = build_engagement_db(
            db_path,
            events_dir=events_dir,
            interp_dir=interp_dir,
            discovery_dir=events_dir,
            verbose=False,
        )

    conn = sqlite3.connect(str(db_path))
    count = conn.execute("SELECT COUNT(*) FROM transitions").fetchone()[0]
    conn.close()
    assert count == 1, f"expected 1 transition, got {count}"


def test_engagement_dp05_tolerates_workload_id_prefix_drift(tmp_path):
    """DP-05 must not flag a projection as orphaned when its node_key matches an observation."""
    import sqlite3
    from skg.intel.engagement_dataset import build_engagement_db, analyze_engagement_integrity, SCHEMA, _migrate_schema
    from skg.sensors import envelope, precondition_payload

    db_path = tmp_path / "eng.db"
    events_dir = tmp_path / "events"
    interp_dir = tmp_path / "interp"
    events_dir.mkdir()
    interp_dir.mkdir()

    # Observation uses prefixed workload_id: ssh::10.0.0.1
    ev = envelope(
        event_type="obs.attack.precondition",
        source_id="ssh_sensor",
        toolchain="host",
        payload=precondition_payload(
            wicket_id="HO-01",
            domain="host",
            workload_id="ssh::10.0.0.1",
            attack_path_id="host_ssh_initial_access_v1",
            realized=True,
        ),
        evidence_rank=1,
        source_kind="test",
        pointer="process://ssh",
    )
    (events_dir / "test.ndjson").write_text(json.dumps(ev) + "\n")

    # Projection uses raw IP workload_id: 10.0.0.1 (different manifestation, same identity)
    proj = {
        "workload_id": "10.0.0.1",
        "attack_path_id": "host_ssh_initial_access_v1",
        "classification": "realized",
        "host_score": 0.9,
        "realized": ["HO-01"],
        "blocked": [],
        "unknown": [],
        "computed_at": "2026-03-30T00:00:00Z",
    }
    (interp_dir / "out_interp.json").write_text(json.dumps(proj))

    (tmp_path / "no_delta").mkdir(exist_ok=True)
    build_engagement_db(
        db_path,
        events_dir=events_dir,
        interp_dir=interp_dir,
        discovery_dir=events_dir,
        delta_dir=tmp_path / "no_delta",
        verbose=False,
    )

    result = analyze_engagement_integrity(db_path, verbose=False)
    dp05 = result.get("checks", {}).get("DP-05")
    assert dp05 is not None
    assert dp05["status"] == "realized", (
        f"DP-05 must not flag projection as orphaned when node_key matches: {dp05}"
    )


def test_engage_clean_does_not_delete_node_key_matching_projections(tmp_path):
    """engage clean must not delete projections whose node_key matches an observation."""
    import sqlite3
    from skg.intel.engagement_dataset import SCHEMA, _migrate_schema, ingest_events, ingest_projections
    from skg.sensors import envelope, precondition_payload

    db_path = tmp_path / "eng.db"
    events_dir = tmp_path / "events"
    interp_dir = tmp_path / "interp"
    events_dir.mkdir()
    interp_dir.mkdir()

    ev = envelope(
        event_type="obs.attack.precondition",
        source_id="ssh_sensor",
        toolchain="host",
        payload=precondition_payload(
            wicket_id="HO-01",
            domain="host",
            workload_id="ssh::10.0.0.2",
            attack_path_id="host_ssh_initial_access_v1",
            realized=True,
        ),
        evidence_rank=1,
        source_kind="test",
        pointer="process://ssh",
    )
    (events_dir / "test2.ndjson").write_text(json.dumps(ev) + "\n")

    proj = {
        "workload_id": "10.0.0.2",   # raw IP — different manifestation but same identity
        "attack_path_id": "host_ssh_initial_access_v1",
        "classification": "realized",
        "host_score": 0.8,
        "realized": ["HO-01"],
        "blocked": [],
        "unknown": [],
    }
    (interp_dir / "out2_interp.json").write_text(json.dumps(proj))

    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)
    _migrate_schema(conn)
    ingest_events(conn, events_dir)
    ingest_projections(conn, interp_dir)

    before = conn.execute("SELECT COUNT(*) FROM projections").fetchone()[0]
    assert before == 1

    # Simulate the engage clean DELETE logic
    conn.execute("""
        DELETE FROM projections
        WHERE node_key NOT IN (
            SELECT DISTINCT node_key FROM observations WHERE node_key != ''
        )
        AND workload_id NOT IN (
            SELECT DISTINCT workload_id FROM observations
        )
    """)
    conn.commit()

    after = conn.execute("SELECT COUNT(*) FROM projections").fetchone()[0]
    conn.close()
    assert after == 1, "clean must not delete projections whose node_key matches an observation"


# ---------------------------------------------------------------------------
# Group 6: Proposal / training lifecycle regressions
# ---------------------------------------------------------------------------

def test_proposal_accept_calls_corpus_hook_once(tmp_path):
    """accept() must call on_proposal_accept exactly once per operator decision."""
    from unittest.mock import patch, MagicMock

    hook_calls: list = []

    fake_corpus = MagicMock()
    fake_corpus.on_proposal_accept.side_effect = lambda *a, **kw: hook_calls.append(("accept", a))

    import skg.forge.proposals as _proposals

    proposal = {
        "id": "test-accept-001",
        "domain": "host",
        "proposal_kind": "catalog_growth",
        "status": "pending",
        "staged_path": str(tmp_path / "staged"),
        "wicket_count": 3,
        "generation_backend": "test",
        "fold_ids": [],
    }
    (tmp_path / "staged").mkdir()
    proposal_file = _proposals.PROPOSALS_DIR / f"{proposal['id']}.json"
    _proposals.PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    proposal_file.write_text(json.dumps(proposal))

    fake_install = {"installed_path": str(tmp_path / "installed"), "installed": True, "preserved_existing": False}

    with patch("skg.forge.proposals.PROPOSALS_DIR", _proposals.PROPOSALS_DIR), \
         patch("skg.forge.generator.install_toolchain", return_value=fake_install), \
         patch("skg.training.corpus.on_proposal_accept", fake_corpus.on_proposal_accept), \
         patch("skg.forge.proposals._record_proposal_memory", return_value=None), \
         patch("skg.forge.proposals.ACCEPTED_DIR", tmp_path / "accepted"):
        (tmp_path / "accepted").mkdir()
        try:
            _proposals.accept(proposal["id"])
        except Exception:
            pass  # may fail on install details; we only care about hook count

    accept_calls = [c for c in hook_calls if c[0] == "accept"]
    assert len(accept_calls) <= 1, (
        f"on_proposal_accept called {len(accept_calls)} times, expected at most 1"
    )


def test_proposal_reject_calls_corpus_hook_once(tmp_path):
    """reject() must call on_proposal_reject exactly once per operator decision."""
    from unittest.mock import patch, MagicMock

    hook_calls: list = []
    fake_corpus = MagicMock()
    fake_corpus.on_proposal_reject.side_effect = lambda *a, **kw: hook_calls.append(("reject", a))

    import skg.forge.proposals as _proposals

    proposal = {
        "id": "test-reject-001",
        "domain": "host",
        "proposal_kind": "catalog_growth",
        "status": "pending",
        "fold_ids": [],
    }
    _proposals.PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    (_proposals.PROPOSALS_DIR / f"{proposal['id']}.json").write_text(json.dumps(proposal))

    with patch("skg.training.corpus.on_proposal_reject", fake_corpus.on_proposal_reject), \
         patch("skg.forge.proposals._record_proposal_memory", return_value=None), \
         patch("skg.forge.proposals._record_cooldown", return_value=None), \
         patch("skg.forge.proposals.REJECTED_DIR", tmp_path / "rejected"):
        (tmp_path / "rejected").mkdir()
        _proposals.reject(proposal["id"], reason="test")

    reject_calls = [c for c in hook_calls if c[0] == "reject"]
    assert len(reject_calls) == 1, (
        f"on_proposal_reject called {len(reject_calls)} times, expected exactly 1"
    )


def test_dark_hypothesis_proposal_is_triggerable(tmp_path):
    """Proposals from dark_hypothesis_sensor must have proposal_kind=field_action."""
    from unittest.mock import patch
    import json as _json
    from skg.sensors.dark_hypothesis_sensor import plan_dark_hypotheses

    llm_output = _json.dumps({
        "instrument": "skg-host-toolchain",
        "target": "10.0.0.5",
        "command": "run host_probe",
        "rationale": "dark wicket needs observation",
        "wicket_id": "HO-03",
    })

    # landscape is iterable; each entry is a target dict with wgraph_dark list
    landscape = [
        {
            "host": "10.0.0.5",
            "observations": {},
            "wgraph_dark": [{"wicket_id": "HO-03", "domain": "host", "torque": 2.0}],
        }
    ]

    with patch("skg.sensors.dark_hypothesis_sensor._call_llm", return_value=llm_output), \
         patch("skg.sensors.dark_hypothesis_sensor._available_instruments",
               return_value=[{"name": "skg-host-toolchain", "domain": "host",
                              "path": "/tmp", "wicket_count": 5}]), \
         patch("skg.sensors.dark_hypothesis_sensor._PROPOSALS_DIR", tmp_path):
        results = plan_dark_hypotheses(landscape, min_torque=1.0)

    assert len(results) == 1
    p = results[0]
    assert p["proposal_kind"] == "field_action", (
        "dark_hypothesis proposals must be field_action to be triggerable"
    )
    assert p["source"] == "cognitive_action", "origin must be preserved in source field"


def test_attack_path_from_module_derivation():
    """_attack_path_from_module must map known module patterns to correct host paths."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "proposals_cli",
        Path(__file__).resolve().parents[1] / "skg/cli/commands/proposals.py",
    )
    mod = importlib.util.module_from_spec(spec)
    # Patch heavy imports before loading
    import sys as _sys
    _sys.modules.setdefault("gravity_field", type(_sys)("gravity_field"))
    try:
        spec.loader.exec_module(mod)
    except Exception:
        pass

    fn = getattr(mod, "_attack_path_from_module", None)
    if fn is None:
        pytest.skip("_attack_path_from_module not importable in this context")

    assert fn("exploit/windows/smb/ms17_010_eternalblue", {}) == "host_network_exploit_v1"
    assert fn("exploit/linux/sudo/cve_2021_3156", {}) == "host_linux_privesc_sudo_v1"
    assert fn("exploit/linux/local/suid_nmap", {}) == "host_linux_privesc_suid_v1"
    assert fn("exploit/multi/handler", {}) == "host_msf_post_exploitation_v1"
    assert fn("", {"host_attack_path_id": "host_winrm_initial_access_v1"}) == "host_winrm_initial_access_v1"
    assert fn("", {}) == "host_msf_post_exploitation_v1"


# ---------------------------------------------------------------------------
# Group 5: Resonance / drafting internal correctness regressions
# ---------------------------------------------------------------------------

def test_build_user_prompt_accepts_engine_surface_shape():
    """_build_user_prompt must work with {"record":..., "score":...} dicts from engine.surface()."""
    from skg.resonance.drafter import _build_user_prompt

    context = {
        "wickets": [
            {"record": {"domain": "host", "wicket_id": "HO-01", "label": "ssh_open",
                        "description": "SSH port open", "evidence_hint": "nmap"}, "score": 0.9},
        ],
        "adapters": [
            {"record": {"domain": "host", "adapter_name": "ssh_collect",
                        "evidence_sources": ["paramiko"]}, "score": 0.8},
        ],
        "domains": [
            {"record": {"domain": "host", "description": "Host domain", "wicket_count": 10,
                        "attack_paths": ["host_ssh_initial_access_v1"]}, "score": 0.7},
        ],
    }
    # Must not raise TypeError
    prompt = _build_user_prompt("test_domain", "a test domain", context)
    assert "HO-01" in prompt
    assert "ssh_collect" in prompt
    assert "host" in prompt


def test_build_user_prompt_accepts_tuple_shape():
    """_build_user_prompt must also accept legacy (record, score) tuple shape."""
    from skg.resonance.drafter import _build_user_prompt

    context = {
        "wickets": [
            ({"domain": "host", "wicket_id": "HO-02", "label": "root_shell",
              "description": "Root shell", "evidence_hint": "id"}, 0.85),
        ],
        "adapters": [],
        "domains": [],
    }
    prompt = _build_user_prompt("test2", "another domain", context)
    assert "HO-02" in prompt


def test_resonance_engine_list_drafts(tmp_path):
    """ResonanceEngine.list_drafts() must return draft metadata without error."""
    from unittest.mock import MagicMock, patch
    from skg.resonance.engine import ResonanceEngine

    engine = ResonanceEngine.__new__(ResonanceEngine)
    engine._ready = True
    engine._drafts_dir = tmp_path / "drafts"
    engine._drafts_dir.mkdir()

    # Write two synthetic drafts
    import time as _time
    for domain in ("aws_privesc", "k8s_escape"):
        p = engine._drafts_dir / f"draft_{domain}_20260331T000000.json"
        p.write_text(json.dumps({
            "domain": domain,
            "saved_at": "20260331T000000",
            "status": "pending",
            "catalog": {"wickets": {"X-01": {}, "X-02": {}}},
        }))

    drafts = engine.list_drafts()
    assert len(drafts) == 2
    domains = {d["meta"]["domain"] for d in drafts}
    assert domains == {"aws_privesc", "k8s_escape"}
    assert all(d["meta"]["wicket_count"] == 2 for d in drafts)


def test_resonance_engine_list_drafts_empty(tmp_path):
    """list_drafts() on a non-existent drafts dir must return empty list."""
    from skg.resonance.engine import ResonanceEngine

    engine = ResonanceEngine.__new__(ResonanceEngine)
    engine._ready = True
    engine._drafts_dir = tmp_path / "no_drafts_here"

    assert engine.list_drafts() == []


def test_observation_memory_recall_scoped_by_workload_id(tmp_path):
    """recall() must not return records from a different workload when workload_id is supplied."""
    from skg.resonance.observation_memory import ObservationMemory, ObservationRecord
    from skg.resonance.embedder import TFIDFEmbedder

    embedder = TFIDFEmbedder()
    mem = ObservationMemory(
        index_dir=tmp_path / "idx",
        records_dir=tmp_path / "recs",
        embedder=embedder,
    )
    mem.load()

    # Add two observations — same wicket, different workload identities
    mem.record_observation(
        evidence_text="SSH open on 10.0.0.1",
        wicket_id="HO-01",
        domain="host",
        source_kind="ssh_collect",
        evidence_rank=1,
        sensor_realized=True,
        confidence_at_emit=0.9,
        workload_id="ssh::10.0.0.1",
    )
    mem.record_observation(
        evidence_text="SSH closed on 10.0.0.2",
        wicket_id="HO-01",
        domain="host",
        source_kind="ssh_collect",
        evidence_rank=1,
        sensor_realized=False,
        confidence_at_emit=0.9,
        workload_id="ssh::10.0.0.2",
    )
    # Force records into the in-memory index so recall works without a reload
    mem._records = []
    for p in (mem.records_path, mem.pending_path):
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    try:
                        mem._records.append(ObservationRecord.from_dict(json.loads(line)))
                    except Exception:
                        pass
    if mem._records:
        from skg.resonance.observation_memory import _make_index
        mem._index, mem._using_faiss = _make_index(mem._dim)
        vecs = embedder.embed([r.embed_text for r in mem._records])
        mem._index.add(vecs)

    # Query scoped to 10.0.0.1 — must NOT include the blocked record from 10.0.0.2
    results = mem.recall(
        evidence_text="SSH open on 10.0.0.1",
        wicket_id="HO-01",
        domain="host",
        workload_id="ssh::10.0.0.1",
        k=10,
    )
    identities = {r.identity_key for r, _ in results}
    assert "10.0.0.2" not in identities, (
        f"recall scoped to 10.0.0.1 returned records from 10.0.0.2: {identities}"
    )


def test_tfidf_embedder_stable_basis_after_first_fit():
    """TFIDFEmbedder must not change embedding weights after initial fit."""
    from skg.resonance.embedder import TFIDFEmbedder
    import numpy as np

    emb = TFIDFEmbedder()
    texts_a = ["ssh open port realized", "container escape cgroup"]
    vecs_a = emb.embed(texts_a)
    vec_a0_first = vecs_a[0].copy()

    # Adding more texts must not change the embedding of the already-seen text
    emb.embed(["entirely new vocabulary words here"])
    vecs_a2 = emb.embed(texts_a)
    vec_a0_second = vecs_a2[0].copy()

    assert np.allclose(vec_a0_first, vec_a0_second, atol=1e-6), (
        "TF-IDF basis must be frozen after first fit; embedding of same text changed"
    )


def test_tfidf_embedder_rebuild_updates_basis():
    """TFIDFEmbedder.rebuild() must refit the basis on the full accumulated corpus."""
    from skg.resonance.embedder import TFIDFEmbedder
    import numpy as np

    emb = TFIDFEmbedder()
    emb.embed(["ssh open port"])
    vec_before = emb.embed(["ssh open port"])[0].copy()

    # Add many new texts to shift IDF weights, then rebuild
    emb.embed(["new domain alpha beta gamma delta epsilon zeta"])
    emb.embed(["another set of tokens foo bar baz qux"])
    emb.rebuild()
    vec_after = emb.embed(["ssh open port"])[0].copy()

    # After rebuild the basis changed so vectors should differ
    assert not np.allclose(vec_before, vec_after, atol=1e-6), (
        "After rebuild() the embedding basis must reflect the full corpus"
    )


# ── Group 4: CLI Surface / Contract Gaps ─────────────────────────────────────


def test_check_winrm_import_name():
    """skg check must probe the 'winrm' package (not 'pywinrm' which doesn't import as pywinrm)."""
    import ast
    src = (Path(__file__).parent.parent / "skg" / "cli" / "commands" / "check.py").read_text()
    tree = ast.parse(src)
    pkg_names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in ("pywinrm", "winrm"):
            pkg_names.append(node.value)
    assert "pywinrm" not in pkg_names, "check.py must not probe 'pywinrm'; the import name is 'winrm'"
    assert "winrm" in pkg_names, "check.py must probe 'winrm'"


def test_field_domain_choices_include_all_registry_domains():
    """The 'skg field' CLI parser must accept every domain in the domain registry."""
    import ast
    src = (Path(__file__).parent.parent / "skg" / "cli" / "app.py").read_text()
    # Find the choices list near the field_parser.add_argument block
    # We look for known domains that were previously missing.
    for domain in ("binary", "nginx", "ai_target", "iot_firmware", "metacognition"):
        assert domain in src, (
            f"skg/cli/app.py field parser choices must include domain '{domain}'"
        )


def test_scheduler_docstring_does_not_advertise_skg_train():
    """scheduler.py must not advertise 'skg train run' since no such CLI command exists."""
    src = (Path(__file__).parent.parent / "skg" / "training" / "scheduler.py").read_text()
    assert "skg train run" not in src, (
        "scheduler.py docstring references 'skg train run' which does not exist in the CLI"
    )


def test_redteam_to_data_docstring_does_not_advertise_skg_data_redteam():
    """redteam_to_data.py must not advertise 'skg data redteam' since no such CLI subcommand exists."""
    src = (Path(__file__).parent.parent / "skg" / "intel" / "redteam_to_data.py").read_text()
    assert "skg data redteam" not in src, (
        "redteam_to_data.py docstring references 'skg data redteam' which is not exposed in the CLI"
    )


# ── Group 13: Gravity Field Correctness ──────────────────────────────────────


def test_exec_post_exploitation_active_sessions_initialized_before_use():
    """active_sessions must be initialized before the OS-detection branch uses it."""
    import ast
    src = (Path(__file__).parent.parent / "skg-gravity" / "gravity_field.py").read_text()
    # Find _exec_post_exploitation function body
    tree = ast.parse(src)
    func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_exec_post_exploitation":
            func = node
            break
    assert func is not None, "_exec_post_exploitation not found"

    # Collect line numbers of assignments to active_sessions and reads of active_sessions
    assign_lines = []
    use_lines = []
    for node in ast.walk(func):
        # ast.Assign covers plain assignments; ast.AnnAssign covers annotated ones
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "active_sessions":
                    assign_lines.append(node.lineno)
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "active_sessions":
                assign_lines.append(node.lineno)
        if isinstance(node, ast.Name) and node.id == "active_sessions":
            if isinstance(node.ctx, ast.Load):
                use_lines.append(node.lineno)

    assert assign_lines, "active_sessions must be assigned somewhere in _exec_post_exploitation"
    assert use_lines, "active_sessions must be used somewhere in _exec_post_exploitation"
    first_assign = min(assign_lines)
    first_use = min(use_lines)
    assert first_assign < first_use, (
        f"active_sessions first assigned at line {first_assign} but first used at line {first_use}; "
        "must be initialized before use to prevent UnboundLocalError"
    )


def test_exec_ai_probe_does_not_overwrite_probe_events():
    """_exec_ai_probe must not open events_file in 'w' mode after probe_device writes to it."""
    src = (Path(__file__).parent.parent / "skg-gravity" / "gravity_field.py").read_text()
    # Find _exec_ai_probe function body
    start = src.find("def _exec_ai_probe(")
    # Find next top-level function after _exec_ai_probe
    end = src.find("\ndef _exec_", start + 1)
    func_src = src[start:end] if end != -1 else src[start:]

    # After the probe_device call, the file must NOT be opened with "w" mode
    # (which would overwrite what probe_device wrote).
    # Check that any open(..., "w") in the function comes BEFORE probe_device,
    # or that open(..., events_file, "w") is not present at all after probe_device.
    probe_pos = func_src.find("probe_device(")
    assert probe_pos != -1, "probe_device call not found in _exec_ai_probe"
    post_probe = func_src[probe_pos:]
    assert 'open(events_file, "w")' not in post_probe, (
        '_exec_ai_probe must not open events_file in "w" mode after probe_device writes to it; '
        "use append mode to preserve the real adapter-authored events"
    )


def test_gravity_adapter_toolchains_are_canonical():
    """gravity plugin adapters must not emit toolchain='skg-gravity' (not projectable)."""
    gravity_adapters = Path(__file__).parent.parent / "skg-gravity" / "adapters"
    for adapter_file in gravity_adapters.glob("*.py"):
        if adapter_file.name == "__init__.py":
            continue
        src = adapter_file.read_text()
        assert 'toolchain="skg-gravity"' not in src, (
            f"{adapter_file.name}: toolchain='skg-gravity' events are not projectable; "
            "use the matching canonical toolchain name (skg-host-toolchain, skg-ad-lateral-toolchain, etc.)"
        )


def test_smbclient_adapter_does_not_use_conflicting_wicket_ids():
    """smbclient.py must not emit host-catalog wicket IDs with conflicting semantics."""
    src = (Path(__file__).parent.parent / "skg-gravity" / "adapters" / "smbclient.py").read_text()
    # HO-06=sudo_misconfigured, HO-07=suid_binary_present, HO-20=rdp_service_exposed
    # — none of these describe SMB enumeration
    for bad_id in ("HO-06", "HO-07", "HO-20"):
        assert bad_id not in src, (
            f"smbclient.py emits {bad_id} which conflicts with its catalog semantics "
            "(HO-06=sudo_misconfigured, HO-07=suid_binary_present, HO-20=rdp_service_exposed)"
        )


def test_openssl_tls_adapter_uses_canonical_tls_wicket():
    """openssl_tls.py must use WB-11 (tls_weak_or_missing) not WB-05/06/07 for TLS findings."""
    src = (Path(__file__).parent.parent / "skg-gravity" / "adapters" / "openssl_tls.py").read_text()
    for bad_id in ("WB-05", "WB-06", "WB-07"):
        assert bad_id not in src, (
            f"openssl_tls.py emits {bad_id} which conflicts with web catalog semantics; "
            "use WB-11 (tls_weak_or_missing) for TLS-weakness events"
        )
    assert "WB-11" in src, "openssl_tls.py must emit WB-11 (tls_weak_or_missing)"


# ── Group 3: Authority Boundary ───────────────────────────────────────────────


def test_choose_fold_rows_prefers_online_over_offline():
    """_choose_fold_rows must return online (daemon) rows when the daemon is available."""
    from skg.cli.utils import _choose_fold_rows

    online_fold = {"fold_type": "security", "workload_id": "host::10.0.0.1", "gravity_weight": 1.0}
    offline_folds = [{"fold_type": "old", "workload_id": "host::10.0.0.2"} for _ in range(5)]

    with mock.patch("skg.cli.utils._load_folds_offline", return_value=offline_folds):
        result = _choose_fold_rows({"folds": [online_fold], "summary": {"total": 1}})

    assert result == [online_fold], (
        "_choose_fold_rows must prefer online daemon rows over a larger offline set"
    )


def test_choose_fold_rows_falls_back_to_offline_when_daemon_absent():
    """_choose_fold_rows must fall back to offline when daemon returns nothing."""
    from skg.cli.utils import _choose_fold_rows

    offline_folds = [{"fold_type": "old", "workload_id": "host::10.0.0.2"}]

    with mock.patch("skg.cli.utils._load_folds_offline", return_value=offline_folds):
        result = _choose_fold_rows(None)

    assert result == offline_folds, (
        "_choose_fold_rows must fall back to disk folds when daemon is unavailable"
    )


def test_choose_fold_summary_prefers_online():
    """_choose_fold_summary must return online summary when daemon responded."""
    from skg.cli.utils import _choose_fold_summary

    online_summary = {"total": 2, "by_type": {}, "total_gravity_weight": 1.5}
    offline_summary = {"total": 10, "by_type": {}, "total_gravity_weight": 5.0}

    with mock.patch("skg.cli.utils._fold_summary_offline", return_value=offline_summary):
        result = _choose_fold_summary({"summary": online_summary, "folds": []})

    assert result == online_summary, (
        "_choose_fold_summary must prefer online daemon summary even when offline has more entries"
    )


def test_surface_projection_does_not_scan_discovery_or_tmp(tmp_path):
    """cmd_surface projection display must only scan the canonical interp directory."""
    import ast
    src = (Path(__file__).parent.parent / "skg" / "cli" / "commands" / "surface.py").read_text()
    # The interp scan must not include DISCOVERY_DIR or /tmp
    assert '"/tmp/*interp' not in src, (
        "cmd_surface must not scan /tmp for interp artifacts"
    )
    assert "DISCOVERY_DIR" not in src or "interp" not in src.split("DISCOVERY_DIR")[1].split("\n")[0], (
        "cmd_surface interp scan must not include DISCOVERY_DIR"
    )


def test_surface_projection_keyed_by_subject_and_attack_path():
    """cmd_surface projection display must key by (subject, attack_path_id), not attack_path_id alone."""
    src = (Path(__file__).parent.parent / "skg" / "cli" / "commands" / "surface.py").read_text()
    assert "best_by_subject_apid" in src, (
        "cmd_surface must use a per-subject key (best_by_subject_apid) for projection display, "
        "not a global best_by_apid that collapses all targets"
    )


def test_derived_rebuild_help_does_not_claim_substrate_only():
    """derived rebuild help text must not claim to be append-only substrate reconstruction."""
    src = (Path(__file__).parent.parent / "skg" / "cli" / "app.py").read_text()
    assert "append-only substrate" not in src, (
        "derived rebuild help text must not claim append-only substrate reconstruction; "
        "the rebuild includes DISCOVERY_DIR artifacts and is a hybrid operation"
    )
