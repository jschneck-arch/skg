from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import mock


def test_gravity_failure_reporter_writes_ndjson():
    from skg.gravity.failures import GravityFailureReporter

    with tempfile.TemporaryDirectory() as td:
        reporter = GravityFailureReporter(
            run_id="run-1",
            cycle_num=2,
            state_dir=Path(td),
            printer=lambda *_args, **_kwargs: None,
        )
        reporter.emit(
            "fold_detector",
            "Fold detector unavailable",
            target_ip="10.0.0.7",
            context={"phase": "boot"},
        )

        payload = json.loads(reporter.path.read_text().strip())

    assert reporter.count() == 1
    assert payload["run_id"] == "run-1"
    assert payload["cycle"] == 2
    assert payload["stage"] == "fold_detector"
    assert payload["target_ip"] == "10.0.0.7"


def test_emit_follow_on_proposals_uses_supplied_generator():
    from skg.gravity.runtime import emit_follow_on_proposals

    captured = {}

    def _fake_generate_exploit_proposals(**kwargs):
        captured.update(kwargs)
        return [{"id": "prop-follow-1"}]

    generated = emit_follow_on_proposals(
        concurrent_results={
            "web": {
                "follow_on_paths": [{
                    "path_id": "demo_path",
                    "port": 443,
                    "kwargs": {"winrm_user": "alice"},
                }],
            }
        },
        ip="10.0.0.7",
        out_path=Path("/tmp"),
        run_id="run-1",
        load_wicket_states=lambda _ip: {"HO-01": {"status": "realized"}},
        generate_exploit_proposals=_fake_generate_exploit_proposals,
        get_lhost=lambda: "10.0.0.1",
        interactive_review=None,
        proposals_dir=Path("/tmp/does-not-exist-follow-on"),
        print_fn=lambda *_args, **_kwargs: None,
        reporter=None,
    )

    assert generated == [{"id": "prop-follow-1"}]
    assert captured["path_id"] == "demo_path"
    assert captured["target_ip"] == "10.0.0.7"
    assert captured["realized_wickets"] == ["HO-01"]
    assert captured["lhost"] == "10.0.0.1"
    assert captured["winrm_user"] == "alice"


def test_emit_auxiliary_proposals_uses_contract_backed_helper():
    import skg.gravity.runtime as runtime_module

    captured = {}

    def _fake_create_msf_action_proposal(**kwargs):
        captured.update(kwargs)
        return {"id": "prop-aux-1"}, {"path": "/tmp/demo.rc"}

    with tempfile.TemporaryDirectory() as td:
        with mock.patch.object(
            runtime_module,
            "create_msf_action_proposal",
            side_effect=_fake_create_msf_action_proposal,
        ) as helper:
            created = runtime_module.emit_auxiliary_proposals(
                ip="10.0.0.7",
                target={"services": [{"port": 443, "service": "https"}]},
                run_id="run-1",
                out_path=Path(td),
                auxiliary_map={
                    "web_http_probe_v1": [{
                        "module": "auxiliary/scanner/http/http_version",
                        "requires": ["WB-06"],
                        "options": {"RPORT": "443", "TARGETURI": "/"},
                        "confidence": 0.8,
                    }],
                },
                lhost="10.0.0.1",
                load_wicket_states=lambda _ip: {"WB-06": {"status": "realized"}},
                proposals_dir=Path(td) / "proposals",
                print_fn=lambda *_args, **_kwargs: None,
                reporter=None,
            )

    assert helper.call_count == 1
    assert created == [{"id": "prop-aux-1"}]
    assert captured["contract_name"] == "msf_rc"
    assert captured["action"]["module"] == "auxiliary/scanner/http/http_version"
    assert captured["action"]["target_ip"] == "10.0.0.7"


def test_execute_triggered_proposals_marks_missing_rc_and_records_failure():
    from skg.gravity.failures import GravityFailureReporter
    from skg.gravity.runtime import execute_triggered_proposals

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        proposals_dir = root / "proposals"
        out_dir = root / "out"
        proposals_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        proposal_path = proposals_dir / "prop-1.json"
        proposal_path.write_text(json.dumps({
            "id": "prop-1",
            "proposal_kind": "field_action",
            "status": "triggered",
            "category": "runtime_observation",
            "action": {
                "target_ip": "10.0.0.7",
                "rc_file": str(root / "missing.rc"),
            },
        }))

        reporter = GravityFailureReporter(
            run_id="run-1",
            cycle_num=1,
            state_dir=root,
            printer=lambda *_args, **_kwargs: None,
        )
        executed = execute_triggered_proposals(
            out_path=out_dir,
            run_id="run-1",
            focus_target=None,
            proposals_dir=proposals_dir,
            print_fn=lambda *_args, **_kwargs: None,
            reporter=reporter,
        )
        updated = json.loads(proposal_path.read_text())

    assert executed == []
    assert updated["status"] == "error_missing_rc"
    assert "RC file missing" in updated["error"]
    assert reporter.count() == 1


def test_domain_registry_loads_native_domains_from_config():
    import skg.core.domain_registry as registry

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg_dir = root / "cfg"
        home_dir = root / "home"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        home_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "daemon_domains.yaml").write_text(
            "\n".join([
                "domains:",
                "  - name: web",
                "    daemon_native: false",
                "    dir: skg-web-toolchain",
                "  - name: host",
                "    daemon_native: true",
                "    dir: skg-host-toolchain",
                "    cli: skg_host.py",
                "    project_sub: [project]",
                "    interp_type: interp.host.realizability",
                "    default_path: host_ssh_initial_access_v1",
            ]),
            encoding="utf-8",
        )

        with mock.patch.object(registry, "SKG_CONFIG_DIR", cfg_dir), \
             mock.patch.object(registry, "SKG_HOME", home_dir):
            domains = registry.load_daemon_domains()
            inventory = registry.summarize_domain_inventory(registry.load_domain_inventory())

    assert list(domains.keys()) == ["host"]
    assert domains["host"]["dir"] == home_dir / "skg-host-toolchain"
    assert any(row["name"] == "web" and not row["daemon_native"] for row in inventory)


def test_derive_effective_domains_uses_services_and_postexp_artifacts():
    from skg.gravity.landscape import derive_effective_domains

    with tempfile.TemporaryDirectory() as td:
        discovery_dir = Path(td)
        (discovery_dir / "gravity_postexp_10_0_0_7_run.ndjson").write_text("{}\n", encoding="utf-8")
        domains = derive_effective_domains(
            {
                "domains": ["host"],
                "services": [
                    {"port": 443, "service": "https"},
                    {"port": 3306, "service": "mysql"},
                ],
            },
            ip="10.0.0.7",
            discovery_dir=discovery_dir,
            probe_ai=False,
        )

    assert "host" in domains
    assert "web" in domains
    assert "data_pipeline" in domains
    assert "binary_analysis" in domains
    assert "container_escape" in domains


def test_apply_first_contact_floor_sets_entropy_and_seed_wickets():
    from skg.gravity.landscape import apply_first_contact_floor

    entropy, applicable, no_nmap_history = apply_first_contact_floor(
        ip="10.0.0.7",
        entropy=3.0,
        applicable=set(),
        domain_wickets={
            "host": {"HO-01"},
            "web": {"WB-01"},
            "sysaudit": {"HO-09"},
            "ad_lateral": {"AD-01"},
        },
        discovery_dir=Path("/tmp/does-not-exist-floor"),
    )

    assert no_nmap_history is True
    assert entropy == 25.0
    assert applicable == {"HO-01", "WB-01", "HO-09", "AD-01"}


def test_rank_instruments_for_target_boosts_cold_start_nmap():
    from skg.gravity.selection import rank_instruments_for_target

    class _Instrument:
        def __init__(self, wavelength):
            self.wavelength = wavelength
            self.available = True

        def failed_to_reduce(self, _ip):
            return False

    target_row = {
        "ip": "10.0.0.7",
        "states": {},
        "applicable_wickets": {"HO-01"},
        "target": {"services": [{"port": 80, "service": "http"}], "_no_nmap_history": True},
        "unknowns": 18.0,
        "entropy": 25.0,
        "R_per_sphere": {},
        "wgraph_inst_boosts": {},
    }
    instruments = {
        "nmap": _Instrument(["HO-01"]),
        "http_collector": _Instrument(["WB-01"]),
    }

    candidates, cold_start = rank_instruments_for_target(
        target_row=target_row,
        instruments=instruments,
        focus_target=None,
        entropy_reduction_potential=lambda _inst, _ip, _states, _wids: 1.0,
        coherence_fn=lambda _name, _target: 1.0,
        reinforcement_fn=lambda _ip, _inst: 0.0,
        has_recent_artifact=lambda _pattern, _hours=6.0: False,
        discovery_dir=Path("/tmp/does-not-exist-rank"),
        cve_dir=Path("/tmp/does-not-exist-rank-cve"),
        interp_dir=Path("/tmp/does-not-exist-rank-interp"),
        print_fn=lambda *_args, **_kwargs: None,
    )

    assert cold_start is True
    assert candidates[0][1] == "nmap"
    assert candidates[0][0] >= 30.0


def test_choose_instruments_serializes_metasploit_when_interactive():
    from skg.gravity.selection import choose_instruments_for_target

    class _Instrument:
        def __init__(self):
            self.available = True

    instruments = {
        "metasploit": _Instrument(),
        "nmap": _Instrument(),
    }
    metasploit_item = (20.0, "metasploit", instruments["metasploit"])
    nmap_item = (30.0, "nmap", instruments["nmap"])

    to_run, serial_item, selected = choose_instruments_for_target(
        candidates=[nmap_item, metasploit_item],
        instruments=instruments,
        target_row={
            "target": {"_no_nmap_history": False},
            "unknowns": 4.0,
            "entropy": 12.0,
        },
        cold_start_target=False,
        coherence_fn=lambda _name, _target: 1.0,
        interactive=True,
        print_fn=lambda *_args, **_kwargs: None,
    )

    assert to_run == [nmap_item]
    assert serial_item == metasploit_item
    assert selected == [nmap_item, metasploit_item]
