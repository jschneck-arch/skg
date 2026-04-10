from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import mock

import yaml


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
    assert captured["identity_key"] == "10.0.0.7"
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
    assert captured["action"]["identity_key"] == "10.0.0.7"
    assert captured["action"]["execution_target"] == "10.0.0.7"
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


def test_execute_triggered_proposals_focus_matches_identity_alias():
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
            "identity_key": "db.internal",
            "category": "runtime_observation",
            "action": {
                "identity_key": "db.internal",
                "execution_target": "10.0.0.7",
                "target_ip": "10.0.0.7",
                "rc_file": str(root / "missing.rc"),
            },
        }))

        execute_triggered_proposals(
            out_path=out_dir,
            run_id="run-1",
            focus_target="db.internal",
            proposals_dir=proposals_dir,
            print_fn=lambda *_args, **_kwargs: None,
            reporter=None,
        )
        updated = json.loads(proposal_path.read_text())

    assert updated["status"] == "error_missing_rc"


def test_gravity_subject_rows_focus_matches_identity_alias():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "skg_gravity_field_runtime_test",
        "/opt/skg/skg-gravity/gravity_field.py",
    )
    gravity_field = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gravity_field)

    rows = gravity_field._gravity_subject_rows(
        {
            "targets": [{
                "ip": "10.0.0.7",
                "host": "10.0.0.7",
                "hostname": "db.internal",
                "services": [{"port": 3306, "service": "mysql"}],
            }],
        },
        {},
        focus_target="db.internal",
    )

    assert len(rows) == 1
    assert rows[0]["identity_key"] == "10.0.0.7"


def test_collect_observation_confirms_matches_identity_alias():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "skg_gravity_field_runtime_test",
        "/opt/skg/skg-gravity/gravity_field.py",
    )
    gravity_field = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gravity_field)

    with tempfile.TemporaryDirectory() as td:
        events_path = Path(td) / "events.ndjson"
        events_path.write_text(
            json.dumps({
                "type": "obs.attack.precondition",
                "provenance": {"evidence": {"pointer": "demo"}},
                "payload": {
                    "workload_id": "mysql::db.internal:3306::users",
                    "target_ip": "10.0.0.7",
                    "wicket_id": "DP-01",
                    "status": "realized",
                },
            }) + "\n",
            encoding="utf-8",
        )

        confirms = gravity_field._collect_observation_confirms(
            {"mysql": {"events_file": str(events_path)}},
            "db.internal",
        )

    assert len(confirms) == 1
    assert confirms[0]["identity_key"] == "db.internal"
    assert confirms[0]["workload_id"] == "mysql::db.internal:3306::users"


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


def test_domain_registry_discovers_unconfigured_toolchain_inventory():
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

        web_dir = home_dir / "skg-web-toolchain"
        (web_dir / "projections" / "web").mkdir(parents=True, exist_ok=True)
        (web_dir / "contracts" / "catalogs").mkdir(parents=True, exist_ok=True)
        (web_dir / "projections" / "web" / "run.py").write_text("def compute_web(*args, **kwargs):\n    return {}\n", encoding="utf-8")
        (web_dir / "contracts" / "catalogs" / "attack_preconditions_catalog.web.v1.json").write_text(
            json.dumps({
                "attack_paths": {
                    "web_initial_access_v1": {"id": "web_initial_access_v1"},
                }
            }),
            encoding="utf-8",
        )
        (web_dir / "forge_meta.json").write_text(
            json.dumps({
                "toolchain": "skg-web-toolchain",
                "domain": "web",
                "description": "Web toolchain",
            }),
            encoding="utf-8",
        )

        host_dir = home_dir / "skg-host-toolchain"
        (host_dir / ".venv" / "bin").mkdir(parents=True, exist_ok=True)
        (host_dir / ".venv" / "bin" / "python").write_text("", encoding="utf-8")
        (host_dir / "skg_host.py").write_text("print('host')\n", encoding="utf-8")

        with mock.patch.object(registry, "SKG_CONFIG_DIR", cfg_dir), \
             mock.patch.object(registry, "SKG_HOME", home_dir):
            inventory = registry.load_domain_inventory()
            summary = registry.summarize_domain_inventory(inventory)
            daemon_domains = registry.load_daemon_domains()

    by_name = {row["name"]: row for row in summary}
    assert "web" in by_name
    assert by_name["web"]["manifest_present"] is True
    assert by_name["web"]["projector_available"] is True
    assert by_name["web"]["catalog_count"] == 1
    assert by_name["web"]["daemon_native"] is False
    assert by_name["web"]["default_path"] == "web_initial_access_v1"
    assert "host" in daemon_domains
    assert "web" not in daemon_domains


def test_coupling_runtime_loads_config_and_validates():
    import skg.core.coupling as coupling

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg_dir = root / "cfg"
        home_dir = root / "home"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        home_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "coupling.yaml").write_text(
            "\n".join([
                "inter_local:",
                "  web:",
                "    data: 0.42",
                "intra_target:",
                "  host:",
                "    web: 0.33",
                "decay_ttl_hours:",
                "  ephemeral: 2",
                "reverse_discount: 0.5",
            ]),
            encoding="utf-8",
        )

        coupling._CONFIG_CACHE["path"] = None
        coupling._CONFIG_CACHE["mtime"] = None
        coupling._CONFIG_CACHE["payload"] = None

        with mock.patch.object(coupling, "SKG_CONFIG_DIR", cfg_dir), \
             mock.patch.object(coupling, "SKG_HOME", home_dir):
            assert coupling.coupling_value("web", "data", table="inter_local") == 0.42
            assert coupling.coupling_value("data", "web", table="inter_local") == 0.21
            assert coupling.coupling_value("host", "web", table="intra_target") == 0.33
            assert coupling.decay_ttl_hours()["ephemeral"] == 2.0
            assert coupling.validate_payload({"inter_local": {"web": {"data": 1.2}}})


def test_coupling_apply_writes_backup_and_updates_config():
    import skg.core.coupling as coupling

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg_dir = root / "cfg"
        home_dir = root / "home"
        delta_dir = root / "delta"
        snapshots_dir = delta_dir / "snapshots"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        home_dir.mkdir(parents=True, exist_ok=True)
        snapshots_dir.mkdir(parents=True, exist_ok=True)

        config_path = cfg_dir / "coupling.yaml"
        config_path.write_text(
            "\n".join([
                "intra_target:",
                "  host:",
                "    web: 0.33",
            ]),
            encoding="utf-8",
        )
        (snapshots_dir / "host.jsonl").write_text(
            json.dumps({
                "workload_id": "host::10.0.0.7",
                "wicket_states": {"HO-01": "realized"},
            }) + "\n",
            encoding="utf-8",
        )
        (snapshots_dir / "web.jsonl").write_text(
            json.dumps({
                "workload_id": "web::10.0.0.7",
                "wicket_states": {"WB-01": "realized"},
            }) + "\n",
            encoding="utf-8",
        )

        coupling._CONFIG_CACHE["path"] = None
        coupling._CONFIG_CACHE["mtime"] = None
        coupling._CONFIG_CACHE["payload"] = None

        with mock.patch.object(coupling, "SKG_CONFIG_DIR", cfg_dir), \
             mock.patch.object(coupling, "SKG_HOME", home_dir):
            result = coupling.apply_learned_intra_target(
                delta_dir=delta_dir,
                review=False,
                backup=True,
                assume_yes=True,
            )
            updated = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            backup_payload = yaml.safe_load((cfg_dir / "coupling.yaml.bak").read_text(encoding="utf-8"))

    assert result["ok"] is True
    assert result["applied"] is True
    assert backup_payload["intra_target"]["host"]["web"] == 0.33
    assert updated["intra_target"]["host"]["web"] == 1.0
    assert updated["intra_target"]["web"]["host"] == 1.0


def test_coupling_apply_review_requires_yes_outside_tty():
    import skg.core.coupling as coupling

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg_dir = root / "cfg"
        home_dir = root / "home"
        learned_path = root / "learned.yaml"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        home_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "coupling.yaml").write_text(
            "\n".join([
                "intra_target:",
                "  host:",
                "    web: 0.33",
            ]),
            encoding="utf-8",
        )
        learned_path.write_text(
            "\n".join([
                "intra_target:",
                "  host:",
                "    web: 0.66",
            ]),
            encoding="utf-8",
        )

        coupling._CONFIG_CACHE["path"] = None
        coupling._CONFIG_CACHE["mtime"] = None
        coupling._CONFIG_CACHE["payload"] = None

        fake_stdin = mock.Mock()
        fake_stdin.isatty.return_value = False
        with mock.patch.object(coupling, "SKG_CONFIG_DIR", cfg_dir), \
             mock.patch.object(coupling, "SKG_HOME", home_dir), \
             mock.patch.object(coupling.sys, "stdin", fake_stdin):
            result = coupling.apply_learned_intra_target(
                learned_file=learned_path,
                review=True,
                backup=False,
                assume_yes=False,
            )

    assert result["ok"] is False
    assert "review requested outside an interactive TTY" in result["errors"][0]


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


def test_derive_effective_domains_includes_measured_view_domains():
    from skg.gravity.landscape import derive_effective_domains

    domains = derive_effective_domains(
        {
            "domains": [],
            "services": [],
        },
        ip="10.0.0.7",
        discovery_dir=Path("/tmp/does-not-exist-view-domains"),
        view_state={
            "measured_domains": ["binary", "data"],
            "view_count": 2,
        },
        probe_ai=False,
    )

    assert "binary_analysis" in domains
    assert "data_pipeline" in domains


def test_summarize_view_nodes_aggregates_observed_tooling():
    from skg.gravity.landscape import summarize_view_nodes

    summary = summarize_view_nodes(
        [
            {
                "identity_key": "db.internal",
                "domain": "binary",
                "measured_now": {"unknown": ["BA-01"], "realized": [], "blocked": []},
                "memory_overlay": {},
                "observed_tools": {
                    "tool_names": ["checksec", "nmap"],
                    "observed_tools": [
                        {
                            "name": "checksec",
                            "instrument_names": ["binary_analysis"],
                            "domain_hints": ["binary"],
                        },
                        {
                            "name": "nmap",
                            "instrument_names": ["nmap"],
                            "domain_hints": ["host", "web"],
                            "nse_available": True,
                            "nse_script_count": 612,
                        },
                    ],
                    "domain_hints": ["binary", "web"],
                    "instrument_hints": ["binary_analysis", "nmap"],
                    "scope": "node_local",
                    "status": "realized",
                    "observed_at": "2026-03-27T01:02:03+00:00",
                },
            }
        ],
        identity_key="db.internal",
    )

    assert summary["observed_tools"]["tool_names"] == ["checksec", "nmap"]
    assert summary["observed_tools"]["instrument_hints"] == ["binary_analysis", "nmap"]
    assert summary["observed_tools"]["domain_hints"] == ["binary_analysis", "web"]
    assert summary["observed_tools"]["nse_available"] is True
    assert summary["observed_tools"]["nse_script_count"] == 612


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


def test_apply_first_contact_floor_skips_bootstrap_for_fresh_view():
    from skg.gravity.landscape import apply_first_contact_floor

    entropy, applicable, no_nmap_history = apply_first_contact_floor(
        ip="10.0.0.7",
        entropy=7.5,
        applicable={"BA-03"},
        domain_wickets={
            "host": {"HO-01"},
            "binary_analysis": {"BA-03"},
        },
        discovery_dir=Path("/tmp/does-not-exist-floor-fresh"),
        has_measured_view=True,
    )

    assert no_nmap_history is False
    assert entropy == 7.5
    assert applicable == {"BA-03"}


def test_rank_instruments_for_target_boosts_cold_start_nmap():
    from skg.gravity.selection import rank_instruments_for_target, _first_contact_entropy

    class _Instrument:
        def __init__(self, wavelength, cost=1.0):
            self.wavelength = wavelength
            self.cost = cost
            self.available = True
            self.entropy_history = {}

        def failed_to_reduce(self, _ip):
            return False

    # nmap's broader wavelength gives higher _first_contact_entropy → it ranks first.
    # Potential is physics-derived: |wavelength| / cost, not a magic constant.
    nmap_inst = _Instrument(
        ["HO-01", "HO-02", "WB-01", "WB-02", "WB-17",
         "HO-03", "HO-04", "HO-05", "HO-06", "HO-07"],
        cost=3.0,
    )
    http_inst = _Instrument(["WB-01", "WB-02"], cost=1.0)

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
        "nmap": nmap_inst,
        "http_collector": http_inst,
    }

    candidates, cold_start = rank_instruments_for_target(
        target_row=target_row,
        instruments=instruments,
        focus_target=None,
        entropy_reduction_potential=lambda _inst, _ip, _states, _wids: 0.0,
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
    # Potential is physics-derived: nmap dominates because |wavelength|/cost > http's.
    nmap_fc = _first_contact_entropy(nmap_inst)
    http_fc = _first_contact_entropy(http_inst)
    assert nmap_fc > http_fc
    assert candidates[0][0] >= nmap_fc


def test_rank_instruments_for_target_uses_fresh_view_to_avoid_cold_start():
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
        "applicable_wickets": {"BA-03"},
        "target": {"services": [], "_no_nmap_history": False},
        "unknowns": 2.0,
        "entropy": 7.5,
        "R_per_sphere": {},
        "wgraph_inst_boosts": {},
        "view_state": {
            "view_count": 1,
            "measured_domains": ["binary_analysis"],
            "measured_unknowns": 3.0,
        },
    }
    instruments = {
        "nmap": _Instrument(["HO-01"]),
        "binary_analysis": _Instrument(["BA-03"]),
    }

    candidates, cold_start = rank_instruments_for_target(
        target_row=target_row,
        instruments=instruments,
        focus_target=None,
        entropy_reduction_potential=lambda _inst, _ip, _states, _wids: 1.0,
        coherence_fn=lambda _name, _row: 1.0,
        reinforcement_fn=lambda _ip, _inst: 0.0,
        has_recent_artifact=lambda _pattern, _hours=6.0: False,
        discovery_dir=Path("/tmp/does-not-exist-rank-fresh"),
        cve_dir=Path("/tmp/does-not-exist-rank-fresh-cve"),
        interp_dir=Path("/tmp/does-not-exist-rank-fresh-interp"),
        print_fn=lambda *_args, **_kwargs: None,
    )

    assert cold_start is False
    assert {name for _, name, _ in candidates} == {"nmap", "binary_analysis"}


def test_rank_instruments_for_target_boosts_observed_tool_hints():
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
        "applicable_wickets": {"HO-01", "BA-03"},
        "target": {"services": [{"port": 22, "service": "ssh"}], "_no_nmap_history": False},
        "unknowns": 2.0,
        "entropy": 8.0,
        "R_per_sphere": {},
        "wgraph_inst_boosts": {},
        "view_state": {
            "view_count": 1,
            "measured_domains": ["host"],
            "measured_unknowns": 2.0,
            "observed_tools": {
                "tool_names": ["checksec", "nmap"],
                "observed_tools": [
                    {
                        "name": "checksec",
                        "instrument_names": ["binary_analysis"],
                        "domain_hints": ["binary"],
                    },
                    {
                        "name": "nmap",
                        "instrument_names": ["nmap"],
                        "domain_hints": ["host", "web"],
                        "nse_available": True,
                    },
                ],
                "domain_hints": ["binary", "host", "web"],
                "instrument_hints": ["binary_analysis", "nmap"],
                "nse_available": True,
            },
        },
    }
    instruments = {
        "nmap": _Instrument(["HO-01"]),
        "binary_analysis": _Instrument(["BA-03"]),
    }

    candidates, cold_start = rank_instruments_for_target(
        target_row=target_row,
        instruments=instruments,
        focus_target=None,
        entropy_reduction_potential=lambda _inst, _ip, _states, _wids: 1.0,
        coherence_fn=lambda _name, _row: 1.0,
        reinforcement_fn=lambda _ip, _inst: 0.0,
        has_recent_artifact=lambda _pattern, _hours=6.0: False,
        discovery_dir=Path("/tmp/does-not-exist-rank-tools"),
        cve_dir=Path("/tmp/does-not-exist-rank-tools-cve"),
        interp_dir=Path("/tmp/does-not-exist-rank-tools-interp"),
        print_fn=lambda *_args, **_kwargs: None,
    )

    assert cold_start is False
    assert [name for _, name, _ in candidates] == ["binary_analysis", "nmap"]
    assert candidates[0][0] > candidates[1][0]


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
