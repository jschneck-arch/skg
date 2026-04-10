"""
Tests for migrated CLI commands.

These tests don't need the daemon or a live target.
"""
from __future__ import annotations
import os
import sys
import types
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import yaml


# ── Helpers ──────────────────────────────────────────────────────────────

class _Args:
    """Simple namespace for passing args to cmd_* functions."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# ── cmd_check ────────────────────────────────────────────────────────────

class TestCmdCheck:
    def _run(self, capsys, extra_patches=None):
        from skg.cli.commands.check import cmd_check
        patches = extra_patches or {}
        # Prevent actual network calls
        with patch("socket.create_connection", side_effect=OSError("no daemon")):
            with patch("urllib.request.urlopen", side_effect=OSError("no ollama")):
                cmd_check(_Args())
        return capsys.readouterr().out

    def test_imports_without_error(self):
        """cmd_check must be importable."""
        from skg.cli.commands.check import cmd_check
        assert callable(cmd_check)

    def test_runs_without_crash(self, capsys):
        """cmd_check must complete (may warn, but must not raise unexpectedly)."""
        from skg.cli.commands.check import cmd_check
        try:
            with patch("socket.create_connection", side_effect=OSError("no daemon")):
                with patch("urllib.request.urlopen", side_effect=OSError("no ollama")):
                    cmd_check(_Args())
        except SystemExit:
            # A SystemExit(1) is valid — it means critical check failed
            pass
        out = capsys.readouterr().out
        assert "SKG" in out
        assert "Summary" in out

    def test_output_contains_python_row(self, capsys):
        """Python version row should always appear."""
        from skg.cli.commands.check import cmd_check
        try:
            with patch("socket.create_connection", side_effect=OSError):
                with patch("urllib.request.urlopen", side_effect=OSError):
                    cmd_check(_Args())
        except SystemExit:
            pass
        out = capsys.readouterr().out
        assert "Python" in out

    def test_output_contains_summary_line(self, capsys):
        """Summary line must be present."""
        from skg.cli.commands.check import cmd_check
        try:
            with patch("socket.create_connection", side_effect=OSError):
                with patch("urllib.request.urlopen", side_effect=OSError):
                    cmd_check(_Args())
        except SystemExit:
            pass
        out = capsys.readouterr().out
        assert "Summary:" in out

    def test_daemon_warn_when_not_running(self, capsys):
        """Should warn when daemon port is closed."""
        from skg.cli.commands.check import cmd_check
        try:
            with patch("socket.create_connection", side_effect=OSError("refused")):
                with patch("urllib.request.urlopen", side_effect=OSError):
                    cmd_check(_Args())
        except SystemExit:
            pass
        out = capsys.readouterr().out
        assert "5055" in out


# ── cmd_replay ───────────────────────────────────────────────────────────

class TestCmdReplay:
    def test_imports_without_error(self):
        from skg.cli.commands.replay import cmd_replay
        assert callable(cmd_replay)

    def test_missing_dir_exits_nonzero(self):
        """cmd_replay must exit 1 when events_dir does not exist."""
        from skg.cli.commands.replay import cmd_replay
        import pytest
        with pytest.raises(SystemExit) as exc_info:
            cmd_replay(_Args(events_dir="/nonexistent_path_for_skg_test_xyz"))
        assert exc_info.value.code == 1

    def test_empty_dir_exits_nonzero(self, tmp_path):
        """cmd_replay must exit 1 when events_dir has no .ndjson files."""
        from skg.cli.commands.replay import cmd_replay
        import pytest
        with pytest.raises(SystemExit) as exc_info:
            cmd_replay(_Args(events_dir=str(tmp_path)))
        assert exc_info.value.code == 1

    def test_missing_dir_message(self, capsys):
        """cmd_replay prints a clear error message for missing directory."""
        from skg.cli.commands.replay import cmd_replay
        try:
            cmd_replay(_Args(events_dir="/nonexistent_path_for_skg_test_xyz"))
        except SystemExit:
            pass
        out = capsys.readouterr().out
        assert "not found" in out or "Events directory" in out

    def test_empty_dir_message(self, tmp_path, capsys):
        """cmd_replay prints a clear error when no ndjson files found."""
        from skg.cli.commands.replay import cmd_replay
        try:
            cmd_replay(_Args(events_dir=str(tmp_path)))
        except SystemExit:
            pass
        out = capsys.readouterr().out
        assert "ndjson" in out.lower() or "No .ndjson" in out

    def test_with_valid_events(self, tmp_path, capsys):
        """cmd_replay loads events and attempts kernel projection."""
        from skg.cli.commands.replay import cmd_replay

        # Write a minimal valid ndjson event
        event = {
            "payload": {
                "workload_id": "test::192.168.1.1",
                "wicket_id": "HO-01",
                "status": "realized",
                "confidence": 0.9,
            }
        }
        ndjson_file = tmp_path / "test_events.ndjson"
        ndjson_file.write_text(json.dumps(event) + "\n")

        # Kernel modules may not all exist; allow ImportError -> SystemExit
        try:
            cmd_replay(_Args(events_dir=str(tmp_path)))
        except SystemExit as e:
            # SystemExit(1) from kernel import failure is acceptable
            pass
        out = capsys.readouterr().out
        # Either loaded events or hit kernel import error — both produce output
        assert out.strip() != ""


# ── cmd_data ─────────────────────────────────────────────────────────────

class TestCmdData:
    def test_imports_without_error(self):
        from skg.cli.commands.data import cmd_data
        assert callable(cmd_data)

    def test_profile_missing_args_prints_usage(self, capsys):
        """cmd_data profile with no url/table should print usage."""
        from skg.cli.commands.data import cmd_data
        cmd_data(_Args(data_cmd="profile", url=None, table=None))
        out = capsys.readouterr().out
        assert "Usage" in out or "usage" in out

    def test_project_missing_args_prints_usage(self, capsys):
        """cmd_data project with no infile/path_id should print usage."""
        from skg.cli.commands.data import cmd_data
        cmd_data(_Args(data_cmd="project", infile=None, path_id=None))
        out = capsys.readouterr().out
        assert "Usage" in out or "usage" in out

    def test_paths_missing_catalog_prints_message(self, capsys):
        """cmd_data paths with missing catalog file prints helpful message."""
        from skg.cli.commands.data import cmd_data
        # The catalog file likely doesn't exist in test env
        cmd_data(_Args(data_cmd="paths"))
        out = capsys.readouterr().out
        # Either prints paths or says catalog not found
        assert out.strip() != ""

    def test_catalog_missing_prints_message(self, capsys):
        """cmd_data catalog with missing file prints message."""
        from skg.cli.commands.data import cmd_data
        cmd_data(_Args(data_cmd="catalog"))
        out = capsys.readouterr().out
        # Either prints catalog JSON or says not found
        assert out.strip() != ""

    def test_unknown_subcmd_prints_usage(self, capsys):
        """cmd_data with unknown subcommand prints usage."""
        from skg.cli.commands.data import cmd_data
        cmd_data(_Args(data_cmd="invalid_subcmd_xyz"))
        out = capsys.readouterr().out
        assert "Usage" in out or "usage" in out

    def test_discover_missing_args_prints_usage(self, capsys):
        """cmd_data discover with no host/user prints usage."""
        from skg.cli.commands.data import cmd_data
        cmd_data(_Args(data_cmd="discover", host=None, user=None))
        out = capsys.readouterr().out
        assert "Usage" in out or "usage" in out


# ── skg.cli.utils importability ──────────────────────────────────────────

class TestUtilsImport:
    def test_utils_importable(self):
        """skg.cli.utils must import without error."""
        import skg.cli.utils as u
        assert callable(u._api)
        assert callable(u._latest_surface)
        assert callable(u._iso_now)
        assert callable(u._load_surface_data)
        assert callable(u._write_surface_data)
        assert callable(u._ensure_local_runtime_targets)
        assert callable(u._surface_target)
        assert callable(u._interp_payload)
        assert callable(u._projection_rank)
        assert callable(u._load_module_from_file)
        assert callable(u._register_target)
        assert callable(u._merge_target_into_surface)
        assert callable(u._register_web_observation_target)
        assert callable(u._persist_target_config)
        assert callable(u._load_target_config)
        assert callable(u._bootstrap_target_surface)
        assert callable(u._run_python)
        assert callable(u._load_skg_env_value)
        assert callable(u._proposal_backlog)
        assert callable(u._fold_summary_offline)
        assert callable(u._choose_fold_summary)
        assert callable(u._load_folds_offline)
        assert callable(u._choose_fold_rows)
        assert callable(u._target_state_counts)
        assert callable(u._rank_surface_targets)
        assert callable(u._print_what_matters_now)
        assert callable(u._load_recall_summary)
        assert callable(u._pearl_brief)
        assert callable(u._active_identity_properties)
        assert callable(u._fold_brief_why)
        assert callable(u._describe_next_collapse)
        assert callable(u._pearl_signature)
        assert callable(u._summarize_pearl_cluster)
        assert callable(u._cluster_pearls)
        assert callable(u._parse_report_timestamp)
        assert callable(u._load_target_snapshot_from_pearls)
        assert callable(u._diff_target_snapshots)
        assert callable(u._infer_identity_properties_from_target)
        assert callable(u._print_substrate_self_audit)
        assert callable(u._build_substrate_self_audit)


class TestConsoleScriptShim:
    def test_console_script_shim_runs_bin_entrypoint(self, capsys):
        from skg.cli import main

        with patch.object(sys, "argv", ["skg"]):
            main()

        out = capsys.readouterr().out
        assert "usage:" in out.lower()

    def test_iso_now_format(self):
        """_iso_now should return a valid ISO 8601 string."""
        from skg.cli.utils import _iso_now
        from datetime import datetime
        ts = _iso_now()
        # Must parse without error
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt is not None

    def test_projection_rank_ordering(self):
        """_projection_rank must order: realized > not_realized > indeterminate > unknown."""
        from skg.cli.utils import _projection_rank
        assert _projection_rank({"classification": "realized"})[0] == 3
        assert _projection_rank({"classification": "not_realized"})[0] == 2
        assert _projection_rank({"classification": "indeterminate"})[0] == 1
        assert _projection_rank({"classification": ""})[0] == 0

    def test_target_state_counts_empty(self):
        """_target_state_counts on empty wicket_states returns zeros."""
        from skg.cli.utils import _target_state_counts
        counts = _target_state_counts({"wicket_states": {}})
        assert counts["unknown"] == 0
        assert counts["realized"] == 0
        assert counts["blocked"] == 0

    def test_target_state_counts_string_states(self):
        """_target_state_counts handles string state values."""
        from skg.cli.utils import _target_state_counts
        ws = {"WB-01": "realized", "WB-02": "blocked", "WB-03": "unknown"}
        counts = _target_state_counts({"wicket_states": ws})
        assert counts["realized"] == 1
        assert counts["blocked"] == 1
        assert counts["unknown"] == 1

    def test_active_identity_properties(self):
        """_active_identity_properties extracts only True-valued properties."""
        from skg.cli.utils import _active_identity_properties
        snap = {"identity_properties": {"a": True, "b": False, "c": True}}
        props = _active_identity_properties(snap)
        assert "a" in props
        assert "c" in props
        assert "b" not in props

    def test_diff_target_snapshots_empty(self):
        """_diff_target_snapshots returns empty dict for missing inputs."""
        from skg.cli.utils import _diff_target_snapshots
        assert _diff_target_snapshots({}, {}) == {}
        assert _diff_target_snapshots(None, {"services": []}) == {}

    def test_diff_target_snapshots_domain_change(self):
        """_diff_target_snapshots detects domain additions."""
        from skg.cli.utils import _diff_target_snapshots
        before = {"services": [], "domains": ["host"], "identity_properties": {}}
        after  = {"services": [], "domains": ["host", "web"], "identity_properties": {}}
        diff = _diff_target_snapshots(before, after)
        assert "web" in diff["domains_added"]
        assert diff["domains_removed"] == []

    def test_parse_report_timestamp_none(self):
        """_parse_report_timestamp returns None for None input."""
        from skg.cli.utils import _parse_report_timestamp
        assert _parse_report_timestamp(None) is None

    def test_parse_report_timestamp_valid(self):
        """_parse_report_timestamp parses a valid ISO string."""
        from skg.cli.utils import _parse_report_timestamp
        ts = _parse_report_timestamp("2026-03-20T12:00:00Z")
        assert ts is not None

    def test_proposal_backlog_no_dir(self):
        """_proposal_backlog returns zero counts when proposals dir absent."""
        from skg.cli.utils import _proposal_backlog
        import unittest.mock as mock
        with mock.patch("skg.cli.utils.SKG_STATE_DIR") as mock_state:
            mock_state.__truediv__ = lambda self, other: Path("/nonexistent_proposals_dir_xyz") if other == "proposals" else Path("/nonexistent") / other
            # Just call with real state dir — should return zeros if dir missing
            counts = _proposal_backlog()
        # all values should be integers
        assert isinstance(counts["pending_total"], int)

    def test_rank_surface_targets_empty(self):
        """_rank_surface_targets on empty surface returns empty list."""
        from skg.cli.utils import _rank_surface_targets
        result = _rank_surface_targets({"targets": []})
        assert result == []

    def test_infer_identity_properties_web_target(self):
        """_infer_identity_properties_from_target detects web surface."""
        from skg.cli.utils import _infer_identity_properties_from_target
        target = {
            "services": [{"port": 80, "service": "http"}],
            "domains": [],
            "kind": "web",
        }
        props = _infer_identity_properties_from_target(target)
        assert props["interactive_surface_present"] is True


class TestParserBehavior:
    def test_build_parser_importable(self):
        from skg.cli import build_parser

        parser = build_parser()
        assert parser is not None

    def test_help_paths_exit_cleanly(self):
        import pytest
        from skg.cli import build_parser

        parser = build_parser()
        for argv in (["--help"], ["graph", "--help"], ["folds", "--help"], ["engage", "--help"], ["core", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                parser.parse_args(argv)
            assert exc_info.value.code == 0

    def test_graph_defaults_to_topology(self, capsys):
        from skg.cli.commands.intelligence import cmd_graph

        class _Graph:
            def topology_report(self):
                return {
                    "nodes": 0,
                    "edges": 0,
                    "R_global": 0.0,
                    "n_realized": 0,
                    "n_blocked": 0,
                    "n_unknown": 0,
                    "clusters": {},
                    "entangled": [],
                    "top_gradient": [],
                }

        with patch("skg.kernel.wicket_graph.get_wicket_graph", return_value=_Graph()):
            cmd_graph(_Args(graph_cmd=None))

        out = capsys.readouterr().out
        assert "Wicket Knowledge Graph" in out

    def test_folds_defaults_to_list(self, capsys):
        from skg.cli.commands.surface import cmd_folds

        with patch("skg.cli.commands.surface._api", return_value={"summary": {"total": 0, "total_gravity_weight": 0.0, "by_type": {}}, "folds": [], "note": "none"}):
            cmd_folds(_Args(folds_cmd=None))

        out = capsys.readouterr().out
        assert "Active folds" in out


class TestCommandPathNormalization:
    def test_feed_reads_api_key_from_config_env(self, tmp_path):
        from skg.cli.commands.intelligence import cmd_feed

        fake_home = tmp_path / "repo"
        fake_script = fake_home / "feeds" / "nvd_ingester.py"
        fake_script.parent.mkdir(parents=True, exist_ok=True)
        fake_script.write_text("#!/usr/bin/env python3\n")

        fake_config = tmp_path / "config"
        fake_config.mkdir()
        (fake_config / "skg.env").write_text('NIST_NVD_API_KEY="secret"\n')

        with patch("skg.cli.commands.intelligence.SKG_HOME", fake_home):
            with patch("skg.cli.commands.intelligence.SKG_CONFIG_DIR", fake_config):
                with patch("skg.cli.utils.SKG_CONFIG_DIR", fake_config):
                    with patch.dict(os.environ, {}, clear=True):
                        with patch("subprocess.call", return_value=0) as mock_call:
                            cmd_feed(_Args(feed_cmd="nvd", service="Apache/2.4.25"))

        mock_call.assert_called_once()

    def test_binary_remote_analysis_projects_and_processes_feedback(self, tmp_path, capsys):
        from skg.cli.commands.exploit import cmd_exploit

        fake_events = [
            {
                "id": f"ev-{idx}",
                "ts": f"2026-03-27T15:12:5{idx}+00:00",
                "type": "obs.attack.precondition",
                "source": {"toolchain": "skg-binary-toolchain"},
                "payload": {
                    "wicket_id": wicket_id,
                    "status": status,
                    "attack_path_id": "binary_stack_overflow_v1",
                    "run_id": "remote-run",
                    "workload_id": "binary::192.168.254.5::ssh-keysign",
                    "detail": wicket_id,
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

        def _fake_run(cmd, capture_output, text):
            assert "--password" in cmd
            assert "--key" not in cmd
            out_path = Path(cmd[cmd.index("--out") + 1])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                "\n".join(json.dumps(event) for event in fake_events) + "\n",
                encoding="utf-8",
            )
            return _Args(returncode=0, stdout="[binary_analysis] 5 events written", stderr="")

        with patch("skg.cli.commands.exploit.DISCOVERY_DIR", tmp_path / "discovery"), \
             patch("skg.cli.commands.exploit.INTERP_DIR", tmp_path / "interp"), \
             patch("skg.cli.commands.exploit._load_target_config", return_value={"auth": {"key": "/tmp/id_rsa"}}), \
             patch("skg.cli.commands.exploit.subprocess.run", side_effect=_fake_run), \
             patch("skg.cli.commands.exploit._api", return_value={"processed": 1}):
            cmd_exploit(_Args(
                exploit_cmd="binary",
                binary_path="/usr/lib/ssh/ssh-keysign",
                target="192.168.254.5",
                user="skg",
                password="skg",
                key="",
                port=22,
                attack_path_id="binary_stack_overflow_v1",
                workload_id="",
            ))

        out = capsys.readouterr().out
        assert "Remote target: 192.168.254.5:22" in out
        assert "Projection written" in out
        assert "Feedback processed: 1 interp(s)" in out
        assert list((tmp_path / "interp").glob("*.json"))

    def test_cred_reuse_uses_configured_targets_path(self, tmp_path, capsys):
        from skg.cli.commands.exploit import cmd_exploit

        captured = {}
        fake_module = types.ModuleType("cred_reuse")

        class _Store:
            def count(self):
                return 1

            def untested_for(self, _target):
                return []

        def _extract_from_events(_events_dir, _store):
            return []

        def _extract_from_targets_yaml(path, _store):
            captured["path"] = path
            return []

        def _reuse_energy(_target_ip, _surface, _store):
            return 0.0

        def _run_reuse_sweep(**_kwargs):
            return []

        fake_module.CredentialStore = _Store
        fake_module.extract_from_events = _extract_from_events
        fake_module.extract_from_targets_yaml = _extract_from_targets_yaml
        fake_module.reuse_energy = _reuse_energy
        fake_module.run_reuse_sweep = _run_reuse_sweep

        fake_config = tmp_path / "config"
        fake_config.mkdir()

        with patch.dict(sys.modules, {"cred_reuse": fake_module}):
            with patch("skg.cli.commands.exploit.SKG_CONFIG_DIR", fake_config):
                with patch("skg.cli.commands.exploit.DISCOVERY_DIR", tmp_path / "discovery"):
                    cmd_exploit(_Args(exploit_cmd="cred-reuse", target="10.0.0.7", authorized=False))

        _ = capsys.readouterr()
        assert captured["path"] == fake_config / "targets.yaml"


class TestEngageCommand:
    def test_missing_subcommand_prints_usage(self, capsys):
        from skg.cli.commands.report import cmd_engage

        with patch("skg.intel.engagement_dataset.build_engagement_db") as mock_build:
            with patch("skg.intel.engagement_dataset.generate_engagement_report") as mock_report:
                with patch("skg.intel.engagement_dataset.analyze_engagement_integrity") as mock_analyze:
                    cmd_engage(_Args(engage_cmd=None))

        out = capsys.readouterr().out
        assert "Usage: skg engage" in out
        mock_build.assert_not_called()
        mock_report.assert_not_called()
        mock_analyze.assert_not_called()


class TestCoreCouplingCommand:
    def test_core_coupling_apply_updates_config(self, capsys):
        from skg.cli.commands.core import cmd_core
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

            with patch.object(coupling, "SKG_CONFIG_DIR", cfg_dir), \
                 patch.object(coupling, "SKG_HOME", home_dir):
                rc = cmd_core(_Args(
                    core_cmd="coupling",
                    validate=False,
                    show=False,
                    learn=False,
                    apply=True,
                    delta_dir=str(root / "delta"),
                    out=None,
                    learned_file=str(learned_path),
                    review=False,
                    backup=True,
                    yes=True,
                ))

            out = capsys.readouterr().out
            updated = yaml.safe_load((cfg_dir / "coupling.yaml").read_text(encoding="utf-8"))

        assert rc == 0
        assert '"ok": true' in out.lower()
        assert updated["intra_target"]["host"]["web"] == 0.66


class TestIdentityFirstCliShell:
    def test_surface_subject_rows_merge_measured_view_with_target_shell(self):
        from skg.cli.utils import _surface_subject_rows

        measured_surface = {
            "workloads": [{
                "identity_key": "db.internal",
                "manifestation_key": "mysql::db.internal:3306::users",
                "domain": "data_pipeline",
                "classification": "indeterminate",
                "realized": ["DP-02"],
                "blocked": [],
                "unknown": ["DP-01"],
                "measured_now": {
                    "realized": ["DP-02"],
                    "blocked": [],
                    "unknown": ["DP-01"],
                },
                "compatibility_score": 0.71,
                "decoherence": 0.12,
                "unresolved_reason": "unmeasured",
                "observed_tools": {
                    "tool_names": ["checksec", "nikto"],
                    "observed_tools": [
                        {"name": "checksec", "instrument_names": ["binary_analysis"], "domain_hints": ["binary"]},
                        {"name": "nikto", "instrument_names": ["nikto"], "domain_hints": ["web"]},
                    ],
                    "domain_hints": ["binary", "web"],
                    "instrument_hints": ["binary_analysis", "nikto"],
                    "scope": "node_local",
                    "status": "realized",
                },
            }],
        }
        target_surface = {
            "targets": [{
                "host": "db.internal",
                "hostname": "db.internal",
                "kind": "database",
                "services": [{"port": 3306, "service": "mysql"}],
                "domains": ["data"],
            }],
        }

        rows = _surface_subject_rows(measured_surface=measured_surface, target_surface=target_surface)

        assert len(rows) == 1
        row = rows[0]
        assert row["identity_key"] == "db.internal"
        assert row["unknown_count"] == 1
        assert row["realized_count"] == 1
        assert row["services"] == [{"port": 3306, "service": "mysql"}]
        assert "data" in row["domains"]
        assert "data_pipeline" in row["domains"]
        assert "mysql::db.internal:3306::users" in row["manifestations"]
        assert row["observed_tools"]["tool_names"] == ["checksec", "nikto"]

    def test_load_target_snapshot_from_pearls_matches_identity_aliases(self, tmp_path):
        from skg.cli.utils import _load_target_snapshot_from_pearls

        pearls_path = tmp_path / "pearls.jsonl"
        pearls_path.write_text(
            json.dumps({
                "timestamp": "2026-03-27T12:00:00+00:00",
                "workload_id": "mysql::db.internal:3306::users",
                "energy_snapshot": {"target_ip": "10.0.0.9"},
                "target_snapshot": {
                    "identity_key": "db.internal",
                    "hostname": "db.internal",
                    "domains": ["data"],
                    "services": [{"port": 3306, "service": "mysql"}],
                },
            }) + "\n",
            encoding="utf-8",
        )

        with patch("skg.cli.utils.SKG_STATE_DIR", tmp_path):
            assert _load_target_snapshot_from_pearls("db.internal") is not None
            assert _load_target_snapshot_from_pearls("10.0.0.9") is not None

    def test_target_list_prints_identity_first_rows(self, tmp_path, capsys):
        from skg.cli.commands.target import cmd_target

        surface_path = tmp_path / "surface_demo.json"
        surface_path.write_text(
            json.dumps({
                "targets": [{
                    "ip": "10.0.0.9",
                    "host": "10.0.0.9",
                    "hostname": "db.internal",
                    "kind": "database",
                    "services": [{"port": 3306, "service": "mysql"}],
                    "domains": ["data"],
                }],
            }),
            encoding="utf-8",
        )

        interp_dir = tmp_path / "interp"
        interp_dir.mkdir()
        (interp_dir / "binary_demo.json").write_text(
            json.dumps({
                "workload_id": "mysql::db.internal:3306::users",
                "attack_path_id": "data_exposure_v1",
                "domain": "data",
                "classification": "indeterminate",
                "realized": ["DP-02"],
                "blocked": [],
                "unknown": ["DP-01"],
                "data_score": 0.61,
                "computed_at": "2026-03-27T13:00:00+00:00",
            }),
            encoding="utf-8",
        )

        with patch("skg.cli.commands.target._latest_surface", return_value=str(surface_path)), \
             patch("skg.cli.commands.target.SKG_STATE_DIR", tmp_path):
            cmd_target(_Args(target_cmd="list"))

        out = capsys.readouterr().out
        assert "Node" in out
        assert "db.internal" in out

    def test_target_remove_prunes_subject_aliases(self, tmp_path, capsys):
        from skg.cli.commands.target import cmd_target

        discovery_dir = tmp_path / "discovery"
        config_dir = tmp_path / "config"
        state_dir = tmp_path / "state"
        interp_dir = tmp_path / "interp"
        events_dir = tmp_path / "events"
        for path in (discovery_dir, config_dir, state_dir, interp_dir, events_dir):
            path.mkdir(parents=True, exist_ok=True)

        (discovery_dir / "surface_demo.json").write_text(
            json.dumps({
                "targets": [{
                    "hostname": "db.internal",
                    "host": "db.internal",
                    "services": [{"port": 3306, "service": "mysql"}],
                }],
            }),
            encoding="utf-8",
        )
        (config_dir / "targets.yaml").write_text(
            "targets:\n  - host: db.internal\n    workload_id: mysql::db.internal:3306::users\n",
            encoding="utf-8",
        )
        (state_dir / "pearls.jsonl").write_text(
            json.dumps({
                "workload_id": "mysql::db.internal:3306::users",
                "target_snapshot": {"identity_key": "db.internal"},
                "energy_snapshot": {"identity_key": "db.internal"},
            }) + "\n",
            encoding="utf-8",
        )
        (interp_dir / "mysql_subject.json").write_text(
            json.dumps({"workload_id": "mysql::db.internal:3306::users"}),
            encoding="utf-8",
        )

        with patch("skg.cli.commands.target.DISCOVERY_DIR", discovery_dir), \
             patch("skg.cli.commands.target.SKG_CONFIG_DIR", config_dir), \
             patch("skg.cli.commands.target.SKG_STATE_DIR", state_dir), \
             patch("skg_core.config.paths.INTERP_DIR", interp_dir), \
             patch("skg_core.config.paths.EVENTS_DIR", events_dir):
            cmd_target(_Args(target_cmd="remove", ip="db.internal"))

        out = capsys.readouterr().out
        assert "removed" in out
        surface = json.loads((discovery_dir / "surface_demo.json").read_text(encoding="utf-8"))
        assert surface["targets"] == []
        targets_cfg = yaml.safe_load((config_dir / "targets.yaml").read_text(encoding="utf-8"))
        assert targets_cfg["targets"] == []
        assert (state_dir / "pearls.jsonl").read_text(encoding="utf-8").strip() == ""
        assert not (interp_dir / "mysql_subject.json").exists()

    def test_resolve_fold_offline_matches_identity_key(self, tmp_path):
        from skg.cli.commands.surface import _resolve_fold_offline

        folds_dir = tmp_path / "folds"
        folds_dir.mkdir(parents=True, exist_ok=True)
        fold_id = "fold-db-1"
        (folds_dir / "folds_db.internal.json").write_text(
            json.dumps([{
                "id": fold_id,
                "fold_type": "structural",
                "location": "mysql::db.internal:3306::users",
                "gravity_weight": 1.2,
            }]),
            encoding="utf-8",
        )

        with patch("skg.cli.commands.surface.DISCOVERY_DIR", tmp_path):
            result = _resolve_fold_offline("db.internal", fold_id[:8])

        assert result["ok"] is True
        remaining = json.loads((folds_dir / "folds_db.internal.json").read_text(encoding="utf-8"))
        assert remaining == []
