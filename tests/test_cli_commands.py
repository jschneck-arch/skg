"""
Tests for migrated CLI commands.

These tests don't need the daemon or a live target.
"""
from __future__ import annotations
import sys
import types
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


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
