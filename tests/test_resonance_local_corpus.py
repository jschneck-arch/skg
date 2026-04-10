import tempfile
import unittest
import time
from unittest.mock import patch
from pathlib import Path

from skg.resonance.local_corpus import (
    index_local_corpus,
    micro_index_local_corpus,
    plan_smart_local_index,
    smart_index_local_corpus,
)


class _FakeEngine:
    def __init__(self):
        self._ids = set()

    def store_corpus(self, record):
        if record.record_id in self._ids:
            return False
        self._ids.add(record.record_id)
        return True


class LocalCorpusIndexTests(unittest.TestCase):
    def test_index_local_corpus_ingests_code_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "example.py").write_text(
                "def hello(name):\n    return f'hello {name}'\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "# Sample\nThis is local corpus text.\n",
                encoding="utf-8",
            )

            result = index_local_corpus(
                _FakeEngine(),
                pearls=False,
                help_cmds="",
                man_cmds="",
                code_root=str(root),
                max_code_files=10,
                chunk_chars=200,
                max_pearl_records=50,
            )

            code = result["summary"]["code"]
            self.assertEqual(code["sources"], 2)
            self.assertGreater(code["added"], 0)
            self.assertEqual(result["totals"]["sources"], 2)

    def test_plan_smart_local_index_prioritizes_query_commands(self):
        caps = {
            "available_help_commands": ["git", "rg", "curl"],
            "available_man_commands": ["find", "rg", "bash"],
            "has_man_renderer": True,
            "code_root": "/tmp",
            "code_root_exists": True,
            "pearls_path": "/tmp/pearls.jsonl",
            "pearls_exists": False,
            "cwd": "/tmp",
        }
        with patch("skg.resonance.local_corpus.discover_local_capabilities", return_value=caps):
            plan = plan_smart_local_index(
                query="use rg to search this repository",
                theta="code",
                max_help_cmds=2,
                max_man_cmds=2,
            )
        self.assertEqual(plan["help_cmds"][0], "rg")
        self.assertEqual(plan["man_cmds"][0], "rg")

    def test_smart_index_respects_interval_without_force(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "smart_state.json"
            state_path.write_text(
                '{"last_run_ts": %f}' % time.time(),
                encoding="utf-8",
            )
            caps = {
                "available_help_commands": [],
                "available_man_commands": [],
                "has_man_renderer": False,
                "code_root": tmpdir,
                "code_root_exists": True,
                "pearls_path": str(Path(tmpdir) / "pearls.jsonl"),
                "pearls_exists": False,
                "cwd": tmpdir,
            }
            with patch("skg.resonance.local_corpus.discover_local_capabilities", return_value=caps):
                result = smart_index_local_corpus(
                    _FakeEngine(),
                    query="status",
                    force=False,
                    min_interval_s=3600,
                    state_path=str(state_path),
                    include_pearls=False,
                    code_root=tmpdir,
                )
            self.assertTrue(result["skipped"])
            self.assertEqual(result["reason"], "interval_not_elapsed")

    def test_micro_index_selects_matching_commands_and_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "sample.py").write_text(
                "def sample():\n    return 42\n",
                encoding="utf-8",
            )
            caps = {
                "available_help_commands": ["python3", "rg"],
                "available_man_commands": ["python3"],
                "has_man_renderer": True,
                "code_root": str(root),
                "code_root_exists": True,
                "pearls_path": str(root / "pearls.jsonl"),
                "pearls_exists": False,
                "cwd": str(root),
            }

            def _fake_safe_run(args, timeout_s=8):
                text = " ".join(args)
                if "--help" in text or "-h" in text:
                    return "usage: python3 [options]"
                if "man " in text:
                    return "python3 manual page"
                return ""

            with patch("skg.resonance.local_corpus.discover_local_capabilities", return_value=caps):
                with patch("skg.resonance.local_corpus._safe_run", side_effect=_fake_safe_run):
                    result = micro_index_local_corpus(
                        _FakeEngine(),
                        query="show python3 help and inspect sample.py",
                        theta="code",
                        force=True,
                        ttl_s=900,
                        state_path=str(root / "micro_state.json"),
                        code_root=str(root),
                        max_help_cmds=2,
                        max_man_cmds=1,
                        max_code_files=2,
                    )

            self.assertIn("python3", result["selected"]["help"])
            self.assertIn("sample.py", result["selected"]["code"])
            self.assertGreater(result["totals"]["sources"], 0)
            self.assertFalse(result["skipped"])

    def test_micro_index_honors_ttl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "sample.py").write_text(
                "print('hello')\n",
                encoding="utf-8",
            )
            caps = {
                "available_help_commands": ["python3"],
                "available_man_commands": [],
                "has_man_renderer": False,
                "code_root": str(root),
                "code_root_exists": True,
                "pearls_path": str(root / "pearls.jsonl"),
                "pearls_exists": False,
                "cwd": str(root),
            }
            state_path = root / "micro_state.json"

            with patch("skg.resonance.local_corpus.discover_local_capabilities", return_value=caps):
                first = micro_index_local_corpus(
                    _FakeEngine(),
                    query="python3 sample.py",
                    force=True,
                    ttl_s=3600,
                    state_path=str(state_path),
                    code_root=str(root),
                    max_help_cmds=1,
                    max_man_cmds=0,
                    max_code_files=1,
                )
                second = micro_index_local_corpus(
                    _FakeEngine(),
                    query="python3 sample.py",
                    force=False,
                    ttl_s=3600,
                    state_path=str(state_path),
                    code_root=str(root),
                    max_help_cmds=1,
                    max_man_cmds=0,
                    max_code_files=1,
                )

            self.assertGreaterEqual(first["totals"]["sources"], 1)
            self.assertTrue(second["skipped"])
            self.assertEqual(second["reason"], "ttl_not_elapsed_for_selected_sources")


if __name__ == "__main__":
    unittest.main()
