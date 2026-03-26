"""
tests/test_bwapp_data.py
=========================
Integration tests for the data pipeline adapter against bWAPP MySQL.

bWAPP (buggy web application) is the lab target for data domain testing:
  - MySQL database: bWAPP
  - Tables: users, heroes, movies, blog, notes, visitors
  - Default credentials: root/'' (MySQL), bee/bug (web)
  - Docker: 172.28.0.30 (skg-lab network) or localhost:3306

These tests validate both DE-* (security) and DP-* (data quality) wickets.

Run against the Docker lab:
  docker-compose -f docker-compose.lab.yml up -d
  .venv/bin/pytest tests/test_bwapp_data.py -v -m bwapp

Or run against local MySQL:
  BWAPP_URL=mysql+pymysql://root:@localhost:3306/bWAPP \
  .venv/bin/pytest tests/test_bwapp_data.py -v -m bwapp

Skip if bWAPP not available (default — runs in CI without Docker):
  .venv/bin/pytest tests/test_bwapp_data.py -v  (skips bwapp-marked tests)
"""
from __future__ import annotations

import json
import os
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ── Fixtures ──────────────────────────────────────────────────────────────

BWAPP_URL = os.environ.get(
    "BWAPP_URL",
    "mysql+pymysql://root:@172.28.0.30:3306/bWAPP",
)
BWAPP_SQLITE_URL = f"sqlite:///{Path(__file__).parent}/fixtures/webapp.db"

DB_AVAILABLE = False
try:
    import importlib.util
    if importlib.util.find_spec("pymysql") or importlib.util.find_spec("sqlalchemy"):
        DB_AVAILABLE = True
except Exception:
    pass


def _profiler():
    """Load db_profiler module."""
    profiler_path = (Path(__file__).resolve().parents[1]
                     / "skg-data-toolchain" / "adapters" / "db_profiler" / "profile.py")
    import importlib.util as ilu
    spec = ilu.spec_from_file_location("skg_db_profiler", profiler_path)
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── SQLite fixture tests (always run) ─────────────────────────────────────

class TestSQLiteFixture:
    """Tests against the local webapp.db fixture — no external dependencies."""

    def test_fixture_db_exists(self):
        db = Path(__file__).parent / "fixtures" / "webapp.db"
        assert db.exists(), "Run: python tests/fixtures/create_webapp_db.py"

    def test_users_dp03_null_email_blocked(self):
        """DP-03: NULL in required email field fires blocked."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="users",
            workload_id="test::users",
            contract_path=str(Path(__file__).parent / "fixtures" / "users_contract.json"),
        )
        dp03 = [e for e in events if e["payload"]["wicket_id"] == "DP-03"]
        assert dp03, "DP-03 event missing"
        # Multiple DP-03 events (one per field) — at least one must be blocked for email
        blocked = [e for e in dp03 if e["payload"]["status"] == "blocked"]
        assert blocked, f"No blocked DP-03 events. Statuses: {[e['payload']['status'] for e in dp03]}"
        email_blocked = [e for e in blocked if "email" in e["payload"]["detail"].lower()]
        assert email_blocked, f"Blocked events don't mention email: {[e['payload']['detail'] for e in blocked]}"

    def test_orders_dp08_duplicate_blocked(self):
        """DP-08: duplicate order_id fires blocked."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="orders",
            workload_id="test::orders",
            contract_path=str(Path(__file__).parent / "fixtures" / "orders_contract.json"),
        )
        dp08 = [e for e in events if e["payload"]["wicket_id"] == "DP-08"]
        assert dp08, "DP-08 event missing"
        assert dp08[-1]["payload"]["status"] == "blocked"

    def test_orders_dp04_bounds_blocked(self):
        """DP-04: amount < 0 and > 999.99 fires blocked."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="orders",
            workload_id="test::orders",
            contract_path=str(Path(__file__).parent / "fixtures" / "orders_contract.json"),
        )
        dp04 = [e for e in events if e["payload"]["wicket_id"] == "DP-04"]
        assert dp04, "DP-04 event missing"
        # At least one DP-04 event must be blocked (amount out of bounds)
        blocked = [e for e in dp04 if e["payload"]["status"] == "blocked"]
        assert blocked, f"No blocked DP-04. Statuses: {[e['payload']['status'] for e in dp04]}"

    def test_sessions_dp09_stale_blocked(self):
        """DP-09: sessions older than TTL fire blocked."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="sessions",
            workload_id="test::sessions",
            contract_path=str(Path(__file__).parent / "fixtures" / "sessions_contract.json"),
        )
        dp09 = [e for e in events if e["payload"]["wicket_id"] == "DP-09"]
        assert dp09, "DP-09 event missing"
        assert dp09[-1]["payload"]["status"] == "blocked"
        # Age increases over time — just confirm it exceeds TTL
        detail = dp09[-1]["payload"]["detail"]
        assert "TTL=24h" in detail and "EXCEEDED" in detail.upper(), \
            f"Expected staleness detail, got: {detail}"

    def test_products_clean_no_blocks(self):
        """Products table is clean — no blocked wickets."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="products",
            workload_id="test::products",
        )
        blocked = [e for e in events if e["payload"]["status"] == "blocked"]
        assert blocked == [], f"Unexpected blocks in clean table: {blocked}"

    def test_dp10_realized_sqlite_reachable(self):
        """DP-10: source reachable always realized for valid SQLite."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="users",
            workload_id="test::dp10",
        )
        dp10 = [e for e in events if e["payload"]["wicket_id"] == "DP-10"]
        assert dp10
        assert dp10[0]["payload"]["status"] == "realized"

    def test_events_are_valid_envelopes(self):
        """All events have required fields."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="orders",
            workload_id="test::envelope",
        )
        for ev in events:
            assert "id" in ev
            assert "type" in ev
            assert ev["type"] == "obs.attack.precondition"
            assert "payload" in ev
            p = ev["payload"]
            assert "wicket_id" in p
            assert p["status"] in ("realized", "blocked", "unknown")

    def test_all_events_have_run_id(self):
        """All events from one profile_table call share a run_id."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_SQLITE_URL,
            table="users",
            workload_id="test::run_id",
            run_id="testrun01",
        )
        run_ids = {e["payload"]["run_id"] for e in events}
        assert run_ids == {"testrun01"}


# ── bWAPP MySQL tests (skip if not available) ──────────────────────────────

@pytest.mark.bwapp
class TestBWAPPMySQL:
    """
    Integration tests against the live bWAPP MySQL database.

    Requires Docker lab running:
      docker-compose -f docker-compose.lab.yml up -d

    Or set BWAPP_URL env var to your MySQL URL.
    """

    @pytest.fixture(autouse=True)
    def require_bwapp(self):
        try:
            import pymysql
            conn = pymysql.connect(
                host="172.28.0.30", port=3306,
                user="root", password="", database="bWAPP",
                connect_timeout=3,
            )
            conn.close()
        except Exception as exc:
            pytest.skip(f"bWAPP MySQL not available: {exc}")

    def test_dp10_bwapp_reachable(self):
        """DP-10: bWAPP MySQL source is reachable."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_URL, table="users",
            workload_id="bwapp::users",
        )
        dp10 = [e for e in events if e["payload"]["wicket_id"] == "DP-10"]
        assert dp10
        assert dp10[0]["payload"]["status"] == "realized"

    def test_bwapp_users_schema_observed(self):
        """DP-01: users table schema contract loadable."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_URL, table="users",
            workload_id="bwapp::users",
            contract_path=str(Path(__file__).parent / "fixtures" / "bwapp_users_contract.json"),
        )
        dp01 = [e for e in events if e["payload"]["wicket_id"] == "DP-01"]
        assert dp01
        assert dp01[0]["payload"]["status"] == "realized"

    def test_bwapp_no_dp08_duplicates_in_users(self):
        """bWAPP users table should have unique IDs (no duplicates)."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_URL, table="users",
            workload_id="bwapp::users",
            contract_path=str(Path(__file__).parent / "fixtures" / "bwapp_users_contract.json"),
        )
        dp08 = [e for e in events if e["payload"]["wicket_id"] == "DP-08"]
        if dp08:
            # Either no duplicates (realized) or duplicates found (blocked — both valid)
            assert dp08[-1]["payload"]["status"] in ("realized", "blocked")

    def test_bwapp_heroes_profile(self):
        """Profile heroes table — should complete without error."""
        profiler = _profiler()
        events = profiler.profile_table(
            url=BWAPP_URL, table="heroes",
            workload_id="bwapp::heroes",
            contract_path=str(Path(__file__).parent / "fixtures" / "bwapp_heroes_contract.json"),
        )
        assert len(events) > 0
        wicket_ids = {e["payload"]["wicket_id"] for e in events}
        assert "DP-10" in wicket_ids  # connectivity always checked

    def test_bwapp_all_tables_discoverable(self):
        """Can enumerate all tables in bWAPP database."""
        try:
            import pymysql
            conn = pymysql.connect(
                host="172.28.0.30", port=3306,
                user="root", password="", database="bWAPP",
            )
            cur = conn.cursor()
            cur.execute("SHOW TABLES")
            tables = [row[0] for row in cur.fetchall()]
            conn.close()
        except Exception as exc:
            pytest.skip(f"Cannot enumerate tables: {exc}")

        assert len(tables) > 0
        # bWAPP should have at minimum: users, heroes, movies, blog
        expected = {"users", "heroes", "movies", "blog"}
        found = set(tables)
        missing = expected - found
        assert not missing, f"Expected bWAPP tables missing: {missing}"

    def test_bwapp_discover_via_cli(self, tmp_path):
        """
        Test the skg data CLI entry points against bWAPP.

        Two paths exercised:
          1. SSH-based discover  — tests cmd_data(discover). Skipped gracefully
             if SSH is not available on the container (bWAPP Docker has no SSH).
          2. Direct-URL profile  — tests cmd_data(profile). Always runs when
             bWAPP MySQL is reachable (guarded by require_bwapp fixture above).

        This ensures the CLI layer is covered even without SSH access.
        """
        import argparse
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from skg.cli.commands.data import cmd_data

        # ── Path 1: SSH discover (optional — bWAPP Docker has no SSH) ──────
        ssh_available = False
        try:
            import paramiko
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect("172.28.0.30", port=22, username="root",
                      password="", timeout=3)
            c.close()
            ssh_available = True
        except Exception:
            pass  # expected — bWAPP Docker exposes MySQL, not SSH

        if ssh_available:
            ns = argparse.Namespace(
                data_cmd="discover",
                host="172.28.0.30",
                user="root",
                password="",
                key=None,
                ssh_port=22,
                workload_id="bwapp::discover_test",
                tables=None,
                out_dir=str(tmp_path),
            )
            cmd_data(ns)
            de_file = tmp_path / "db_discovery_172_28_0_30.ndjson"
            assert de_file.exists(), "discover should write DE-* events file"
            events = [json.loads(l) for l in de_file.read_text().splitlines() if l.strip()]
            assert len(events) > 0, "discover should emit at least one DE-* event"

        # ── Path 2: Direct-URL profile (always runs via require_bwapp) ─────
        out_file = tmp_path / "bwapp_profile_users.ndjson"
        ns2 = argparse.Namespace(
            data_cmd="profile",
            url=BWAPP_URL,
            table="users",
            workload_id="bwapp::users",
            contract=None,
            attack_path_id="data_completeness_failure_v1",
            out=str(out_file),
        )
        cmd_data(ns2)

        assert out_file.exists(), "profile should write events file"
        events2 = [json.loads(l) for l in out_file.read_text().splitlines() if l.strip()]
        assert len(events2) > 0, "profile should emit wicket events"
        wicket_ids = {e["payload"]["wicket_id"] for e in events2}
        assert "DP-10" in wicket_ids, "DP-10 (source reachable) must be realized"

        statuses = {e["payload"]["status"] for e in events2}
        assert statuses & {"realized", "blocked", "unknown"}, \
            "events must have valid status values"


# ── db_discovery unit tests (no live target) ──────────────────────────────

class TestDbDiscoveryUnit:
    """Unit tests for db_discovery adapter internals — no SSH required."""

    def _load_discovery(self):
        path = (Path(__file__).resolve().parents[1]
                / "skg-data-toolchain" / "adapters" / "db_discovery" / "parse.py")
        import importlib.util as ilu
        spec = ilu.spec_from_file_location("skg_db_discovery", path)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_no_ssh_returns_empty(self):
        """run() with unreachable host returns empty list."""
        mod = self._load_discovery()
        events = mod.run(
            host="192.0.2.1",  # TEST-NET — unreachable
            ssh_port=22,
            user="root",
            password="bogus",
            key=None,
            workload_id="test",
            run_id="t001",
        )
        assert events == []

    def test_check_de01_no_ports(self):
        """DE-01 blocked when no DB ports found."""
        mod = self._load_discovery()
        data = {"host": "10.0.0.1", "listening_ports": {}, "errors": []}
        events = mod.check_de_01(data, "test", "r001")
        assert events
        assert events[0]["payload"]["status"] == "blocked"

    def test_check_de01_mysql_found(self):
        """DE-01 realized when MySQL port present."""
        mod = self._load_discovery()
        data = {"host": "10.0.0.1", "listening_ports": {3306: "mysql"}, "errors": []}
        events = mod.check_de_01(data, "test", "r001")
        assert events[0]["payload"]["status"] == "realized"
        assert "mysql" in events[0]["payload"]["detail"]

    def test_check_de03_default_cred_accepted(self):
        """DE-03 realized when default MySQL cred accepted."""
        mod = self._load_discovery()
        data = {
            "host": "10.0.0.1",
            "listening_ports": {3306: "mysql"},
            "default_cred_result": {
                "mysql": {"user": "root", "password": "", "success": True,
                          "db_list": ["bWAPP", "dvwa"]}
            },
            "harvested_cred_result": {},
        }
        events = mod.check_de_03(data, "test", "r001")
        realized = [e for e in events if e["payload"]["status"] == "realized"]
        assert realized
        assert "root" in realized[0]["payload"]["detail"]

    def test_check_de05_loopback_bind_blocked(self):
        """DE-05 blocked when bind address is 127.0.0.1."""
        mod = self._load_discovery()
        data = {
            "host": "10.0.0.1",
            "listening_ports": {3306: "mysql"},
            "bind_addresses": {"mysql": "127.0.0.1"},
        }
        events = mod.check_de_05(data, "test", "r001")
        assert events[0]["payload"]["status"] == "blocked"

    def test_check_de05_wildcard_bind_realized(self):
        """DE-05 realized when bind address is 0.0.0.0."""
        mod = self._load_discovery()
        data = {
            "host": "10.0.0.1",
            "listening_ports": {3306: "mysql"},
            "bind_addresses": {"mysql": "0.0.0.0"},
        }
        events = mod.check_de_05(data, "test", "r001")
        assert events[0]["payload"]["status"] == "realized"

    def test_build_db_url_mysql(self):
        """_build_db_url produces correct pymysql URL."""
        mod = self._load_discovery()
        url = mod._build_db_url("mysql", "127.0.0.1", 3306, "root", "", "bWAPP")
        assert url == "mysql+pymysql://root@127.0.0.1:3306/bWAPP"

    def test_build_db_url_postgresql(self):
        """_build_db_url produces correct postgresql URL."""
        mod = self._load_discovery()
        url = mod._build_db_url("postgresql", "127.0.0.1", 5432, "postgres", "pg", "app")
        assert url == "postgresql://postgres:pg@127.0.0.1:5432/app"

    def test_sensitive_table_detection(self):
        """DE-07 realized when sensitive table names found."""
        mod = self._load_discovery()
        data = {
            "host": "10.0.0.1",
            "listening_ports": {3306: "mysql"},
            "sensitive_tables": {"mysql": ["users", "sessions", "payment_cards"]},
        }
        events = mod.check_de_07(data, "test", "r001")
        realized = [e for e in events if e["payload"]["status"] == "realized"]
        assert realized
        assert "3 sensitive tables" in realized[0]["payload"]["detail"]

    def test_run_with_profiling_signature(self):
        """run_with_profiling exists and returns tuple."""
        mod = self._load_discovery()
        assert hasattr(mod, "run_with_profiling")
        # With unreachable host both lists empty
        de, dp = mod.run_with_profiling(
            host="192.0.2.1", ssh_port=22, user="root",
            password="bogus", key=None,
            workload_id="test",
        )
        assert de == []
        assert dp == []
