"""
skg.core.state_db
=================
SQLite-backed state mirror for fast gravity loop queries.

The primary observation store is NDJSON (append-only, full provenance).
This module provides a fast query layer on top: current wicket states,
credential hits, and pivot targets can be queried in O(1) instead of
scanning NDJSON files.

Updated by the gravity loop after each instrument run.
Read by the gravity loop for landscape computation and pivot detection.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("skg.core.state_db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wicket_states (
    node_key   TEXT NOT NULL,
    wicket_id  TEXT NOT NULL,
    status     TEXT NOT NULL CHECK(status IN ('realized','blocked','unknown')),
    phi_r      REAL DEFAULT 0.0,
    phi_b      REAL DEFAULT 0.0,
    phi_u      REAL DEFAULT 1.0,
    confidence REAL DEFAULT 0.0,
    ts         TEXT NOT NULL,
    source     TEXT DEFAULT '',
    PRIMARY KEY (node_key, wicket_id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_key   TEXT NOT NULL,
    service    TEXT NOT NULL,
    port       INTEGER,
    username   TEXT,
    secret     TEXT,
    secret_type TEXT DEFAULT 'password',
    source     TEXT DEFAULT '',
    ts         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_creds_node ON credentials(node_key);

CREATE TABLE IF NOT EXISTS pivot_targets (
    discovered_from TEXT NOT NULL,
    target_ip       TEXT NOT NULL,
    discovery_method TEXT DEFAULT '',
    ts              TEXT NOT NULL,
    PRIMARY KEY (discovered_from, target_ip)
);

CREATE TABLE IF NOT EXISTS instrument_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    node_key     TEXT NOT NULL,
    instrument   TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    success      INTEGER DEFAULT 0,
    error        TEXT DEFAULT '',
    E_before     REAL DEFAULT 0.0,
    E_after      REAL DEFAULT 0.0,
    ts           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_node ON instrument_runs(node_key, instrument);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GravityStateDB:
    """
    Fast SQLite mirror of gravity loop state.

    Thread-safety: each call opens and closes a connection (WAL mode for
    concurrent readers). Not designed for high-frequency parallel writes.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
        except Exception as exc:
            log.warning("state_db schema init failed: %s", exc)

    # -- Wicket state mirror -----------------------------------------------

    def upsert_wicket(
        self,
        node_key: str,
        wicket_id: str,
        status: str,
        *,
        phi_r: float = 0.0,
        phi_b: float = 0.0,
        phi_u: float = 1.0,
        confidence: float = 0.0,
        source: str = "",
    ) -> None:
        ts = _now()
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO wicket_states
                       (node_key, wicket_id, status, phi_r, phi_b, phi_u, confidence, ts, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (node_key, wicket_id, status, phi_r, phi_b, phi_u, confidence, ts, source),
                )
        except Exception as exc:
            log.debug("state_db upsert_wicket failed: %s", exc)

    def wicket_states(self, node_key: str) -> dict[str, dict]:
        """Return {wicket_id: {status, phi_r, phi_b, phi_u, confidence, ts}}."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT wicket_id, status, phi_r, phi_b, phi_u, confidence, ts "
                    "FROM wicket_states WHERE node_key = ?",
                    (node_key,),
                ).fetchall()
            return {
                row["wicket_id"]: dict(row)
                for row in rows
            }
        except Exception as exc:
            log.debug("state_db wicket_states failed: %s", exc)
            return {}

    def bulk_upsert_wickets(self, node_key: str, states: dict[str, dict]) -> None:
        """Sync a full wicket state dict (from kernel) into the DB."""
        ts = _now()
        rows = []
        for wid, info in states.items():
            status = info.get("status", "unknown")
            if status not in ("realized", "blocked", "unknown"):
                status = "unknown"
            rows.append((
                node_key, wid, status,
                float(info.get("phi_r", 0.0) or 0.0),
                float(info.get("phi_b", 0.0) or 0.0),
                float(info.get("phi_u", 1.0) or 1.0),
                float(info.get("confidence", 0.0) or 0.0),
                ts,
                str(info.get("source", "")),
            ))
        if not rows:
            return
        try:
            with self._connect() as conn:
                conn.executemany(
                    """INSERT OR REPLACE INTO wicket_states
                       (node_key, wicket_id, status, phi_r, phi_b, phi_u, confidence, ts, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    rows,
                )
        except Exception as exc:
            log.debug("state_db bulk_upsert_wickets failed: %s", exc)

    # -- Credential store --------------------------------------------------

    def add_credential(
        self,
        node_key: str,
        service: str,
        *,
        port: Optional[int] = None,
        username: str = "",
        secret: str = "",
        secret_type: str = "password",
        source: str = "",
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO credentials
                       (node_key, service, port, username, secret, secret_type, source, ts)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (node_key, service, port, username, secret, secret_type, source, _now()),
                )
        except Exception as exc:
            log.debug("state_db add_credential failed: %s", exc)

    def credentials_for_node(self, node_key: str) -> list[dict]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT service, port, username, secret, secret_type, source, ts "
                    "FROM credentials WHERE node_key = ? ORDER BY ts DESC",
                    (node_key,),
                ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            log.debug("state_db credentials_for_node failed: %s", exc)
            return []

    def all_credentials(self) -> list[dict]:
        """Return all stored credentials across all nodes -- for pivot/reuse."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT node_key, service, port, username, secret, secret_type, source, ts "
                    "FROM credentials ORDER BY ts DESC"
                ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            log.debug("state_db all_credentials failed: %s", exc)
            return []

    # -- Pivot targets -----------------------------------------------------

    def add_pivot_target(
        self, discovered_from: str, target_ip: str, method: str = ""
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO pivot_targets
                       (discovered_from, target_ip, discovery_method, ts)
                       VALUES (?, ?, ?, ?)""",
                    (discovered_from, target_ip, method, _now()),
                )
        except Exception as exc:
            log.debug("state_db add_pivot_target failed: %s", exc)

    def pivot_targets(self) -> list[dict]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT discovered_from, target_ip, discovery_method, ts "
                    "FROM pivot_targets ORDER BY ts DESC"
                ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            log.debug("state_db pivot_targets failed: %s", exc)
            return []

    # -- Instrument run log ------------------------------------------------

    def log_instrument_run(
        self,
        node_key: str,
        instrument: str,
        run_id: str,
        *,
        success: bool = False,
        error: str = "",
        E_before: float = 0.0,
        E_after: float = 0.0,
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO instrument_runs
                       (node_key, instrument, run_id, success, error, E_before, E_after, ts)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (node_key, instrument, run_id, int(success), error, E_before, E_after, _now()),
                )
        except Exception as exc:
            log.debug("state_db log_instrument_run failed: %s", exc)

    def recent_runs(self, node_key: str, instrument: str, n: int = 5) -> list[dict]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT run_id, success, error, E_before, E_after, ts "
                    "FROM instrument_runs WHERE node_key = ? AND instrument = ? "
                    "ORDER BY ts DESC LIMIT ?",
                    (node_key, instrument, n),
                ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            log.debug("state_db recent_runs failed: %s", exc)
            return []
