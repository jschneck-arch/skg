"""
adapters/db_profiler/profile.py
================================
Database profiler — the primary instrument for the data pipeline domain.

This adapter connects to a relational database (Postgres, MySQL, SQLite,
or any SQLAlchemy-compatible source), profiles tables and views against
their declared schema contracts, and emits obs.attack.precondition events
for each DP-* wicket.

This is the data domain equivalent of the SSH sensor: it opens a connection,
runs structured queries, observes conditions, and emits tri-state events.
The gravity field directs it toward the highest-entropy pipeline stages —
the ones with the most unknown wickets.

Evidence ranks emitted:
  rank 1 (runtime) — live query against the database
  rank 2 (build)   — pipeline log or audit table
  rank 3 (config)  — schema contract on disk
  rank 6 (scanner) — statistical profiling (distribution, encoding)

Supports:
  - Postgres (psycopg2 or asyncpg)
  - MySQL/MariaDB (pymysql)
  - SQLite (stdlib)
  - Any SQLAlchemy URL

Usage:
  python profile.py --url postgresql://user:pass@host/db --table orders \\
                    --contract contracts/orders_contract.json \\
                    --out /var/lib/skg/events/data_orders.ndjson

  python profile.py --url sqlite:///mydb.db --table transactions \\
                    --workload-id banking::transactions --out events.ndjson

  python profile.py --config /etc/skg/data_sources.yaml --out-dir /var/lib/skg/events/
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

TOOLCHAIN   = "skg-data-toolchain"
SOURCE_ID   = "adapter.db_profiler"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"


def get_version() -> str:
    try:
        return VERSION_FILE.read_text().strip()
    except Exception:
        return "0.1.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Event emission ────────────────────────────────────────────────────────

def _ev(wicket_id: str, status: str, rank: int, confidence: float,
        detail: str, workload_id: str, run_id: str,
        source_kind: str = "db_profiler_runtime",
        pointer: str = "",
        attack_path_id: str = "") -> dict:
    """Build a compliant obs.attack.precondition envelope event."""
    now = iso_now()
    payload: dict = {
        "wicket_id":    wicket_id,
        "status":       status,
        "workload_id":  workload_id,
        "detail":       detail,
        "run_id":       run_id,
        "observed_at":  now,
    }
    if attack_path_id:
        payload["attack_path_id"] = attack_path_id
    return {
        "id":   str(uuid.uuid4()),
        "ts":   now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id":  SOURCE_ID,
            "toolchain":  TOOLCHAIN,
            "version":    get_version(),
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": rank,
            "evidence": {
                "source_kind":  source_kind,
                "pointer":      pointer or workload_id,
                "collected_at": now,
                "confidence":   confidence,
            },
        },
    }


# ── Schema contract loading ───────────────────────────────────────────────

def load_contract(contract_path: str | None, table: str) -> dict:
    """
    Load a schema contract from a JSON file.
    Contract format:
    {
      "table": "orders",
      "primary_key": "order_id",
      "ttl_hours": 24,
      "required_fields": ["order_id", "customer_id", "amount", "created_at"],
      "bounds": {
        "amount": {"min": 0, "max": 1000000},
        "status": {"enum": ["pending", "complete", "cancelled"]}
      },
      "foreign_keys": [
        {"field": "customer_id", "ref_table": "customers", "ref_field": "id"}
      ],
      "expected_count_per_batch": null,
      "distribution_baselines": {
        "amount": {"mean": 150.0, "std": 80.0, "p50": 120.0, "p95": 400.0}
      }
    }
    """
    if contract_path and Path(contract_path).exists():
        return json.loads(Path(contract_path).read_text())
    # Minimal contract — enough to run basic checks
    return {
        "table":           table,
        "primary_key":     None,
        "ttl_hours":       24,
        "required_fields": [],
        "bounds":          {},
        "foreign_keys":    [],
        "expected_count_per_batch": None,
        "distribution_baselines":  {},
    }


# ── Database connection ───────────────────────────────────────────────────

class DBConnection:
    """
    Thin wrapper around SQLAlchemy or stdlib sqlite3.
    Falls back to sqlite3 if SQLAlchemy is not installed.
    """

    def __init__(self, url: str):
        self.url  = url
        self._conn = None
        self._engine = None
        self._is_sqlite_stdlib = False
        self._dialect = ""

    def connect(self) -> None:
        if self.url.startswith("sqlite:///"):
            # Use stdlib — no extra deps
            import sqlite3
            db_path = self.url[len("sqlite:///"):]
            self._conn = sqlite3.connect(db_path)
            self._conn.row_factory = sqlite3.Row
            self._is_sqlite_stdlib = True
        else:
            try:
                from sqlalchemy import create_engine, text
                self._engine = create_engine(self.url, pool_pre_ping=True,
                                              connect_args={"connect_timeout": 10})
                self._conn = self._engine.connect()
                self._text = text
                self._dialect = getattr(self._engine.dialect, "name", "")
            except ImportError:
                raise RuntimeError(
                    "SQLAlchemy not installed. "
                    "Install: pip install sqlalchemy psycopg2-binary --break-system-packages"
                )

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        """Execute SQL and return list of row dicts."""
        if self._is_sqlite_stdlib:
            import sqlite3
            cursor = self._conn.execute(sql, params or {})
            cols = [d[0] for d in cursor.description] if cursor.description else []
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
        else:
            result = self._conn.execute(self._text(sql), params or {})
            if result.returns_rows:
                cols = list(result.keys())
                return [dict(zip(cols, row)) for row in result.fetchall()]
            return []

    def table_exists(self, table: str) -> bool:
        try:
            if self._is_sqlite_stdlib:
                r = self.query(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=:t",
                    {"t": table})
                return bool(r)
            if self._dialect in {"mysql", "mariadb"}:
                r = self.query(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = DATABASE() AND table_name = :t",
                    {"t": table},
                )
                return bool(r)
            if self._dialect in {"postgresql", "postgres"}:
                r = self.query(
                    "SELECT to_regclass(:t) AS t", {"t": table}
                )
                return bool(r and r[0].get("t"))
            else:
                r = self.query(
                    "SELECT 1 AS present FROM information_schema.tables "
                    "WHERE table_name = :t",
                    {"t": table},
                )
                return bool(r)
        except Exception:
            return False

    def close(self) -> None:
        try:
            if self._conn:
                self._conn.close()
            if self._engine:
                self._engine.dispose()
        except Exception:
            pass


# ── Profiler checks ────────────────────────────────────────────────────────

def check_dp01_schema_contract(contract: dict, workload_id: str,
                                run_id: str) -> list[dict]:
    """DP-01: Schema contract present."""
    if contract.get("required_fields") or contract.get("bounds") or \
       contract.get("primary_key"):
        return [_ev("DP-01", "realized", 3, 0.95,
                    f"Contract loaded: {len(contract.get('required_fields',[]))} "
                    f"required fields, pk={contract.get('primary_key','none')}",
                    workload_id, run_id, "db_contract", workload_id)]
    return [_ev("DP-01", "unknown", 3, 0.50,
                "No contract file found — running with minimal defaults",
                workload_id, run_id, "db_contract", workload_id)]


def check_dp02_schema_version(db: DBConnection, table: str,
                               contract: dict, workload_id: str,
                               run_id: str, state: dict) -> list[dict]:
    """
    DP-02: Schema version stable.
    Detects changes by comparing column fingerprint to last observed.
    """
    try:
        # Get current column list
        if db._is_sqlite_stdlib:
            rows = db.query(f"PRAGMA table_info({table})")
            cols = sorted(r["name"] for r in rows)
        else:
            rows = db.query(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :t ORDER BY ordinal_position",
                {"t": table}
            )
            cols = [r["column_name"] for r in rows]

        fingerprint = ",".join(cols)
        prev = state.get("schema_fingerprint", {}).get(table)

        if prev is None:
            state.setdefault("schema_fingerprint", {})[table] = fingerprint
            return [_ev("DP-02", "unknown", 3, 0.70,
                        f"First observation — {len(cols)} columns recorded",
                        workload_id, run_id, "db_schema_scan", workload_id)]
        elif prev == fingerprint:
            return [_ev("DP-02", "realized", 3, 0.95,
                        f"Schema unchanged — {len(cols)} columns",
                        workload_id, run_id, "db_schema_scan", workload_id)]
        else:
            old_cols = set(prev.split(","))
            new_cols = set(fingerprint.split(","))
            added   = new_cols - old_cols
            removed = old_cols - new_cols
            state["schema_fingerprint"][table] = fingerprint
            return [_ev("DP-02", "blocked", 3, 0.95,
                        f"Schema changed: +{sorted(added)} -{sorted(removed)}",
                        workload_id, run_id, "db_schema_scan", workload_id)]
    except Exception as exc:
        return [_ev("DP-02", "unknown", 3, 0.30, str(exc),
                    workload_id, run_id)]


def check_dp03_required_fields(db: DBConnection, table: str,
                                contract: dict, workload_id: str,
                                run_id: str) -> list[dict]:
    """DP-03: Required fields populated — no NULLs in declared required fields."""
    required = contract.get("required_fields", [])
    if not required:
        return [_ev("DP-03", "unknown", 1, 0.40,
                    "No required fields declared in contract",
                    workload_id, run_id)]

    events = []
    any_null = False

    for field in required:
        try:
            rows = db.query(
                f"SELECT COUNT(*) AS n FROM {table} WHERE {field} IS NULL"
            )
            null_count = rows[0]["n"] if rows else 0
            if null_count > 0:
                any_null = True
                events.append(_ev("DP-03", "blocked", 1, 0.99,
                                  f"{field}: {null_count} NULL values",
                                  workload_id, run_id,
                                  "db_null_check", f"{workload_id}/{field}"))
            else:
                events.append(_ev("DP-03", "realized", 1, 0.99,
                                  f"{field}: no NULLs",
                                  workload_id, run_id,
                                  "db_null_check", f"{workload_id}/{field}"))
        except Exception as exc:
            events.append(_ev("DP-03", "unknown", 1, 0.30,
                              f"{field}: query failed — {exc}",
                              workload_id, run_id))

    return events


def check_dp04_bounds(db: DBConnection, table: str,
                      contract: dict, workload_id: str,
                      run_id: str) -> list[dict]:
    """DP-04: Fields within declared bounds."""
    bounds = contract.get("bounds", {})
    if not bounds:
        return [_ev("DP-04", "unknown", 1, 0.40,
                    "No bounds declared in contract",
                    workload_id, run_id)]

    events = []
    for field, constraint in bounds.items():
        try:
            if "enum" in constraint:
                allowed = constraint["enum"]
                placeholders = ",".join([f"'{v}'" for v in allowed])
                rows = db.query(
                    f"SELECT COUNT(*) AS n FROM {table} "
                    f"WHERE {field} IS NOT NULL AND {field} NOT IN ({placeholders})"
                )
                out_of_range = rows[0]["n"] if rows else 0
                status = "blocked" if out_of_range > 0 else "realized"
                detail = (f"{field}: {out_of_range} values outside enum {allowed}"
                          if out_of_range > 0
                          else f"{field}: all values within enum")
            else:
                mn = constraint.get("min")
                mx = constraint.get("max")
                where_parts = []
                if mn is not None:
                    where_parts.append(f"{field} < {mn}")
                if mx is not None:
                    where_parts.append(f"{field} > {mx}")
                if not where_parts:
                    continue
                where_clause = " OR ".join(where_parts)
                rows = db.query(
                    f"SELECT COUNT(*) AS n FROM {table} "
                    f"WHERE {field} IS NOT NULL AND ({where_clause})"
                )
                out_of_range = rows[0]["n"] if rows else 0
                status = "blocked" if out_of_range > 0 else "realized"
                detail = (f"{field}: {out_of_range} out-of-bounds (min={mn} max={mx})"
                          if out_of_range > 0
                          else f"{field}: all within bounds (min={mn} max={mx})")

            events.append(_ev("DP-04", status, 1, 0.95, detail,
                              workload_id, run_id,
                              "db_bounds_check", f"{workload_id}/{field}"))
        except Exception as exc:
            events.append(_ev("DP-04", "unknown", 1, 0.30,
                              f"{field}: bounds check failed — {exc}",
                              workload_id, run_id))
    return events


def check_dp05_referential_integrity(db: DBConnection, table: str,
                                      contract: dict, workload_id: str,
                                      run_id: str) -> list[dict]:
    """DP-05: Foreign key integrity — no orphaned records."""
    fks = contract.get("foreign_keys", [])
    if not fks:
        return [_ev("DP-05", "unknown", 1, 0.40,
                    "No foreign keys declared in contract",
                    workload_id, run_id)]

    events = []
    for fk in fks:
        field     = fk.get("field", "")
        ref_table = fk.get("ref_table", "")
        ref_field = fk.get("ref_field", "id")
        if not field or not ref_table:
            continue
        try:
            rows = db.query(
                f"SELECT COUNT(*) AS n FROM {table} t "
                f"LEFT JOIN {ref_table} r ON t.{field} = r.{ref_field} "
                f"WHERE t.{field} IS NOT NULL AND r.{ref_field} IS NULL"
            )
            orphaned = rows[0]["n"] if rows else 0
            status = "blocked" if orphaned > 0 else "realized"
            detail = (f"{field} → {ref_table}.{ref_field}: {orphaned} orphaned rows"
                      if orphaned > 0
                      else f"{field} → {ref_table}.{ref_field}: integrity intact")
            events.append(_ev("DP-05", status, 1, 0.95, detail,
                              workload_id, run_id,
                              "db_fk_check", f"{workload_id}/{field}"))
        except Exception as exc:
            events.append(_ev("DP-05", "unknown", 1, 0.30,
                              f"{field}: FK check failed — {exc}",
                              workload_id, run_id))
    return events


def check_dp08_duplicates(db: DBConnection, table: str,
                           contract: dict, workload_id: str,
                           run_id: str) -> list[dict]:
    """DP-08: No duplicate records by primary key."""
    pk = contract.get("primary_key")
    if not pk:
        return [_ev("DP-08", "unknown", 1, 0.40,
                    "No primary key declared in contract",
                    workload_id, run_id)]
    try:
        rows = db.query(
            f"SELECT COUNT(*) AS n FROM ("
            f"  SELECT {pk} FROM {table} "
            f"  GROUP BY {pk} HAVING COUNT(*) > 1"
            f") AS dups"
        )
        dup_count = rows[0]["n"] if rows else 0
        if dup_count > 0:
            return [_ev("DP-08", "blocked", 1, 0.99,
                        f"{dup_count} duplicate {pk} values",
                        workload_id, run_id,
                        "db_dedup_check", workload_id)]
        return [_ev("DP-08", "realized", 1, 0.99,
                    f"No duplicates on {pk}",
                    workload_id, run_id,
                    "db_dedup_check", workload_id)]
    except Exception as exc:
        return [_ev("DP-08", "unknown", 1, 0.30, str(exc),
                    workload_id, run_id)]


def check_dp09_freshness(db: DBConnection, table: str,
                          contract: dict, workload_id: str,
                          run_id: str) -> list[dict]:
    """
    DP-09: Data freshness within declared TTL.
    Looks for a timestamp column named updated_at, created_at, or ts.
    """
    ttl_hours  = contract.get("ttl_hours", 24)
    ts_columns = contract.get("timestamp_columns",
                               ["updated_at", "created_at", "ts",
                                "event_time", "recorded_at", "modified_at"])

    for ts_col in ts_columns:
        try:
            rows = db.query(f"SELECT MAX({ts_col}) AS latest FROM {table}")
            if not rows or rows[0]["latest"] is None:
                continue
            latest_val = rows[0]["latest"]

            # Parse the value — could be datetime object or string
            if hasattr(latest_val, "timestamp"):
                latest_dt = latest_val.replace(tzinfo=timezone.utc) \
                    if latest_val.tzinfo is None else latest_val
            else:
                # Try to parse as ISO string
                ts_str = str(latest_val)
                latest_dt = datetime.fromisoformat(
                    ts_str.replace("Z", "+00:00"))
                if latest_dt.tzinfo is None:
                    latest_dt = latest_dt.replace(tzinfo=timezone.utc)

            now   = datetime.now(timezone.utc)
            age_h = (now - latest_dt).total_seconds() / 3600
            ttl_ok = age_h <= ttl_hours

            status = "realized" if ttl_ok else "blocked"
            detail = (f"{ts_col}: latest={latest_val}, "
                      f"age={age_h:.1f}h, TTL={ttl_hours}h — "
                      f"{'within' if ttl_ok else 'EXCEEDED'}")
            return [_ev("DP-09", status, 1, 0.95, detail,
                        workload_id, run_id,
                        "db_freshness_check", workload_id)]
        except Exception:
            continue

    return [_ev("DP-09", "unknown", 1, 0.30,
                f"No timestamp column found (tried: {ts_columns})",
                workload_id, run_id)]


def check_dp10_upstream_reachable(db: DBConnection, url: str,
                                   workload_id: str, run_id: str) -> list[dict]:
    """
    DP-10: Upstream source reachable.
    Opens the connection here — this IS the reachability probe.
    On success, the connection is left open for subsequent checks.
    On failure, returns blocked so profile_table can short-circuit.
    """
    try:
        db.connect()
        db.query("SELECT 1")
        return [_ev("DP-10", "realized", 4, 0.99,
                    f"Connected to {_redact_url(url)}",
                    workload_id, run_id,
                    "db_connect_probe", _redact_url(url))]
    except Exception as exc:
        return [_ev("DP-10", "blocked", 4, 0.99,
                    f"Cannot connect: {exc}",
                    workload_id, run_id,
                    "db_connect_probe", _redact_url(url))]


def check_dp11_batch_complete(db: DBConnection, table: str,
                               contract: dict, workload_id: str,
                               run_id: str, batch_id: str | None = None) -> list[dict]:
    """DP-11: Batch complete — actual count vs expected."""
    expected = contract.get("expected_count_per_batch")
    if expected is None:
        # Check against most recent batch if batch_id column declared
        batch_col = contract.get("batch_column")
        if not batch_col:
            return [_ev("DP-11", "unknown", 1, 0.40,
                        "No expected_count_per_batch or batch_column in contract",
                        workload_id, run_id)]

    try:
        if batch_id and contract.get("batch_column"):
            rows = db.query(
                f"SELECT COUNT(*) AS n FROM {table} "
                f"WHERE {contract['batch_column']} = :bid",
                {"bid": batch_id}
            )
        else:
            rows = db.query(f"SELECT COUNT(*) AS n FROM {table}")

        actual = rows[0]["n"] if rows else 0

        if expected is None:
            return [_ev("DP-11", "unknown", 1, 0.50,
                        f"Table has {actual} rows (no expected count to compare)",
                        workload_id, run_id,
                        "db_count_check", workload_id)]

        # Allow 1% tolerance
        tol = max(1, int(expected * 0.01))
        if abs(actual - expected) <= tol:
            return [_ev("DP-11", "realized", 1, 0.90,
                        f"Count {actual} matches expected {expected} (±{tol})",
                        workload_id, run_id,
                        "db_count_check", workload_id)]
        return [_ev("DP-11", "blocked", 1, 0.90,
                    f"Count {actual} vs expected {expected} (delta={actual-expected:+d})",
                    workload_id, run_id,
                    "db_count_check", workload_id)]
    except Exception as exc:
        return [_ev("DP-11", "unknown", 1, 0.30, str(exc), workload_id, run_id)]


def check_dp12_distribution(db: DBConnection, table: str,
                              contract: dict, workload_id: str,
                              run_id: str, state: dict) -> list[dict]:
    """
    DP-12: Distribution stable.
    Compares current mean/stddev to baseline in contract or last observation.
    Z-score > 3.0 on any field = distribution shift.
    """
    import math

    baselines = contract.get("distribution_baselines", {})
    numeric_fields = contract.get("numeric_fields", list(baselines.keys()))

    if not numeric_fields:
        return [_ev("DP-12", "unknown", 6, 0.40,
                    "No numeric_fields or distribution_baselines in contract",
                    workload_id, run_id)]

    events = []
    for field in numeric_fields[:6]:  # limit to 6 per run
        try:
            rows = db.query(
                f"SELECT AVG(CAST({field} AS FLOAT)) AS mean, "
                f"COUNT(*) AS n "
                f"FROM {table} WHERE {field} IS NOT NULL"
            )
            if not rows or rows[0]["n"] < 10:
                continue

            current_mean = float(rows[0]["mean"] or 0)
            n = rows[0]["n"]

            baseline = baselines.get(field, {})
            prev_mean = state.get("distribution", {}).get(f"{table}.{field}", {}).get("mean")

            if not baseline and prev_mean is None:
                # Record as baseline for next run
                state.setdefault("distribution", {})\
                     .setdefault(f"{table}.{field}", {})["mean"] = current_mean
                events.append(_ev("DP-12", "unknown", 6, 0.50,
                                  f"{field}: mean={current_mean:.3f} (establishing baseline, n={n})",
                                  workload_id, run_id,
                                  "db_distribution_scan", workload_id))
                continue

            ref_mean = baseline.get("mean", prev_mean or current_mean)
            ref_std  = baseline.get("std")

            if ref_std and ref_std > 0:
                z = abs(current_mean - ref_mean) / ref_std
                if z > 3.0:
                    status = "blocked"
                    detail = (f"{field}: mean={current_mean:.3f} vs "
                              f"baseline={ref_mean:.3f} (z={z:.2f} > 3.0 — drift)")
                elif z > 2.0:
                    status = "unknown"
                    detail = (f"{field}: mean={current_mean:.3f} vs "
                              f"baseline={ref_mean:.3f} (z={z:.2f} — watch)")
                else:
                    status = "realized"
                    detail = (f"{field}: mean={current_mean:.3f} vs "
                              f"baseline={ref_mean:.3f} (z={z:.2f} — stable)")
                events.append(_ev("DP-12", status, 6, 0.80, detail,
                                  workload_id, run_id,
                                  "db_distribution_scan", workload_id))
            else:
                # No std — just record
                pct_change = abs(current_mean - ref_mean) / max(abs(ref_mean), 1e-9)
                if pct_change > 0.20:
                    status = "blocked"
                    detail = f"{field}: mean {ref_mean:.3f}→{current_mean:.3f} ({pct_change:.0%} change)"
                else:
                    status = "realized"
                    detail = f"{field}: mean {current_mean:.3f} stable ({pct_change:.1%} change)"
                events.append(_ev("DP-12", status, 6, 0.65, detail,
                                  workload_id, run_id,
                                  "db_distribution_scan", workload_id))

            state.setdefault("distribution", {})\
                 .setdefault(f"{table}.{field}", {})["mean"] = current_mean

        except Exception as exc:
            events.append(_ev("DP-12", "unknown", 6, 0.30,
                              f"{field}: distribution check failed — {exc}",
                              workload_id, run_id))

    return events if events else [_ev("DP-12", "unknown", 6, 0.40,
                                      "No numeric fields profiled",
                                      workload_id, run_id)]


def check_dp13_null_injection(db: DBConnection, table: str,
                               contract: dict, workload_id: str,
                               run_id: str, state: dict) -> list[dict]:
    """
    DP-13: No null injection by transformation.
    Compares current null counts per field to last observed.
    An increase in null count = null injection.
    """
    required = contract.get("required_fields", [])
    if not required:
        return [_ev("DP-13", "unknown", 1, 0.40,
                    "No required_fields to compare null counts against",
                    workload_id, run_id)]

    events = []
    for field in required:
        try:
            rows = db.query(
                f"SELECT COUNT(*) AS n FROM {table} WHERE {field} IS NULL"
            )
            current_nulls = rows[0]["n"] if rows else 0
            prev_nulls = state.get("null_counts", {}).get(f"{table}.{field}")

            state.setdefault("null_counts", {})[f"{table}.{field}"] = current_nulls

            if prev_nulls is None:
                # First observation
                continue
            elif current_nulls > prev_nulls:
                delta = current_nulls - prev_nulls
                events.append(_ev("DP-13", "blocked", 1, 0.90,
                                  f"{field}: +{delta} NULLs introduced "
                                  f"({prev_nulls} → {current_nulls})",
                                  workload_id, run_id,
                                  "db_null_injection_check",
                                  f"{workload_id}/{field}"))
        except Exception as exc:
            events.append(_ev("DP-13", "unknown", 1, 0.30,
                              f"{field}: {exc}", workload_id, run_id))

    if not events:
        events.append(_ev("DP-13", "realized", 1, 0.85,
                          "No null injection detected in required fields",
                          workload_id, run_id,
                          "db_null_injection_check", workload_id))
    return events


def check_dp15_schema_conformance(db: DBConnection, table: str,
                                   contract: dict, workload_id: str,
                                   run_id: str) -> list[dict]:
    """
    DP-15: Records conform to current schema.
    Validates a sample of records against declared types.
    """
    type_checks = contract.get("type_constraints", {})
    if not type_checks:
        return [_ev("DP-15", "unknown", 1, 0.40,
                    "No type_constraints in contract",
                    workload_id, run_id)]

    events = []
    for field, expected_type in type_checks.items():
        try:
            # Check for type violations by trying to cast
            if expected_type in ("integer", "int", "bigint"):
                sql = (f"SELECT COUNT(*) AS n FROM {table} WHERE {field} IS NOT NULL "
                       f"AND CAST({field} AS TEXT) NOT SIMILAR TO '[0-9]+'")
            elif expected_type in ("numeric", "float", "decimal"):
                sql = (f"SELECT COUNT(*) AS n FROM {table} WHERE {field} IS NOT NULL "
                       f"AND {field}::TEXT !~ '^[+-]?[0-9]+\\.?[0-9]*([eE][+-]?[0-9]+)?$'")
            elif expected_type == "email":
                sql = (f"SELECT COUNT(*) AS n FROM {table} WHERE {field} IS NOT NULL "
                       f"AND {field} NOT LIKE '%@%.%'")
            elif expected_type == "uuid":
                sql = (f"SELECT COUNT(*) AS n FROM {table} WHERE {field} IS NOT NULL "
                       f"AND {field}::TEXT !~ "
                       f"'^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$'")
            else:
                continue

            rows = db.query(sql)
            violations = rows[0]["n"] if rows else 0
            if violations > 0:
                events.append(_ev("DP-15", "blocked", 1, 0.85,
                                  f"{field}: {violations} values not conforming to {expected_type}",
                                  workload_id, run_id,
                                  "db_type_check", f"{workload_id}/{field}"))
            else:
                events.append(_ev("DP-15", "realized", 1, 0.85,
                                  f"{field}: all values conform to {expected_type}",
                                  workload_id, run_id,
                                  "db_type_check", f"{workload_id}/{field}"))
        except Exception as exc:
            events.append(_ev("DP-15", "unknown", 1, 0.30,
                              f"{field}: type check failed — {exc}",
                              workload_id, run_id))

    return events if events else [_ev("DP-15", "unknown", 1, 0.40,
                                      "No applicable type constraints",
                                      workload_id, run_id)]


def _redact_url(url: str) -> str:
    """Remove credentials from connection URL for safe logging."""
    return re.sub(r"://[^@]+@", "://***@", url)


# ── State persistence ─────────────────────────────────────────────────────

def _candidate_state_dirs() -> list[Path]:
    candidates: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path | None) -> None:
        if path is None:
            return
        key = str(path)
        if key in seen:
            return
        seen.add(key)
        candidates.append(path)

    env_dir = os.getenv("SKG_DATA_STATE_DIR")
    if env_dir:
        _add(Path(env_dir))

    state_root = os.getenv("SKG_STATE_DIR")
    if state_root:
        _add(Path(state_root) / "data_state")

    try:
        from skg.core.paths import SKG_STATE_DIR as _SKG_STATE_DIR
        _add(_SKG_STATE_DIR / "data_state")
    except Exception:
        pass

    _add(Path("/var/lib/skg/data_state"))
    _add(Path(tempfile.gettempdir()) / "skg" / "data_state")
    return candidates


def _state_file(workload_id: str, state_dir: Path) -> Path:
    safe_name = workload_id.replace("/", "_").replace("::", "_")
    return state_dir / f"{safe_name}.json"


def load_state(workload_id: str) -> dict:
    for state_dir in _candidate_state_dirs():
        state_file = _state_file(workload_id, state_dir)
        if not state_file.exists():
            continue
        try:
            return json.loads(state_file.read_text())
        except Exception:
            continue
    return {}


def save_state(workload_id: str, state: dict) -> None:
    payload = json.dumps(state, indent=2)
    for state_dir in _candidate_state_dirs():
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
            _state_file(workload_id, state_dir).write_text(payload)
            return
        except OSError:
            continue


# ── Main profiling entry point ────────────────────────────────────────────

def profile_table(url: str, table: str, workload_id: str,
                  contract_path: str | None = None,
                  attack_path_id: str = "data_completeness_failure_v1",
                  run_id: str | None = None,
                  batch_id: str | None = None) -> list[dict]:
    """
    Profile a database table and return all DP-* wicket events.
    This is the complete observation pass — equivalent to the SSH sensor's
    full host enumeration.
    """
    run_id   = run_id or str(uuid.uuid4())[:8]
    contract = load_contract(contract_path, table)
    state    = load_state(workload_id)

    print(f"  [DATA] Profiling {table} @ {_redact_url(url)}")
    print(f"  [DATA] Workload: {workload_id}  Run: {run_id}")

    db = DBConnection(url)
    all_events: list[dict] = []

    # DP-10: connectivity first — opens the connection.
    # If this fails, everything else is blocked (upstream source down).
    dp10 = check_dp10_upstream_reachable(db, url, workload_id, run_id)
    all_events.extend(dp10)
    if dp10[0]["payload"]["status"] == "blocked":
        print(f"  [DATA] Source unreachable — stopping (DP-10=blocked)")
        for wid in ["DP-03","DP-04","DP-05","DP-08","DP-09","DP-11","DP-12","DP-13"]:
            all_events.append(_ev(wid, "blocked", 4, 0.90,
                                  "Blocked by upstream source unreachable (DP-10)",
                                  workload_id, run_id))
        save_state(workload_id, state)
        return all_events

    # Connection is already open from DP-10 — do not call db.connect() again
    try:
        if not db.table_exists(table):
            print(f"  [DATA] Table {table} not found")
            return all_events + [_ev("DP-01", "blocked", 3, 0.99,
                                     f"Table {table} does not exist",
                                     workload_id, run_id)]

        # Run all checks
        checks = [
            ("DP-01", lambda: check_dp01_schema_contract(contract, workload_id, run_id)),
            ("DP-02", lambda: check_dp02_schema_version(db, table, contract, workload_id, run_id, state)),
            ("DP-03", lambda: check_dp03_required_fields(db, table, contract, workload_id, run_id)),
            ("DP-04", lambda: check_dp04_bounds(db, table, contract, workload_id, run_id)),
            ("DP-05", lambda: check_dp05_referential_integrity(db, table, contract, workload_id, run_id)),
            ("DP-08", lambda: check_dp08_duplicates(db, table, contract, workload_id, run_id)),
            ("DP-09", lambda: check_dp09_freshness(db, table, contract, workload_id, run_id)),
            ("DP-11", lambda: check_dp11_batch_complete(db, table, contract, workload_id, run_id, batch_id)),
            ("DP-12", lambda: check_dp12_distribution(db, table, contract, workload_id, run_id, state)),
            ("DP-13", lambda: check_dp13_null_injection(db, table, contract, workload_id, run_id, state)),
            ("DP-15", lambda: check_dp15_schema_conformance(db, table, contract, workload_id, run_id)),
        ]

        for wicket_id, check_fn in checks:
            try:
                evs = check_fn()
                all_events.extend(evs)
                statuses = [e["payload"]["status"] for e in evs]
                worst = ("blocked" if "blocked" in statuses
                         else "unknown" if "unknown" in statuses
                         else "realized")
                marker = "✓" if worst == "realized" else ("✗" if worst == "blocked" else "?")
                print(f"    {marker} {wicket_id} [{worst}]  "
                      f"{evs[0]['payload']['detail'][:70] if evs else ''}")
            except Exception as exc:
                all_events.append(_ev(wicket_id, "unknown", 1, 0.20,
                                      f"Check error: {exc}", workload_id, run_id))

    finally:
        db.close()
        save_state(workload_id, state)

    # Stamp attack_path_id onto each event payload so the projector can resolve
    # the correct attack path rather than default-pathing everything.
    if attack_path_id:
        for ev in all_events:
            try:
                if "attack_path_id" not in ev["payload"]:
                    ev["payload"]["attack_path_id"] = attack_path_id
            except (KeyError, TypeError):
                pass

    return all_events


def profile_from_config(config_path: str, out_dir: str) -> dict[str, list]:
    """
    Profile multiple data sources from a YAML config file.

    Config format:
    data_sources:
      - url: postgresql://user:pass@host/db
        table: orders
        workload_id: banking::orders
        contract: /etc/skg/contracts/orders.json
        attack_path_id: data_completeness_failure_v1

      - url: sqlite:///mydb.db
        table: sensor_readings
        workload_id: agriculture::sensors
    """
    import yaml
    data = yaml.safe_load(Path(config_path).read_text())
    sources = data.get("data_sources", [])
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    results = {}
    for src in sources:
        url         = src.get("url", "")
        table       = src.get("table", "")
        workload_id = src.get("workload_id") or f"data::{table}"
        contract    = src.get("contract")
        apid        = src.get("attack_path_id", "data_completeness_failure_v1")

        if not url or not table:
            continue

        events = profile_table(url, table, workload_id, contract, apid)
        run_id = events[0]["payload"]["run_id"] if events else "unknown"

        out_file = out_path / f"data_{workload_id.replace('::', '_')}_{run_id}.ndjson"
        with open(out_file, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

        results[workload_id] = events
        print(f"  → {len(events)} events → {out_file.name}")

    return results


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="SKG data pipeline profiler — emits DP-* wicket events")
    p.add_argument("--url",         help="SQLAlchemy connection URL")
    p.add_argument("--table",       help="Table or view name to profile")
    p.add_argument("--workload-id", dest="workload_id", default=None)
    p.add_argument("--contract",    default=None, help="Schema contract JSON")
    p.add_argument("--attack-path-id", dest="attack_path_id",
                   default="data_completeness_failure_v1")
    p.add_argument("--batch-id",    dest="batch_id", default=None)
    p.add_argument("--run-id",      dest="run_id", default=None)
    p.add_argument("--out",         default=None, help="Output .ndjson file")
    p.add_argument("--out-dir",     dest="out_dir",
                   default="/var/lib/skg/events",
                   help="Output directory (for --config mode)")
    p.add_argument("--config",      default=None,
                   help="YAML config for multi-source profiling")
    args = p.parse_args()

    if args.config:
        results = profile_from_config(args.config, args.out_dir)
        total = sum(len(v) for v in results.values())
        print(f"\n  {len(results)} sources profiled, {total} events total")
        return

    if not args.url or not args.table:
        p.print_help()
        return

    workload_id = args.workload_id or f"data::{args.table}"
    events = profile_table(
        url=args.url, table=args.table,
        workload_id=workload_id,
        contract_path=args.contract,
        attack_path_id=args.attack_path_id,
        run_id=args.run_id,
        batch_id=args.batch_id,
    )

    out = args.out or f"/var/lib/skg/events/data_{args.table}_{events[0]['payload']['run_id'] if events else 'x'}.ndjson"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    realized = sum(1 for e in events if e["payload"]["status"] == "realized")
    blocked  = sum(1 for e in events if e["payload"]["status"] == "blocked")
    unknown  = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"\n  {len(events)} events: {realized}R {blocked}B {unknown}U → {out}")


if __name__ == "__main__":
    main()
