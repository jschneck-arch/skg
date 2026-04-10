"""
skg.intel.engagement_dataset
==============================
Converts red team engagement telemetry (events, projections, transitions,
folds, proposals) into a structured SQLite database, then runs the data
pipeline toolchain against it to assess the dataset's own integrity.

This closes a loop that is easy to miss: the red team engagement produces
a data product. That data product — obs.attack.precondition events,
interp results, gravity cycles, proposal chains — has its own data quality
conditions. Schema consistency, completeness, freshness, referential
integrity between events and projections, duplicate run_ids.

Applying the data domain to the red team domain is not circular.
It is the domain-agnostic claim made concrete: the same substrate that
evaluates whether a web attack is realizable also evaluates whether the
telemetry recording that attack is trustworthy.

Usage:
    python engagement_dataset.py --out /var/lib/skg/engagement.db
    python engagement_dataset.py --out eng.db --analyze
    python engagement_dataset.py --out eng.db --analyze --report eng_report.json

    from skg.intel.engagement_dataset import (
        build_engagement_db, analyze_engagement_integrity
    )
"""
from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from skg_core.config.paths import EVENTS_DIR, INTERP_DIR, SKG_CONFIG_DIR, SKG_STATE_DIR, SKG_HOME, DISCOVERY_DIR, DELTA_DIR

# ── Schema ────────────────────────────────────────────────────────────────

SCHEMA = """
-- Raw observation events (obs.attack.precondition)
-- node_key is the stable identity anchor (identity_key from canonical_observation_subject).
-- target_ip is retained as the routable network address (additional context only).
CREATE TABLE IF NOT EXISTS observations (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    collected_at    TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    toolchain       TEXT NOT NULL,
    wicket_id       TEXT NOT NULL,
    status          TEXT NOT NULL CHECK(status IN ('realized','blocked','unknown')),
    workload_id     TEXT NOT NULL,
    node_key        TEXT NOT NULL DEFAULT '',
    attack_path_id  TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    evidence_rank   INTEGER NOT NULL,
    confidence      REAL NOT NULL,
    detail          TEXT,
    target_ip       TEXT,
    domain          TEXT
);

-- Projection results (interp files)
-- node_key is the stable identity anchor derived from workload_id via parse_workload_ref.
-- It is used for referential integrity checks so that projections and observations
-- with different workload_id manifestations (raw IP vs ssh:: prefix) are still joined.
CREATE TABLE IF NOT EXISTS projections (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    attack_path_id  TEXT NOT NULL,
    workload_id     TEXT NOT NULL,
    node_key        TEXT NOT NULL DEFAULT '',
    classification  TEXT NOT NULL,
    score           REAL,
    realized_count  INTEGER,
    blocked_count   INTEGER,
    unknown_count   INTEGER,
    run_id          TEXT,
    domain          TEXT,
    sheaf_h1        INTEGER DEFAULT 0,
    source_file     TEXT
);

-- Gravity cycles (field_state snapshots)
-- node_key is the stable identity anchor; target_ip is the routable address.
CREATE TABLE IF NOT EXISTS gravity_cycles (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    node_key        TEXT NOT NULL DEFAULT '',
    target_ip       TEXT NOT NULL,
    energy_before   REAL,
    energy_after    REAL,
    instrument      TEXT,
    success         INTEGER,
    events_produced INTEGER,
    run_id          TEXT
);

-- Operator proposals (exploit_dispatch output)
CREATE TABLE IF NOT EXISTS proposals (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    path_id         TEXT NOT NULL,
    node_key        TEXT NOT NULL DEFAULT '',
    target_ip       TEXT NOT NULL,
    status          TEXT NOT NULL,
    msf_module      TEXT,
    run_id          TEXT,
    triggered_at    TEXT
);

-- Delta transitions (DeltaStore output)
CREATE TABLE IF NOT EXISTS transitions (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    workload_id     TEXT NOT NULL,
    wicket_id       TEXT NOT NULL,
    from_state      TEXT NOT NULL,
    to_state        TEXT NOT NULL,
    signal_weight   REAL,
    meaning         TEXT,
    run_id          TEXT
);

-- Folds detected by gravity
CREATE TABLE IF NOT EXISTS folds (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    node_key        TEXT NOT NULL DEFAULT '',
    target_ip       TEXT NOT NULL,
    fold_type       TEXT NOT NULL,
    location        TEXT,
    detail          TEXT,
    discovery_prob  REAL,
    gravity_weight  REAL,
    resolved        INTEGER DEFAULT 0
);

-- Engagement metadata
CREATE TABLE IF NOT EXISTS engagement_meta (
    key             TEXT PRIMARY KEY,
    value           TEXT,
    updated_at      TEXT
);
"""

# ── Ingest functions ──────────────────────────────────────────────────────

def _infer_domain(toolchain: str, attack_path_id: str, wicket_id: str) -> str:
    """Infer domain from available signals."""
    if wicket_id.startswith("WB-"):  return "web"
    if wicket_id.startswith("HO-"):  return "host"
    if wicket_id.startswith("CE-"):  return "container_escape"
    if wicket_id.startswith("AD-"):  return "ad_lateral"
    if wicket_id.startswith("AP-"):  return "aprs"
    if wicket_id.startswith("BA-"):  return "binary_analysis"
    if wicket_id.startswith("FI-"):  return "sysaudit"
    if wicket_id.startswith("PI-"):  return "sysaudit"
    if wicket_id.startswith("LI-"):  return "sysaudit"
    if wicket_id.startswith("DP-"):  return "data_pipeline"
    if "web" in toolchain:           return "web"
    if "host" in toolchain:          return "host"
    if "ad" in toolchain:            return "ad_lateral"
    if "aprs" in toolchain:          return "aprs"
    return "unknown"


def ingest_events(conn: sqlite3.Connection, events_dir: Path) -> int:
    """
    Load all obs.attack.precondition events from the events directory.
    Handles events from all sensors: SSH, web, net, BH, CVE, agent, data.
    """
    count = 0
    seen: set[str] = set()

    for ndjson_file in sorted(events_dir.glob("**/*.ndjson")):
        try:
            for line in ndjson_file.read_text(encoding="utf-8",
                                               errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue

                if ev.get("type") != "obs.attack.precondition":
                    continue

                ev_id = ev.get("id", str(uuid.uuid4()))
                if ev_id in seen:
                    continue
                seen.add(ev_id)

                payload  = ev.get("payload", {})
                prov     = ev.get("provenance", {})
                evidence = prov.get("evidence", {})
                source   = ev.get("source", {})

                wicket_id = (payload.get("wicket_id") or
                             payload.get("node_id") or "")
                domain = _infer_domain(
                    source.get("toolchain", ""),
                    payload.get("attack_path_id", ""),
                    wicket_id,
                )

                node_key = str(
                    payload.get("identity_key")
                    or payload.get("workload_id")
                    or payload.get("target_ip")
                    or ""
                ).strip()
                conn.execute("""
                    INSERT OR IGNORE INTO observations
                    (id, ts, collected_at, source_id, toolchain,
                     wicket_id, status, workload_id, node_key, attack_path_id,
                     run_id, evidence_rank, confidence, detail,
                     target_ip, domain)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    ev_id,
                    ev.get("ts", ""),
                    evidence.get("collected_at", ev.get("ts", "")),
                    source.get("source_id", ""),
                    source.get("toolchain", ""),
                    wicket_id,
                    payload.get("status", "unknown"),
                    payload.get("workload_id", ""),
                    node_key,
                    payload.get("attack_path_id", ""),
                    payload.get("run_id", ""),
                    prov.get("evidence_rank", 0),
                    evidence.get("confidence", 0.0),
                    payload.get("detail", "")[:500],
                    payload.get("target_ip", ""),
                    domain,
                ))
                count += 1
        except Exception:
            continue

    conn.commit()
    return count


def ingest_projections(conn: sqlite3.Connection, interp_dir: Path) -> int:
    """Load all projection results from the interp directory."""
    count = 0
    seen:  set[str] = set()

    for json_file in sorted(interp_dir.glob("*.json")):
        try:
            data = json.loads(json_file.read_text())
            if "payload" in data:
                payload = data["payload"]
                raw_id  = data.get("id")
            else:
                payload = data
                raw_id  = None

            # Build a deterministic dedup key from (workload_id, attack_path_id).
            # Files without an explicit id field previously got a fresh uuid4 on
            # every build, causing the same realized path to appear N times in
            # the projections table (once per file per build run).
            workload_id_key   = payload.get("workload_id", "")
            attack_path_key   = payload.get("attack_path_id", "")
            if raw_id:
                ev_id = raw_id
            elif workload_id_key and attack_path_key:
                # Stable hash: same (workload_id, attack_path_id) → same id
                import hashlib as _hl
                ev_id = _hl.sha1(
                    f"{workload_id_key}::{attack_path_key}".encode()
                ).hexdigest()[:32]
            else:
                ev_id = str(uuid.uuid4())

            if ev_id in seen:
                continue
            seen.add(ev_id)

            # Score key varies by domain
            score = (payload.get("host_score") or payload.get("web_score") or
                     payload.get("lateral_score") or payload.get("escape_score") or
                     payload.get("aprs") or payload.get("data_score") or 0.0)

            sheaf = payload.get("sheaf", {})
            h1    = 1 if sheaf.get("has_obstruction") else 0

            # Infer domain from score key or path
            for key, dom in [("host_score","host"),("web_score","web"),
                             ("lateral_score","ad_lateral"),("escape_score","container_escape"),
                             ("aprs","aprs"),("data_score","data_pipeline")]:
                if key in payload:
                    domain = dom
                    break
            else:
                domain = _infer_domain("", payload.get("attack_path_id",""), "")

            from skg.identity import parse_workload_ref as _parse_ref
            _proj_wid = payload.get("workload_id", "")
            _proj_node_key = _parse_ref(_proj_wid).get("identity_key", _proj_wid)

            conn.execute("""
                INSERT OR IGNORE INTO projections
                (id, ts, attack_path_id, workload_id, node_key, classification,
                 score, realized_count, blocked_count, unknown_count,
                 run_id, domain, sheaf_h1, source_file)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ev_id,
                data.get("ts", payload.get("computed_at", "")),
                payload.get("attack_path_id", ""),
                _proj_wid,
                _proj_node_key,
                payload.get("classification", ""),
                float(score) if score else 0.0,
                len(payload.get("realized", [])),
                len(payload.get("blocked",  [])),
                len(payload.get("unknown",  [])),
                payload.get("run_id", ""),
                domain,
                h1,
                json_file.name,
            ))
            count += 1
        except Exception:
            continue

    conn.commit()
    return count


def ingest_folds(conn: sqlite3.Connection, discovery_dir: Path) -> int:
    """Load fold state from gravity discovery output."""
    count = 0
    folds_dir = discovery_dir / "folds"
    if not folds_dir.exists():
        return 0

    for fold_file in sorted(folds_dir.glob("folds_*.json")):
        try:
            folds = json.loads(fold_file.read_text())
            # Extract IP from filename
            ip = fold_file.stem.replace("folds_", "").replace("_", ".")

            for fold in (folds if isinstance(folds, list) else [folds]):
                fold_id = fold.get("id", str(uuid.uuid4()))
                fold_ip = fold.get("target_ip", ip)
                fold_node_key = str(
                    fold.get("identity_key") or fold.get("node_key") or fold_ip
                ).strip()
                conn.execute("""
                    INSERT OR IGNORE INTO folds
                    (id, ts, node_key, target_ip, fold_type, location,
                     detail, discovery_prob, gravity_weight, resolved)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (
                    fold_id,
                    fold.get("detected_at", ""),
                    fold_node_key,
                    fold_ip,
                    fold.get("fold_type", ""),
                    fold.get("location", ""),
                    fold.get("detail", "")[:500],
                    fold.get("discovery_probability", 0.0),
                    fold.get("gravity_weight", 0.0),
                    1 if fold.get("resolved") else 0,
                ))
                count += 1
        except Exception:
            continue

    conn.commit()
    return count


def ingest_transitions(conn: sqlite3.Connection, delta_dir: Path) -> int:
    """Load DeltaStore transition history."""
    count = 0
    delta_file = delta_dir / "delta_store.ndjson"
    if not delta_file.exists():
        # Try alternate locations
        for candidate in [
            delta_dir.parent / "delta_store.ndjson",
            delta_dir.parent / "state" / "delta_store.ndjson",
        ]:
            if candidate.exists():
                delta_file = candidate
                break
        else:
            return 0

    seen: set[str] = set()
    try:
        for line in delta_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                t = json.loads(line)
            except Exception:
                continue

            t_id = t.get("id", str(uuid.uuid4()))
            if t_id in seen:
                continue
            seen.add(t_id)

            conn.execute("""
                INSERT OR IGNORE INTO transitions
                (id, ts, workload_id, wicket_id, from_state,
                 to_state, signal_weight, meaning, run_id)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                t_id,
                t.get("ts", ""),
                t.get("workload_id", ""),
                t.get("wicket_id", t.get("node_id", "")),
                t.get("from_state", ""),
                t.get("to_state", ""),
                t.get("signal_weight", 0.0),
                t.get("meaning", ""),
                t.get("run_id", ""),
            ))
            count += 1
    except Exception:
        pass

    conn.commit()
    return count


# ── Schema migration ─────────────────────────────────────────────────────

def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Apply incremental schema changes to an existing database."""
    existing = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM pragma_table_info('projections')"
        )
    }
    if "node_key" not in existing:
        conn.execute(
            "ALTER TABLE projections ADD COLUMN node_key TEXT NOT NULL DEFAULT ''"
        )
        conn.commit()


# ── Build the database ────────────────────────────────────────────────────

def build_engagement_db(
    db_path: str | Path,
    events_dir:    Path | None = None,
    interp_dir:    Path | None = None,
    discovery_dir: Path | None = None,
    delta_dir:     Path | None = None,
    verbose: bool = True,
) -> dict:
    """
    Build a SQLite engagement database from all SKG telemetry.

    Returns ingestion summary dict.
    """
    db_path    = Path(db_path)
    events_dir    = events_dir    or EVENTS_DIR
    interp_dir    = interp_dir    or INTERP_DIR
    discovery_dir = discovery_dir or DISCOVERY_DIR
    delta_dir     = delta_dir     or DELTA_DIR

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)
    _migrate_schema(conn)

    now = datetime.now(timezone.utc).isoformat()

    if verbose:
        print(f"  Building engagement database: {db_path}")

    # Ingest all telemetry
    obs_count  = ingest_events(conn, events_dir)
    proj_count = ingest_projections(conn, interp_dir)
    fold_count = ingest_folds(conn, discovery_dir)
    trans_count = ingest_transitions(conn, delta_dir)

    # Also scan discovery dir for events (gravity outputs)
    disc_obs = ingest_events(conn, discovery_dir)

    total_obs = obs_count + disc_obs

    if verbose:
        print(f"    observations:  {total_obs}")
        print(f"    projections:   {proj_count}")
        print(f"    folds:         {fold_count}")
        print(f"    transitions:   {trans_count}")

    # Engagement metadata
    meta = {
        "generated_at":   now,
        "events_dir":     str(events_dir),
        "interp_dir":     str(interp_dir),
        "total_obs":      str(total_obs),
        "total_proj":     str(proj_count),
        "total_folds":    str(fold_count),
        "total_trans":    str(trans_count),
    }
    for k, v in meta.items():
        conn.execute("""
            INSERT OR REPLACE INTO engagement_meta (key, value, updated_at)
            VALUES (?,?,?)
        """, (k, v, now))
    conn.commit()

    # Quick integrity summary
    rows = conn.execute("""
        SELECT
          (SELECT COUNT(*) FROM observations) AS obs,
          (SELECT COUNT(DISTINCT workload_id) FROM observations) AS workloads,
          (SELECT COUNT(DISTINCT target_ip) FROM observations WHERE target_ip != '') AS targets,
          (SELECT COUNT(DISTINCT wicket_id) FROM observations) AS unique_wickets,
          (SELECT COUNT(*) FROM observations WHERE status = 'realized') AS realized,
          (SELECT COUNT(*) FROM observations WHERE status = 'blocked') AS blocked,
          (SELECT COUNT(*) FROM observations WHERE status = 'unknown') AS unknown_obs,
          (SELECT COUNT(*) FROM projections) AS projections,
          (SELECT COUNT(*) FROM projections WHERE classification = 'realized') AS paths_realized,
          (SELECT COUNT(*) FROM projections WHERE classification LIKE 'indeterminate%') AS paths_indet,
          (SELECT COUNT(*) FROM folds WHERE resolved = 0) AS open_folds,
          (SELECT COUNT(*) FROM transitions) AS transitions
    """).fetchone()

    summary = {
        "db_path":         str(db_path),
        "observations":    rows[0],
        "workloads":       rows[1],
        "targets":         rows[2],
        "unique_wickets":  rows[3],
        "realized":        rows[4],
        "blocked":         rows[5],
        "unknown":         rows[6],
        "projections":     rows[7],
        "paths_realized":  rows[8],
        "paths_indet":     rows[9],
        "open_folds":      rows[10],
        "transitions":     rows[11],
    }

    conn.close()

    if verbose:
        print(f"\n  Engagement DB summary:")
        print(f"    {summary['observations']} observations "
              f"({summary['realized']}R {summary['blocked']}B {summary['unknown']}U)")
        print(f"    {summary['unique_wickets']} unique wickets across "
              f"{summary['workloads']} workloads, {summary['targets']} targets")
        print(f"    {summary['projections']} projections "
              f"({summary['paths_realized']} realized, "
              f"{summary['paths_indet']} indeterminate)")
        print(f"    {summary['open_folds']} open folds, "
              f"{summary['transitions']} delta transitions")

    return summary


# ── Data integrity analysis of the engagement dataset ─────────────────────

def analyze_engagement_integrity(
    db_path: str | Path,
    verbose: bool = True,
) -> dict:
    """
    Apply data pipeline domain integrity analysis to the engagement database.

    The engagement telemetry is a data product. We apply DP-* wicket logic
    to it directly — treating the SQLite tables as pipeline stages.

    This answers: "Is the telemetry itself trustworthy?"

    Checks run:
      DP-01: Schema contract present (the SCHEMA defines it)
      DP-03: Required fields populated (no NULL wicket_id, workload_id, status)
      DP-04: Values within bounds (status ∈ {realized, blocked, unknown},
                                    evidence_rank 1-6,
                                    confidence 0.0-1.0)
      DP-05: Referential integrity (every projection references a known workload)
      DP-08: No duplicate event IDs
      DP-09: Freshness (most recent observation within TTL)
      DP-11: Batch completeness (all domains have at least one observation)
      DP-12: Distribution stable (status distribution within expected bounds)

    Returns dict matching data pipeline domain output format.
    """
    db_path = Path(db_path)
    if not db_path.exists():
        return {"error": f"Database not found: {db_path}"}

    conn   = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    results: dict[str, dict] = {}
    now    = datetime.now(timezone.utc)

    if verbose:
        print(f"\n  Analyzing engagement dataset integrity: {db_path}")
        print(f"  {'Wicket':8s} {'Status':10s}  Detail")
        print(f"  {'-'*8} {'-'*10}  {'-'*60}")

    def _check(wicket_id: str, status: str, detail: str):
        results[wicket_id] = {"status": status, "detail": detail}
        if verbose:
            marker = "✓" if status == "realized" else \
                     ("✗" if status == "blocked" else "?")
            print(f"  {marker} {wicket_id:6s} [{status:8s}]  {detail[:70]}")

    # DP-01: Schema contract
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    expected = {"observations","projections","folds","transitions","engagement_meta"}
    missing_tables = expected - set(tables)
    if missing_tables:
        _check("DP-01", "blocked",
               f"Missing tables: {missing_tables}")
    else:
        _check("DP-01", "realized",
               f"All {len(expected)} tables present")

    # DP-03: Required fields populated
    null_checks = [
        ("observations", "wicket_id"),
        ("observations", "workload_id"),
        ("observations", "status"),
        ("observations", "ts"),
        ("projections",  "attack_path_id"),
        ("projections",  "classification"),
    ]
    null_violations = []
    for table, col in null_checks:
        if table not in tables:
            continue
        n = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {col} IS NULL OR {col} = ''"
        ).fetchone()[0]
        if n > 0:
            null_violations.append(f"{table}.{col}: {n} nulls")

    if null_violations:
        _check("DP-03", "blocked",
               f"NULL required fields: {'; '.join(null_violations[:3])}")
    else:
        n_obs = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        _check("DP-03", "realized",
               f"All required fields populated across {n_obs} observations")

    # DP-04: Values within declared bounds
    bound_violations = []

    # status must be in valid set
    invalid_status = conn.execute("""
        SELECT COUNT(*) FROM observations
        WHERE status NOT IN ('realized','blocked','unknown')
    """).fetchone()[0]
    if invalid_status > 0:
        bound_violations.append(f"status: {invalid_status} invalid values")

    # evidence_rank must be 1-6
    invalid_rank = conn.execute("""
        SELECT COUNT(*) FROM observations
        WHERE evidence_rank NOT BETWEEN 1 AND 6
    """).fetchone()[0]
    if invalid_rank > 0:
        bound_violations.append(f"evidence_rank: {invalid_rank} outside 1-6")

    # confidence must be 0.0-1.0
    invalid_conf = conn.execute("""
        SELECT COUNT(*) FROM observations
        WHERE confidence < 0.0 OR confidence > 1.0
    """).fetchone()[0]
    if invalid_conf > 0:
        bound_violations.append(f"confidence: {invalid_conf} outside 0-1")

    # classification must be valid
    invalid_cls = conn.execute("""
        SELECT COUNT(*) FROM projections
        WHERE classification NOT IN
          ('realized','not_realized','indeterminate','indeterminate_h1','unknown')
    """).fetchone()[0]
    if invalid_cls > 0:
        bound_violations.append(f"classification: {invalid_cls} invalid values")

    if bound_violations:
        _check("DP-04", "blocked",
               f"Bound violations: {'; '.join(bound_violations)}")
    else:
        _check("DP-04", "realized",
               "All field values within declared bounds")

    # DP-05: Referential integrity — projections reference known workloads.
    # Join on node_key (stable identity) rather than exact workload_id so that
    # different manifestation shapes (e.g. "10.0.0.1" vs "ssh::10.0.0.1") for
    # the same identity are not treated as orphaned.
    orphaned = conn.execute("""
        SELECT COUNT(*) FROM projections p
        WHERE p.node_key NOT IN (
            SELECT DISTINCT node_key FROM observations WHERE node_key != ''
        )
        AND p.workload_id NOT IN (
            SELECT DISTINCT workload_id FROM observations
        )
    """).fetchone()[0]
    if orphaned > 0:
        _check("DP-05", "blocked",
               f"{orphaned} projections reference workloads with no observations")
    else:
        n_proj = conn.execute("SELECT COUNT(*) FROM projections").fetchone()[0]
        _check("DP-05", "realized",
               f"All {n_proj} projections reference known workloads")

    # DP-08: Duplicate event IDs
    dup_count = conn.execute("""
        SELECT COUNT(*) FROM (
            SELECT id, COUNT(*) AS n FROM observations GROUP BY id HAVING n > 1
        )
    """).fetchone()[0]
    if dup_count > 0:
        _check("DP-08", "blocked",
               f"{dup_count} duplicate observation IDs")
    else:
        _check("DP-08", "realized",
               "No duplicate event IDs")

    # DP-09: Freshness — most recent observation within 72h
    latest_row = conn.execute("""
        SELECT MAX(ts) FROM observations WHERE ts != ''
    """).fetchone()[0]
    if latest_row:
        try:
            latest_dt = datetime.fromisoformat(
                latest_row.replace("Z", "+00:00"))
            if latest_dt.tzinfo is None:
                from datetime import timezone as _tz
                latest_dt = latest_dt.replace(tzinfo=_tz.utc)
            age_h = (now - latest_dt).total_seconds() / 3600
            if age_h > 72:
                _check("DP-09", "blocked",
                       f"Most recent observation is {age_h:.1f}h old (TTL=72h)")
            else:
                _check("DP-09", "realized",
                       f"Most recent observation {age_h:.1f}h ago (TTL=72h)")
        except Exception:
            _check("DP-09", "unknown",
                   "Could not parse observation timestamp")
    else:
        _check("DP-09", "blocked",
               "No observations with timestamps — dataset empty or corrupt")

    # DP-11: Batch completeness — all expected domains present
    observed_domains = {r[0] for r in conn.execute(
        "SELECT DISTINCT domain FROM observations WHERE domain != 'unknown'"
    ).fetchall()}

    expected_domains = {"web", "host", "sysaudit"}  # minimum expected
    missing_domains  = expected_domains - observed_domains
    if missing_domains:
        _check("DP-11", "blocked",
               f"Missing domains: {sorted(missing_domains)} "
               f"(present: {sorted(observed_domains)})")
    else:
        _check("DP-11", "realized",
               f"All expected domains present: {sorted(observed_domains)}")

    # DP-12: Status distribution within expected bounds
    total_obs = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    if total_obs >= 10:
        dist = conn.execute("""
            SELECT status, COUNT(*) AS n FROM observations GROUP BY status
        """).fetchall()
        dist_map = {r[0]: r[1] for r in dist}
        unknown_pct = dist_map.get("unknown", 0) / total_obs

        # >90% unknown suggests collection is running but nothing is being resolved
        if unknown_pct > 0.90:
            _check("DP-12", "blocked",
                   f"{unknown_pct:.0%} of observations are unknown — "
                   f"possible collection misconfiguration")
        # All realized and no unknowns — possible stale fixed dataset
        elif dist_map.get("unknown", 0) == 0 and dist_map.get("realized", 0) > 0:
            _check("DP-12", "unknown",
                   "All observations resolved — dataset may be static snapshot, "
                   "not live telemetry")
        else:
            r_pct = dist_map.get("realized", 0) / total_obs
            b_pct = dist_map.get("blocked",  0) / total_obs
            _check("DP-12", "realized",
                   f"Status distribution normal: "
                   f"{r_pct:.0%}R {b_pct:.0%}B {unknown_pct:.0%}U")
    else:
        _check("DP-12", "unknown",
               f"Only {total_obs} observations — insufficient for distribution check")

    conn.close()

    # Build a structured output matching data domain interp format
    status_counts = {"realized": 0, "blocked": 0, "unknown": 0}
    for wid, r in results.items():
        s = r["status"]
        status_counts[s if s in status_counts else "unknown"] += 1

    blocked_wids  = [w for w, r in results.items() if r["status"] == "blocked"]
    realized_wids = [w for w, r in results.items() if r["status"] == "realized"]
    unknown_wids  = [w for w, r in results.items() if r["status"] == "unknown"]

    if blocked_wids:
        classification = "not_realized"
    elif unknown_wids:
        classification = "indeterminate"
    else:
        classification = "realized"

    if verbose:
        print(f"\n  Engagement dataset integrity: {classification}")
        if blocked_wids:
            print(f"  Issues detected: {blocked_wids}")

    return {
        "db_path":        str(db_path),
        "classification": classification,
        "realized":       realized_wids,
        "blocked":        blocked_wids,
        "unknown":        unknown_wids,
        "checks":         results,
        "domain":         "engagement_integrity",
        "computed_at":    now.isoformat(),
    }


def generate_engagement_report(
    db_path: str | Path,
    out_path: str | Path | None = None,
) -> dict:
    """
    Full engagement report: dataset integrity + content summary + attack paths realized.
    Writes JSON report if out_path provided.
    """
    db_path = Path(db_path)
    conn    = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    integrity = analyze_engagement_integrity(db_path, verbose=True)

    # Content summary
    print(f"\n  Engagement content:")

    domains = conn.execute("""
        SELECT domain, COUNT(*) AS obs,
               SUM(CASE status WHEN 'realized' THEN 1 ELSE 0 END) AS r,
               SUM(CASE status WHEN 'blocked'  THEN 1 ELSE 0 END) AS b,
               SUM(CASE status WHEN 'unknown'  THEN 1 ELSE 0 END) AS u
        FROM observations GROUP BY domain ORDER BY obs DESC
    """).fetchall()

    domain_summary = []
    for row in domains:
        print(f"    {row['domain']:22s}  {row['obs']:4d} obs  "
              f"({row['r']}R {row['b']}B {row['u']}U)")
        domain_summary.append(dict(row))

    # Realized attack paths
    realized_paths = conn.execute("""
        SELECT attack_path_id, workload_id, MAX(score) AS score, domain
        FROM projections WHERE classification = 'realized'
        GROUP BY workload_id, attack_path_id
        ORDER BY score DESC
    """).fetchall()

    print(f"\n  Realized attack paths ({len(realized_paths)}):")
    for path in realized_paths:
        print(f"    ✓ {path['attack_path_id']:40s}  "
              f"score={path['score']:.2f}  ({path['workload_id']})")

    # H1 obstructions
    h1_paths = conn.execute("""
        SELECT attack_path_id, workload_id
        FROM projections WHERE sheaf_h1 = 1
        GROUP BY workload_id, attack_path_id
    """).fetchall()
    if h1_paths:
        print(f"\n  H¹ obstructions ({len(h1_paths)} — structural cycle, "
              f"not resolvable by observation):")
        for p in h1_paths:
            print(f"    ~ {p['attack_path_id']:40s}  ({p['workload_id']})")

    # Open folds
    open_folds = conn.execute("""
        SELECT fold_type, COUNT(*) AS n, AVG(gravity_weight) AS avg_weight
        FROM folds WHERE resolved = 0
        GROUP BY fold_type ORDER BY avg_weight DESC
    """).fetchall()
    if open_folds:
        print(f"\n  Open folds (unresolved uncertainty):")
        for fold in open_folds:
            print(f"    {fold['fold_type']:14s}  n={fold['n']}  "
                  f"avg_Φ={fold['avg_weight']:.2f}")

    # High-signal transitions
    high_signal = conn.execute("""
        SELECT meaning, COUNT(*) AS n
        FROM transitions WHERE signal_weight >= 0.8
        GROUP BY meaning ORDER BY n DESC LIMIT 5
    """).fetchall()
    if high_signal:
        print(f"\n  High-signal transitions (weight ≥ 0.8):")
        for t in high_signal:
            print(f"    {t['meaning']:30s}  n={t['n']}")

    conn.close()

    report = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "db_path":          str(db_path),
        "integrity":        integrity,
        "domain_summary":   domain_summary,
        "realized_paths":   [dict(r) for r in realized_paths],
        "h1_obstructions":  [dict(r) for r in h1_paths],
        "open_folds":       [dict(r) for r in open_folds],
        "high_signal_transitions": [dict(r) for r in high_signal],
    }

    # ── LLM narrative synthesis ───────────────────────────────────────────────
    # Call the LLM pool (or Ollama backend fallback) to produce a paragraph-level
    # summary: what was found, what was compromised, what to fix, risk rating.
    narrative = _generate_llm_narrative(report)
    if narrative:
        report["narrative"] = narrative
        print(f"\n  Engagement Narrative:")
        for line in narrative.strip().splitlines()[:20]:
            print(f"    {line}")

    if out_path:
        Path(out_path).write_text(json.dumps(report, indent=2))
        print(f"\n  Report written: {out_path}")

    return report


def _generate_llm_narrative(report: dict) -> str | None:
    """
    Call the LLM pool (or Ollama fallback) to generate a natural-language
    engagement narrative from the structured report data.

    Returns the narrative string, or None if no LLM backend is available.
    """
    import sys
    from pathlib import Path as _P

    # Build a compact summary for the prompt — avoid sending the full report JSON
    realized = report.get("realized_paths", [])
    h1 = report.get("h1_obstructions", [])
    folds = report.get("open_folds", [])
    domain_summary = report.get("domain_summary", [])
    integrity = report.get("integrity", {})

    prompt_data = {
        "realized_paths": [
            {"path": r.get("attack_path_id"), "target": r.get("workload_id"),
             "score": r.get("score"), "domain": r.get("domain")}
            for r in realized[:10]
        ],
        "h1_obstructions": [
            {"path": h.get("attack_path_id"), "target": h.get("workload_id")}
            for h in h1[:5]
        ],
        "open_folds": [
            {"type": f.get("fold_type"), "n": f.get("n"), "avg_weight": f.get("avg_weight")}
            for f in folds[:5]
        ],
        "domain_observations": [
            {"domain": d.get("domain"), "obs": d.get("obs"),
             "realized": d.get("r"), "blocked": d.get("b")}
            for d in domain_summary[:8]
        ],
        "integrity_issues": integrity.get("blocked", []),
    }

    system_prompt = (
        "You are an expert security analyst summarizing a red team engagement report. "
        "Write 3-5 concise paragraphs covering: (1) what attack paths were realized and on "
        "which targets, (2) what was structurally blocked (H¹ obstructions), (3) key data "
        "quality issues if any, (4) open uncertainty areas (folds), (5) remediation priority. "
        "Be factual. Do not invent findings not present in the data."
    )
    user_prompt = (
        "Engagement data:\n" + json.dumps(prompt_data, indent=2)
    )
    full_prompt = system_prompt + "\n\n" + user_prompt

    # Try LLM pool first, then Ollama backend fallback
    try:
        skg_root = _P(__file__).resolve().parents[2]
        sys.path.insert(0, str(skg_root))
        from skg.resonance.llm_pool import LLMPool
        import yaml as _yaml
        cfg_candidates = [
            SKG_CONFIG_DIR / "skg_config.yaml",
            skg_root / "config" / "skg_config.yaml",
        ]
        cfg_path = next((candidate for candidate in cfg_candidates if candidate.exists()), cfg_candidates[0])
        pool_cfg = {}
        if cfg_path.exists():
            pool_cfg = (_yaml.safe_load(cfg_path.read_text()) or {}).get("resonance", {}).get("llm_pool", {})
        if pool_cfg.get("enabled"):
            pool = LLMPool(pool_cfg)
            return pool.generate(full_prompt, max_tokens=512)
    except Exception:
        pass

    try:
        from skg.resonance.ollama_backend import OllamaBackend
        backend = OllamaBackend()
        if backend.available():
            return backend.generate(full_prompt, num_predict=400)
    except Exception:
        pass

    return None


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="Build and analyze the SKG engagement dataset")
    p.add_argument("--out",     required=True,
                   help="Output SQLite database path")
    p.add_argument("--analyze", action="store_true",
                   help="Run data integrity analysis after building")
    p.add_argument("--report",  default=None,
                   help="Write full report to JSON file")
    p.add_argument("--events-dir",    default=None)
    p.add_argument("--interp-dir",    default=None)
    p.add_argument("--discovery-dir", default=None)
    a = p.parse_args()

    summary = build_engagement_db(
        db_path=a.out,
        events_dir    = Path(a.events_dir)    if a.events_dir    else None,
        interp_dir    = Path(a.interp_dir)    if a.interp_dir    else None,
        discovery_dir = Path(a.discovery_dir) if a.discovery_dir else None,
    )

    if a.analyze or a.report:
        generate_engagement_report(a.out, out_path=a.report)


if __name__ == "__main__":
    main()
