"""
skg/intel/redteam_to_data.py
==============================
Cross-domain data integrity test.

Reads red team observation events (HO-*, WB-*, CE-*, FI-*, PI-*, LI-*, AD-*)
and derives the implied data integrity posture (DP-* wicket states) of any
data pipelines running on or connected to the compromised infrastructure.

The core insight: a security finding has implications for data trustworthiness
that are not just analogous — they are causally connected. A system with a
confirmed RCE does not just have a security problem. The data it produces,
stores, and processes cannot be assumed to be unmodified.

This is the formal connection between the security domain and the data domain
that Work4 needs. The mapping is:

  Security observation → Data integrity implication

It uses the same tri-state projection logic:
  BLOCKED  = data integrity condition definitely violated (e.g. RCE confirmed)
  REALIZED = data integrity condition confirmed (e.g. no known compromise)
  UNKNOWN  = security state unclear, data integrity cannot be determined

The output is a complete DP-* assessment derived purely from red team
telemetry — no database connection required. If you have run a red team
engagement, you can immediately produce a data integrity report for any
databases on those systems.

Usage:
    python redteam_to_data.py --events-dir /var/lib/skg/events \\
                               --out /var/lib/skg/discovery/data_from_redteam.ndjson

    # Or pass --out-dir to write into the discovery directory directly.
"""
from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOLCHAIN = "skg-redteam-to-data"
SOURCE_ID = "intel.redteam_data_integrity"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dp_ev(wicket_id: str, status: str, confidence: float,
           detail: str, workload_id: str, run_id: str,
           source_sec_wicket: str, sec_workload: str) -> dict:
    """
    Build a DP-* wicket event derived from a security observation.

    Evidence rank 4 (network/inference): this is a derived observation,
    not a direct database query. Lower confidence than a direct measurement,
    but higher than static documentation because it's based on live telemetry.
    """
    now = iso_now()
    return {
        "id":   str(uuid.uuid4()),
        "ts":   now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id":  SOURCE_ID,
            "toolchain":  TOOLCHAIN,
            "version":    "1.0.0",
        },
        "payload": {
            "wicket_id":          wicket_id,
            "status":             status,
            "workload_id":        workload_id,
            "detail":             detail,
            "run_id":             run_id,
            "observed_at":        now,
            "derived_from": {
                "security_wicket":   source_sec_wicket,
                "security_workload": sec_workload,
                "derivation":        "cross_domain_implication",
            },
        },
        "provenance": {
            "evidence_rank": 4,  # inferred from security telemetry
            "evidence": {
                "source_kind":  "redteam_cross_domain",
                "pointer":      f"security://{sec_workload}/{source_sec_wicket}",
                "collected_at": now,
                "confidence":   confidence,
            },
        },
    }


# ── Cross-domain mapping table ─────────────────────────────────────────────
#
# Each entry: (security_wicket_id, security_status) → list of DP implications
#
# Format per implication:
#   dp_wicket:    which DP-* wicket is affected
#   status:       what tri-state to set on that DP wicket
#   confidence:   how certain this implication is (0.0–1.0)
#   detail:       human-readable explanation
#   rationale:    the causal chain justifying this implication
#
# Confidence levels:
#   0.95  — near-certain causal chain (e.g. RCE → data modified)
#   0.80  — strong implication (e.g. credential access → data accessible)
#   0.65  — moderate implication (e.g. vulnerable package → may affect pipeline)
#   0.50  — weak implication (e.g. network access → data may be reachable)

SECURITY_TO_DATA: dict[tuple[str,str], list[dict]] = {

    # ── RCE / Code Execution ──────────────────────────────────────────────

    ("CE-01", "realized"): [
        {"dp_wicket": "DP-07", "status": "blocked", "confidence": 0.95,
         "detail": "Container code execution confirmed — transformation logic in this container cannot be trusted",
         "rationale": "RCE in a container running ETL/pipeline code means the transformation output may be attacker-controlled"},
        {"dp_wicket": "DP-11", "status": "blocked", "confidence": 0.85,
         "detail": "Container RCE — batch completeness unverifiable; attacker may have modified batch state",
         "rationale": "An attacker with code execution can cancel jobs, inject records, or modify completion flags"},
        {"dp_wicket": "DP-13", "status": "blocked", "confidence": 0.80,
         "detail": "Container RCE — null injection by attacker cannot be ruled out",
         "rationale": "Code execution gives direct access to data transformation before it reaches the database"},
    ],

    ("PI-05", "blocked"): [
        # PI-05 BLOCKED means shell WAS spawned by service — RCE confirmed
        {"dp_wicket": "DP-07", "status": "blocked", "confidence": 0.95,
         "detail": "Shell spawned by service process — pipeline code execution chain compromised at OS level",
         "rationale": "A shell child of a web/app service means the service was exploited; any data it processes is untrusted"},
        {"dp_wicket": "DP-03", "status": "blocked", "confidence": 0.80,
         "detail": "Service-level RCE — attacker may have injected NULL into required fields via application layer",
         "rationale": "With application-level code execution, all data written by that application is suspect"},
    ],

    ("WB-10", "realized"): [
        {"dp_wicket": "DP-08", "status": "blocked", "confidence": 0.90,
         "detail": "SQLi data extraction confirmed — database integrity cannot be assumed; records may have been duplicated or injected via SQLi",
         "rationale": "Confirmed SQL injection against the application layer is direct evidence of database manipulation capability"},
        {"dp_wicket": "DP-04", "status": "blocked", "confidence": 0.75,
         "detail": "SQLi extraction confirmed — field value bounds may have been violated by injected data",
         "rationale": "SQL injection allows inserting arbitrary values bypassing application-layer validation"},
        {"dp_wicket": "DP-12", "status": "blocked", "confidence": 0.70,
         "detail": "SQLi extraction confirmed — distribution may have shifted due to data exfiltration or injection",
         "rationale": "An attacker who can extract can also inject, potentially altering statistical distributions"},
    ],

    ("WB-09", "realized"): [
        {"dp_wicket": "DP-08", "status": "unknown", "confidence": 0.65,
         "detail": "Injectable SQL parameter found — duplicate records may exist from injection attempts",
         "rationale": "Confirmed SQL injection vector (without confirmed extraction) means database integrity is uncertain"},
        {"dp_wicket": "DP-03", "status": "unknown", "confidence": 0.60,
         "detail": "Injectable parameter found — NULL injection possible through application layer",
         "rationale": "SQL injection can INSERT NULL values that bypass application-level required field checks"},
    ],

    # ── System Compromise ─────────────────────────────────────────────────

    ("FI-07", "blocked"): [
        # FI-07 BLOCKED means new UID-0 account — persistent root access
        {"dp_wicket": "DP-02", "status": "blocked", "confidence": 0.90,
         "detail": "New root account detected — attacker has persistent root; schema may have been altered",
         "rationale": "Root access on a database server allows direct schema modification outside application control"},
        {"dp_wicket": "DP-09", "status": "blocked", "confidence": 0.80,
         "detail": "Persistent root access — freshness claims unverifiable; attacker can backdate data modifications",
         "rationale": "With root access, system timestamps can be altered, making TTL-based freshness checks unreliable"},
        {"dp_wicket": "DP-07", "status": "blocked", "confidence": 0.85,
         "detail": "Persistent root access — any pipeline transformation running on this host is suspect",
         "rationale": "Root can modify pipeline scripts, binaries, or configuration without leaving application logs"},
    ],

    ("FI-01", "blocked"): [
        # FI-01 BLOCKED means system binary changed — potential rootkit
        {"dp_wicket": "DP-07", "status": "blocked", "confidence": 0.85,
         "detail": "System binary modified — pipeline execution environment cannot be trusted",
         "rationale": "A modified system binary (python, bash, etc.) may produce incorrect transformation output"},
        {"dp_wicket": "DP-06", "status": "unknown", "confidence": 0.70,
         "detail": "System binary modification — declared transformations may not have run as expected",
         "rationale": "If the runtime was modified, transformation application cannot be confirmed"},
    ],

    ("PI-08", "blocked"): [
        # PI-08 BLOCKED means LD_PRELOAD hijacking confirmed
        {"dp_wicket": "DP-07", "status": "blocked", "confidence": 0.95,
         "detail": "LD_PRELOAD hijacking confirmed — all library calls on this system are intercepted; transformation correctness cannot be guaranteed",
         "rationale": "LD_PRELOAD intercepts all libc calls including file I/O, network, and memory — complete control over any process"},
        {"dp_wicket": "DP-03", "status": "blocked", "confidence": 0.90,
         "detail": "LD_PRELOAD hijacking — required field validation may be bypassed at the library level",
         "rationale": "A preloaded library can intercept write() calls and modify data before it reaches the database driver"},
    ],

    # ── Credential Access ─────────────────────────────────────────────────

    ("HO-09", "realized"): [
        {"dp_wicket": "DP-10", "status": "unknown", "confidence": 0.70,
         "detail": "Credentials found in environment — if DB credentials, pipeline source may be accessible to attacker",
         "rationale": "Credentials in env variables are often database credentials; attacker has same access as the pipeline"},
        {"dp_wicket": "DP-05", "status": "unknown", "confidence": 0.60,
         "detail": "Credential access — referential integrity may have been violated via direct DB access with stolen credentials",
         "rationale": "Direct DB access bypasses application-layer FK enforcement"},
    ],

    ("AD-01", "realized"): [
        {"dp_wicket": "DP-05", "status": "unknown", "confidence": 0.55,
         "detail": "Domain user enumerated — AD-joined databases may be accessible; referential integrity cannot be assumed",
         "rationale": "Domain user access to AD-joined SQL Server bypasses application authentication"},
    ],

    # ── Log/Audit Tampering ───────────────────────────────────────────────

    ("LI-02", "blocked"): [
        # LI-02 BLOCKED means log file shrank — tampering
        {"dp_wicket": "DP-11", "status": "blocked", "confidence": 0.90,
         "detail": "Log file tampered — batch audit trail unreliable; completeness cannot be verified from logs",
         "rationale": "Pipeline batch completion is typically verified from audit logs; if logs are tampered, completeness is unverifiable"},
        {"dp_wicket": "DP-09", "status": "blocked", "confidence": 0.85,
         "detail": "Log tampering — data freshness timestamps may have been altered in logs",
         "rationale": "Freshness verification that relies on log timestamps cannot be trusted after log tampering"},
    ],

    ("LI-08", "blocked"): [
        # LI-08 BLOCKED means wtmp/lastlog tampered
        {"dp_wicket": "DP-09", "status": "blocked", "confidence": 0.85,
         "detail": "Login history tampered — access timeline unreliable; data modification timestamps unverifiable",
         "rationale": "Attacker covering tracks by wiping login history is consistent with modifying data and hiding the access"},
    ],

    # ── Container/Infrastructure ──────────────────────────────────────────

    ("CE-03", "realized"): [
        {"dp_wicket": "DP-10", "status": "unknown", "confidence": 0.75,
         "detail": "Docker socket accessible — containerized data sources can be restarted or replaced by attacker",
         "rationale": "Docker socket access allows stopping/starting containers, replacing images, and modifying volumes"},
        {"dp_wicket": "DP-13", "status": "unknown", "confidence": 0.65,
         "detail": "Docker socket accessible — container-level data injection or NULL injection possible via volume manipulation",
         "rationale": "Direct volume access lets an attacker modify data files before the database reads them"},
    ],

    ("HO-15", "realized"): [
        {"dp_wicket": "DP-10", "status": "unknown", "confidence": 0.60,
         "detail": "Container runtime accessible to non-root — pipeline data sources may be manipulable",
         "rationale": "Container runtime access allows container manipulation; may affect data source availability"},
    ],

    # ── Vulnerability Confirmation ────────────────────────────────────────

    ("HO-11", "realized"): [
        {"dp_wicket": "DP-07", "status": "unknown", "confidence": 0.65,
         "detail": "Vulnerable package installed on pipeline host — transformation code may be exploitable",
         "rationale": "A vulnerable package in the pipeline runtime is a potential entry point to corrupt transformations"},
    ],

    ("HO-06", "realized"): [
        {"dp_wicket": "DP-02", "status": "unknown", "confidence": 0.60,
         "detail": "Sudo misconfiguration — privilege escalation possible; schema modification without admin approval",
         "rationale": "NOPASSWD sudo to a privileged command can be used to modify database schemas or pipeline configs"},
    ],

    # ── Positive security observations (data confirmed safe) ──────────────

    ("LI-05", "realized"): [
        {"dp_wicket": "DP-11", "status": "realized", "confidence": 0.75,
         "detail": "auditd active with rules — batch operations are audited; completeness verifiable from audit log",
         "rationale": "Kernel audit trail for file/process events provides tamper-evident record of batch execution"},
    ],

    ("LI-06", "realized"): [
        {"dp_wicket": "DP-09", "status": "realized", "confidence": 0.70,
         "detail": "Logs forwarded to remote SIEM — freshness timestamps cannot be retroactively modified",
         "rationale": "Remote log forwarding creates tamper-evident timestamps; freshness claims are verifiable"},
    ],

    ("FI-01", "realized"): [
        {"dp_wicket": "DP-07", "status": "realized", "confidence": 0.70,
         "detail": "System binaries match baseline — pipeline execution environment has not been tampered",
         "rationale": "Confirmed binary integrity means the transformation runtime is executing as intended"},
    ],

    ("PI-08", "realized"): [
        {"dp_wicket": "DP-07", "status": "realized", "confidence": 0.80,
         "detail": "No LD_PRELOAD hijacking — library call interception not present; transformation library calls are authentic",
         "rationale": "Confirmed absence of LD_PRELOAD means the pipeline's library calls are not intercepted"},
    ],
}


def load_security_events(events_dir: Path) -> list[dict]:
    """Load all obs.attack.precondition events from EVENTS_DIR."""
    events = []
    for f in sorted(events_dir.glob("*.ndjson"))[-200:]:
        try:
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                ev = json.loads(line)
                if ev.get("type") == "obs.attack.precondition":
                    events.append(ev)
        except Exception:
            continue
    return events


def derive_data_integrity(
    security_events: list[dict],
    data_workload_prefix: str = "data::",
    run_id: str | None = None,
) -> list[dict]:
    """
    Derive DP-* wicket events from a set of security observation events.

    For each security workload that has realised observations, generates
    a corresponding data workload ID and emits DP-* events based on the
    cross-domain mapping table.

    Returns list of DP-* obs.attack.precondition events.
    """
    run_id = run_id or str(uuid.uuid4())[:8]

    # Index security events: (workload_id, wicket_id) → latest status
    latest: dict[tuple, dict] = {}
    for ev in security_events:
        p   = ev.get("payload", {})
        wid = p.get("wicket_id", "")
        wkl = p.get("workload_id", "")
        ts  = ev.get("ts", "")
        key = (wkl, wid)
        if key not in latest or ts > latest[key]["ts"]:
            latest[key] = {
                "status":       p.get("status", "unknown"),
                "workload_id":  wkl,
                "wicket_id":    wid,
                "ts":           ts,
                "detail":       p.get("detail", ""),
            }

    # Group by security workload
    by_workload: dict[str, dict[str, str]] = defaultdict(dict)
    for (wkl, wid), info in latest.items():
        by_workload[wkl][wid] = info["status"]

    # Generate DP-* events for each security workload
    derived_events = []

    for sec_workload, wicket_states in by_workload.items():
        # Create a data workload ID that corresponds to this security workload
        # Strip existing prefixes (ssh::, net::, audit::) and use bare IP/name
        bare = sec_workload
        for prefix in ("ssh::", "net::", "audit::", "web::", "cve::", "binary::"):
            if bare.startswith(prefix):
                bare = bare[len(prefix):]
                break
        data_workload_id = f"{data_workload_prefix}{bare}"

        applied: set[tuple] = set()  # (dp_wicket, status) pairs already emitted

        for (sec_wid, sec_status), implications in SECURITY_TO_DATA.items():
            if wicket_states.get(sec_wid) == sec_status:
                for impl in implications:
                    dp_wid   = impl["dp_wicket"]
                    dp_status = impl["status"]

                    # Take strongest status: blocked > unknown > realized
                    key = (dp_wid,)
                    existing = next(
                        (e for e in derived_events
                         if e["payload"]["workload_id"] == data_workload_id
                         and e["payload"]["wicket_id"] == dp_wid),
                        None
                    )
                    if existing:
                        prev_status = existing["payload"]["status"]
                        strength = {"blocked": 3, "unknown": 2, "realized": 1}
                        if strength.get(dp_status, 0) <= strength.get(prev_status, 0):
                            continue  # existing is already stronger or equal
                        # Remove the weaker event
                        derived_events = [
                            e for e in derived_events
                            if not (e["payload"]["workload_id"] == data_workload_id
                                    and e["payload"]["wicket_id"] == dp_wid)
                        ]

                    derived_events.append(_dp_ev(
                        wicket_id=dp_wid,
                        status=dp_status,
                        confidence=impl["confidence"],
                        detail=impl["detail"],
                        workload_id=data_workload_id,
                        run_id=run_id,
                        source_sec_wicket=sec_wid,
                        sec_workload=sec_workload,
                    ))

    return derived_events


def report(derived_events: list[dict]) -> dict:
    """
    Summarize derived data integrity events into an assessment report.
    """
    by_workload: dict[str, dict] = defaultdict(lambda: {
        "realized": [], "blocked": [], "unknown": []
    })

    for ev in derived_events:
        p      = ev["payload"]
        wkl    = p["workload_id"]
        wid    = p["wicket_id"]
        status = p["status"]
        by_workload[wkl][status].append(wid)

    try:
        from skg_core.substrate.node import NodeState, TriState
        from skg_core.substrate.path import Path as SKGPath
        from skg_core.substrate.projection import project_path
    except Exception:
        from skg.substrate.node import NodeState, TriState
        from skg.substrate.path import Path as SKGPath
        from skg.substrate.projection import project_path

    catalog_path = Path(__file__).parent.parent / \
        "skg-data-toolchain/contracts/catalogs/" \
        "attack_preconditions_catalog.data.v1.json"

    # Fallback path
    if not catalog_path.exists():
        catalog_path = Path("/opt/skg/skg-data-toolchain/contracts/catalogs/"
                            "attack_preconditions_catalog.data.v1.json")

    catalog = {}
    if catalog_path.exists():
        catalog = json.loads(catalog_path.read_text())

    workload_reports = {}
    for wkl, states in by_workload.items():
        n_r = len(states["realized"])
        n_b = len(states["blocked"])
        n_u = len(states["unknown"])
        total = n_r + n_b + n_u

        if n_b > 0:
            overall = "compromised"
        elif n_u > total * 0.5:
            overall = "uncertain"
        elif n_r > 0 and n_b == 0 and n_u == 0:
            overall = "appears_clean"
        else:
            overall = "partially_verified"

        # Project against completeness failure path
        path_projections = {}
        if catalog:
            node_states = {}
            for wid in states["realized"]:
                node_states[wid] = NodeState(wid, TriState.REALIZED, 0.8, iso_now())
            for wid in states["blocked"]:
                node_states[wid] = NodeState(wid, TriState.BLOCKED, 0.9, iso_now())
            for wid in states["unknown"]:
                node_states[wid] = NodeState.unknown(wid)

            for path_id, path_def in catalog.get("attack_paths", {}).items():
                req = path_def.get("required_wickets", [])
                if not req:
                    continue
                try:
                    result = project_path(
                        SKGPath(path_id, req),
                        node_states
                    )
                    path_projections[path_id] = result.classification
                except Exception:
                    pass

        workload_reports[wkl] = {
            "overall_posture":   overall,
            "realized_count":    n_r,
            "blocked_count":     n_b,
            "unknown_count":     n_u,
            "blocked_wickets":   states["blocked"],
            "realized_wickets":  states["realized"],
            "unknown_wickets":   states["unknown"],
            "path_projections":  path_projections,
            "interpretation": (
                f"Data pipeline on {wkl} is assessed as {overall}. "
                + (f"{n_b} data integrity condition(s) blocked by security findings. "
                   if n_b > 0 else "")
                + (f"{n_u} condition(s) uncertain due to security gaps. "
                   if n_u > 0 else "")
                + (f"{n_r} condition(s) confirmed clean by security posture."
                   if n_r > 0 else "")
            ),
        }

    return {
        "assessment_type": "cross_domain_data_integrity",
        "source":          "red_team_telemetry",
        "derived_events":  len(derived_events),
        "workloads":       workload_reports,
        "note": (
            "These DP-* assessments are derived from security observations, "
            "not direct database queries. Evidence rank 4 (inferred). "
            "Confidence varies by implication strength (0.50–0.95). "
            "A BLOCKED status means the security finding causally implies "
            "data integrity cannot be confirmed — not that data is definitely corrupted. "
            "Run skg data profile against the actual database to obtain rank-1 evidence."
        ),
    }


def main():
    import argparse
    p = argparse.ArgumentParser(
        description="Derive data integrity assessment from red team telemetry")
    p.add_argument("--events-dir", dest="events_dir",
                   default="/var/lib/skg/events",
                   help="Directory containing security observation events")
    p.add_argument("--out",       default=None,
                   help="Output NDJSON file for derived DP-* events")
    p.add_argument("--out-dir",   dest="out_dir", default=None,
                   help="Output directory (auto-named file)")
    p.add_argument("--run-id",    dest="run_id", default=None)
    p.add_argument("--report",    action="store_true",
                   help="Print assessment report to stdout")
    args = p.parse_args()

    events_dir = Path(args.events_dir)
    if not events_dir.exists():
        print(f"[WARN] Events directory not found: {events_dir}")
        security_events = []
    else:
        security_events = load_security_events(events_dir)
        print(f"  Loaded {len(security_events)} security events from {events_dir}")

    run_id = args.run_id or str(uuid.uuid4())[:8]
    derived = derive_data_integrity(security_events, run_id=run_id)

    print(f"\n  Derived {len(derived)} DP-* data integrity events")

    if args.report or not (args.out or args.out_dir):
        r = report(derived)
        print(f"\n  {'='*60}")
        print(f"  CROSS-DOMAIN DATA INTEGRITY ASSESSMENT")
        print(f"  {'='*60}")
        for wkl, wr in r["workloads"].items():
            marker = ("✗" if wr["overall_posture"] == "compromised"
                      else "?" if wr["overall_posture"] == "uncertain"
                      else "✓")
            print(f"\n  {marker} {wkl}")
            print(f"    Posture: {wr['overall_posture']}")
            print(f"    {wr['realized_count']}R {wr['blocked_count']}B {wr['unknown_count']}U")
            if wr["blocked_wickets"]:
                print(f"    Blocked: {wr['blocked_wickets']}")
            for pid, cls in wr.get("path_projections", {}).items():
                if cls != "indeterminate":
                    print(f"    Path {pid}: {cls}")
        print(f"\n  {r['note']}")

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as fh:
            for ev in derived:
                fh.write(json.dumps(ev) + "\n")
        print(f"\n  → {out}")

    elif args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"data_from_redteam_{run_id}.ndjson"
        with open(out, "w") as fh:
            for ev in derived:
                fh.write(json.dumps(ev) + "\n")
        print(f"\n  → {out}")


if __name__ == "__main__":
    main()
