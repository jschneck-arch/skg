"""
sqlmap_adapter.py
=================
Automated SQL injection exploitation via sqlmap.
Fires after WB-14 (auth surface) or WB-01 (web service) is realized.

Emits:
  WB-41: SQL injection injectable (confirmed vuln)
  WB-10: auth bypass via SQLi
  DP-10: database reachable (if data dumped)
  DP-02: schema extracted
"""
from __future__ import annotations
import json, re, subprocess, sys, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def run_sqlmap(target_url: str, out_dir: Path, forms: bool = True,
               level: int = 2, risk: int = 1) -> list[dict]:
    """
    Run sqlmap against target_url.
    Returns list of obs.attack.precondition events.

    level 1-5 (default 2 for engagement balance)
    risk 1-3 (default 1 — avoid destructive tests unless authorized)
    """
    try:
        subprocess.run(["sqlmap", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_output = out_dir / f"sqlmap_{uuid.uuid4().hex[:8]}"

    cmd = [
        "sqlmap",
        "-u", target_url,
        "--batch",              # non-interactive
        "--level", str(level),
        "--risk", str(risk),
        "--output-dir", str(tmp_output),
        "--timeout", "30",
        "--retries", "2",
        "--threads", "4",
        "--no-cast",            # avoid type casting issues
    ]
    if forms:
        cmd.append("--forms")   # auto-detect forms

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        output = ""

    # Parse sqlmap output for injection findings
    injectable = bool(re.search(r"(is vulnerable|SQL injection|sqlmap identified)", output, re.IGNORECASE))
    db_type = ""
    db_match = re.search(r"back-end DBMS:\s*(.+)", output, re.IGNORECASE)
    if db_match:
        db_type = db_match.group(1).strip()[:60]

    tables_dumped = bool(re.search(r"Table:.*\n.*rows", output, re.IGNORECASE))
    auth_bypassed = bool(re.search(r"(admin.*logged|authentication.*bypassed|session.*cookie)", output, re.IGNORECASE))

    from skg.sensors.event_builder import make_precondition_event
    from skg.identity.workload import canonical_workload_id

    web_workload_id = canonical_workload_id(target_url, domain="web")
    data_workload_id = canonical_workload_id(target_url, domain="data")

    events = []

    if injectable:
        events.append(make_precondition_event(
            wicket_id="WB-41",
            status="realized",
            workload_id=web_workload_id,
            source_id="sqlmap_adapter",
            toolchain="skg-web-toolchain",
            target_ip=target_url,
            domain="web",
            label="sqli_injectable",
            detail=f"sqlmap confirmed injection. DBMS: {db_type or 'unknown'}",
            attack_path_id="web_sqli_to_shell_v1",
            evidence_rank=3,
            source_kind="sqlmap",
            confidence=0.95,
        ))

        if db_type:
            events.append(make_precondition_event(
                wicket_id="DP-10",
                status="realized",
                workload_id=data_workload_id,
                source_id="sqlmap_adapter",
                toolchain="skg-web-toolchain",
                target_ip=target_url,
                domain="data",
                label="database_accessible",
                detail=f"Database accessible via SQLi: {db_type}",
                evidence_rank=3,
                source_kind="sqlmap",
                confidence=0.90,
            ))

        if tables_dumped:
            events.append(make_precondition_event(
                wicket_id="DP-02",
                status="realized",
                workload_id=data_workload_id,
                source_id="sqlmap_adapter",
                toolchain="skg-web-toolchain",
                target_ip=target_url,
                domain="data",
                label="schema_extracted",
                detail="sqlmap dumped table structure",
                evidence_rank=3,
                source_kind="sqlmap",
                confidence=0.92,
            ))

    if auth_bypassed:
        events.append(make_precondition_event(
            wicket_id="WB-10",
            status="realized",
            workload_id=web_workload_id,
            source_id="sqlmap_adapter",
            toolchain="skg-web-toolchain",
            target_ip=target_url,
            domain="web",
            label="auth_bypass_via_sqli",
            detail="sqlmap achieved authentication bypass via SQL injection",
            attack_path_id="web_sqli_to_shell_v1",
            evidence_rank=3,
            source_kind="sqlmap",
            confidence=0.88,
        ))

    # Write events to NDJSON
    out_file = out_dir / f"sqlmap_events_{uuid.uuid4().hex[:8]}.ndjson"
    if events:
        out_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    return events
