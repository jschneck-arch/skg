"""
sqlmap_adapter.py
=================
Automated SQL injection exploitation via sqlmap.
Fires after WB-05 (SQL injection) is realized or suspected.

Emits:
  WB-05: SQL injection confirmed
  WB-10: auth bypass via SQLi
  DP-10: database reachable (if data dumped)
  DP-02: schema extracted
"""
from __future__ import annotations
import json, os, re, subprocess, sys, tempfile, uuid
from datetime import datetime, timezone
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

    events = []
    now = datetime.now(timezone.utc).isoformat()

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

    if injectable:
        events.append({
            "type": "obs.attack.precondition",
            "id": str(uuid.uuid4()),
            "ts": now,
            "payload": {
                "wicket_id": "WB-05",
                "target_ip": target_url,
                "workload_id": f"web::{target_url}",
                "domain": "web",
                "status": "realized",
                "confidence": 0.95,
                "evidence": f"sqlmap confirmed injection. DBMS: {db_type or 'unknown'}",
                "decay_class": "structural",
                "source": "sqlmap",
                "db_type": db_type,
            },
        })

        if db_type:
            events.append({
                "type": "obs.attack.precondition",
                "id": str(uuid.uuid4()),
                "ts": now,
                "payload": {
                    "wicket_id": "DP-10",
                    "target_ip": target_url,
                    "workload_id": f"data::{target_url}",
                    "domain": "data",
                    "status": "realized",
                    "confidence": 0.90,
                    "evidence": f"Database accessible via SQLi: {db_type}",
                    "decay_class": "structural",
                    "source": "sqlmap",
                },
            })

        if tables_dumped:
            events.append({
                "type": "obs.attack.precondition",
                "id": str(uuid.uuid4()),
                "ts": now,
                "payload": {
                    "wicket_id": "DP-02",
                    "target_ip": target_url,
                    "workload_id": f"data::{target_url}",
                    "domain": "data",
                    "status": "realized",
                    "confidence": 0.92,
                    "evidence": "sqlmap dumped table structure",
                    "decay_class": "structural",
                    "source": "sqlmap",
                },
            })

    if auth_bypassed:
        events.append({
            "type": "obs.attack.precondition",
            "id": str(uuid.uuid4()),
            "ts": now,
            "payload": {
                "wicket_id": "WB-10",
                "target_ip": target_url,
                "workload_id": f"web::{target_url}",
                "domain": "web",
                "status": "realized",
                "confidence": 0.88,
                "evidence": "sqlmap achieved authentication bypass via SQL injection",
                "decay_class": "structural",
                "source": "sqlmap",
            },
        })

    # Write events to NDJSON
    out_file = out_dir / f"sqlmap_events_{uuid.uuid4().hex[:8]}.ndjson"
    if events:
        out_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    return events
