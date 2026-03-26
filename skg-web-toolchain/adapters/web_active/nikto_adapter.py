"""
nikto_adapter.py
================
Web vulnerability scanning via nikto.
Emits wicket events for any confirmed findings.
"""
from __future__ import annotations
import json, re, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Nikto finding → wicket mapping
NIKTO_WICKET_MAP = {
    r"sql\s*injection":         ("WB-05", 0.75),
    r"xss":                     ("WB-08", 0.70),
    r"command.*(exec|inject)":  ("WB-07", 0.75),
    r"directory.*listing":      ("WB-03", 0.80),
    r"phpinfo":                 ("WB-17", 0.90),
    r"server.*version":         ("WB-02", 0.85),
    r"backup.*file":            ("WB-04", 0.85),
    r"\.git":                   ("WB-04", 0.90),
    r"shellshock":              ("WB-07", 0.90),
    r"file.*inclusion":         ("WB-06", 0.75),
    r"default.*password":       ("WB-09", 0.80),
    r"authentication.*bypass":  ("WB-10", 0.80),
    r"path.*traversal":         ("WB-15", 0.80),
    r"ssrf":                    ("WB-18", 0.75),
}


def run_nikto(target_url: str, out_dir: Path) -> list[dict]:
    """Run nikto against target_url, return events."""
    try:
        subprocess.run(["nikto", "-Version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"nikto_{uuid.uuid4().hex[:8]}.json"

    cmd = [
        "nikto",
        "-h", target_url,
        "-Format", "json",
        "-output", str(out_file),
        "-Tuning", "123456789",  # all tests
        "-timeout", "10",
        "-nointeractive",
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired:
        pass

    events = []
    now = datetime.now(timezone.utc).isoformat()

    if out_file.exists():
        try:
            data = json.loads(out_file.read_text())
            vulnerabilities = data.get("vulnerabilities", [])
        except Exception:
            vulnerabilities = []

        seen_wickets: dict[str, float] = {}
        for vuln in vulnerabilities:
            msg = (vuln.get("msg") or "").lower()
            url = vuln.get("url") or ""
            for pattern, (wicket_id, conf) in NIKTO_WICKET_MAP.items():
                if re.search(pattern, msg, re.IGNORECASE):
                    if seen_wickets.get(wicket_id, 0) < conf:
                        seen_wickets[wicket_id] = conf

        for wicket_id, confidence in seen_wickets.items():
            events.append({
                "type": "obs.attack.precondition",
                "id": str(uuid.uuid4()),
                "ts": now,
                "payload": {
                    "wicket_id": wicket_id,
                    "target_ip": target_url,
                    "workload_id": f"web::{target_url}",
                    "domain": "web",
                    "status": "realized",
                    "confidence": confidence,
                    "evidence": f"nikto detected pattern matching {wicket_id}",
                    "decay_class": "operational",
                    "source": "nikto",
                },
            })

    return events
