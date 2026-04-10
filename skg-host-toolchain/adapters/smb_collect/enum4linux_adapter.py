"""
enum4linux_adapter.py
=====================
SMB/AD enumeration via enum4linux-ng.
Fires when HO-19 (SMB exposed) is realized.

Emits:
  HO-20: null session / anonymous access
  AD-01: domain user enumerated
  AD-02: domain group enumerated
  AD-03: password policy extracted
  HO-05: local user accounts enumerated
  HO-06: shares enumerable / accessible
"""
from __future__ import annotations
import json, re, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def run_enum4linux(target_ip: str, out_dir: Path,
                   username: str = "", password: str = "") -> list[dict]:
    """Run enum4linux-ng (or enum4linux) against target_ip."""
    # Try enum4linux-ng first, fall back to enum4linux
    tool = "enum4linux-ng"
    try:
        subprocess.run([tool, "--help"], capture_output=True, timeout=5)
    except FileNotFoundError:
        tool = "enum4linux"
        try:
            subprocess.run([tool], capture_output=True, timeout=5)
        except FileNotFoundError:
            # Try rpcclient as minimal fallback
            return _run_rpcclient(target_ip, out_dir, username, password)

    cmd = [tool, "-A", target_ip]  # -A = all simple enumeration
    if username:
        cmd += ["-u", username, "-p", password or ""]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        output = ""

    return _parse_enum4linux_output(output, target_ip, out_dir)


def _parse_enum4linux_output(output: str, target_ip: str, out_dir: Path) -> list[dict]:
    """Parse enum4linux output into obs.attack.precondition events."""
    events = []
    now = datetime.now(timezone.utc).isoformat()

    def ev(wicket_id, status, confidence, evidence, domain="host"):
        return {
            "type": "obs.attack.precondition",
            "id": str(uuid.uuid4()),
            "ts": now,
            "payload": {
                "wicket_id": wicket_id,
                "target_ip": target_ip,
                "identity_key": target_ip,
                "workload_id": f"{domain}::{target_ip}",
                "domain": domain,
                "status": status,
                "confidence": confidence,
                "evidence": evidence,
                "decay_class": "operational",
                "source": "enum4linux",
            },
        }

    # Null session
    if re.search(r"(null session|anonymous.*ok|session setup ok)", output, re.IGNORECASE):
        events.append(ev("HO-20", "realized", 0.90,
                         "Null session / anonymous access allowed"))

    # Domain users
    users = re.findall(r"user:\s*\[([^\]]+)\]", output, re.IGNORECASE)
    if users:
        events.append(ev("AD-01", "realized", 0.85,
                         f"Domain users enumerated: {', '.join(users[:5])}",
                         domain="ad_lateral"))
        events.append(ev("HO-05", "realized", 0.85,
                         f"Local/domain users: {', '.join(users[:5])}"))

    # Groups
    groups = re.findall(r"group:\s*\[([^\]]+)\]", output, re.IGNORECASE)
    if groups:
        events.append(ev("AD-02", "realized", 0.80,
                         f"Domain groups: {', '.join(groups[:5])}",
                         domain="ad_lateral"))

    # Password policy
    if re.search(r"(password policy|min.*password|lockout)", output, re.IGNORECASE):
        events.append(ev("AD-03", "realized", 0.80,
                         "Password policy extracted",
                         domain="ad_lateral"))

    # Shares
    shares = re.findall(r"sharename\s*:\s*(\S+)", output, re.IGNORECASE)
    if shares:
        events.append(ev("HO-06", "realized", 0.85,
                         f"SMB shares enumerated: {', '.join(shares[:5])}"))

    # Write
    out_file = out_dir / f"enum4linux_events_{target_ip.replace('.','_')}.ndjson"
    if events:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    return events


def _run_rpcclient(target_ip: str, out_dir: Path,
                   username: str, password: str) -> list[dict]:
    """Minimal fallback: rpcclient null session check."""
    try:
        cmd = ["rpcclient", "-U", f"{username}%{password}" if username else "%",
               "-N", target_ip, "-c", "enumdomusers"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return _parse_enum4linux_output(proc.stdout + proc.stderr, target_ip, out_dir)
    except Exception:
        return []
