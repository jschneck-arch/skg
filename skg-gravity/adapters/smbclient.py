"""
smbclient.py — SMB share enumeration adapter
=============================================
Lists shares, tests anonymous/guest access, and pulls interesting files via
smbclient.  Installed on this system at /usr/bin/smbclient.

Emits obs.attack.precondition events for:
  HO-19  SMB exposed                (any response)
  HO-25  share enumerable           (list succeeds — exploitable service)
  HO-26  null/anonymous session     (no creds required — world-readable share)
  HO-27  interesting files found    (credential-bearing files on shares)
  AD-04  sensitive share accessible (SYSVOL/NETLOGON/IPC$ accessible)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INSTRUMENT_NAME = "smbclient"

_SENSITIVE_SHARES = {"sysvol", "netlogon", "c$", "admin$", "ipc$"}
_INTERESTING_EXTS = re.compile(
    r"\.(txt|cfg|conf|config|ini|xml|json|yaml|yml|bak|old|backup|sql|"
    r"ps1|bat|cmd|vbs|log|passwd|shadow|key|pem|pfx|p12)$",
    re.IGNORECASE,
)


def run(
    ip: str,
    target: dict[str, Any],
    run_id: str,
    out_dir: Any,
    result: dict[str, Any],
    *,
    authorized: bool = False,
    node_key: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    from pathlib import Path as _Path
    from skg.sensors import envelope, precondition_payload

    _node_key = node_key or ip
    _out_dir  = _Path(str(out_dir)) if out_dir else _Path("/tmp/skg_gravity")
    _out_dir.mkdir(parents=True, exist_ok=True)

    creds = target.get("credentials") or {}
    username = creds.get("username") or ""
    password = creds.get("password") or ""

    events: list[dict] = []

    # ── 1. List shares ────────────────────────────────────────────────────
    shares = _list_shares(ip, username, password)

    if shares is None:
        result["error"] = "smbclient not available or host unreachable"
        return result

    if not shares:
        result["success"] = True
        result["note"] = "No shares found"
        return result

    share_names = [s["name"] for s in shares]
    events.append(envelope(
        event_type="obs.attack.precondition",
        source_id="smbclient_adapter",
        toolchain="skg-host-toolchain",
        payload=precondition_payload(
            wicket_id="HO-19",
            label=f"SMB responded on {ip}",
            domain="host",
            workload_id=f"host::{_node_key}",
            realized=True,
            detail=f"smbclient -L returned {len(shares)} share(s)",
        ),
        evidence_rank=3,
        source_kind="smbclient",
        pointer=f"smb://{ip}",
        confidence=0.95,
    ))
    events.append(envelope(
        event_type="obs.attack.precondition",
        source_id="smbclient_adapter",
        toolchain="skg-host-toolchain",
        payload=precondition_payload(
            wicket_id="HO-25",
            label=f"SMB shares enumerable on {ip}: {', '.join(share_names[:5])}",
            domain="host",
            workload_id=f"host::{_node_key}",
            realized=True,
            detail=f"Shares: {', '.join(share_names)}",
        ),
        evidence_rank=3,
        source_kind="smbclient",
        pointer=f"smb://{ip}",
        confidence=0.90,
    ))

    # Null/anonymous session if we listed without creds
    if not username:
        events.append(envelope(
            event_type="obs.attack.precondition",
            source_id="smbclient_adapter",
            toolchain="skg-host-toolchain",
            payload=precondition_payload(
                wicket_id="HO-26",
                label=f"Null/anonymous SMB session allowed on {ip}",
                domain="host",
                workload_id=f"host::{_node_key}",
                realized=True,
                detail="smbclient -L with -N (no password) returned share list",
            ),
            evidence_rank=2,
            source_kind="smbclient",
            pointer=f"smb://{ip}",
            confidence=0.85,
        ))

    # ── 2. Check for sensitive shares ────────────────────────────────────
    sensitive_found = [s for s in share_names if s.lower() in _SENSITIVE_SHARES]
    if sensitive_found:
        events.append(envelope(
            event_type="obs.attack.precondition",
            source_id="smbclient_adapter",
            toolchain="skg-ad-lateral-toolchain",
            payload=precondition_payload(
                wicket_id="AD-04",
                label=f"Sensitive share(s) accessible on {ip}: {', '.join(sensitive_found)}",
                domain="ad_lateral",
                workload_id=f"host::{_node_key}",
                realized=True,
                detail=f"Shares: {sensitive_found}",
            ),
            evidence_rank=2,
            source_kind="smbclient",
            pointer=f"smb://{ip}/{sensitive_found[0]}",
            confidence=0.88,
        ))

    # ── 3. Try to list interesting files in each accessible share ─────────
    interesting_files: list[str] = []
    for share in shares:
        sname = share["name"]
        if sname.lower() in ("ipc$",):
            continue
        files = _list_share_files(ip, sname, username, password)
        for f in files:
            if _INTERESTING_EXTS.search(f):
                interesting_files.append(f"\\\\{ip}\\{sname}\\{f}")

    if interesting_files:
        events.append(envelope(
            event_type="obs.attack.precondition",
            source_id="smbclient_adapter",
            toolchain="skg-host-toolchain",
            payload=precondition_payload(
                wicket_id="HO-27",
                label=f"Interesting files accessible on {ip}",
                domain="host",
                workload_id=f"host::{_node_key}",
                realized=True,
                detail=f"Files: {', '.join(interesting_files[:5])}",
            ),
            evidence_rank=2,
            source_kind="smbclient",
            pointer=interesting_files[0],
            confidence=0.80,
        ))

    # ── Write NDJSON ──────────────────────────────────────────────────────
    import json
    if events:
        ev_file = _out_dir / f"smbclient_{ip.replace('.', '_')}_{run_id[:8]}.ndjson"
        ev_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        _ingest(str(ev_file), run_id, result)
        result["events_file"] = str(ev_file)

    result["success"] = True
    result["events"]  = len(events)
    result["shares"]  = share_names
    return result


def _list_shares(ip: str, username: str, password: str) -> list[dict] | None:
    """Run smbclient -L and return list of {name, type, comment} dicts."""
    if username:
        cmd = ["smbclient", "-L", f"//{ip}", "-U", f"{username}%{password}"]
    else:
        cmd = ["smbclient", "-L", f"//{ip}", "-N"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return _parse_share_list(proc.stdout + proc.stderr)
    except FileNotFoundError:
        return None
    except Exception:
        return []


def _parse_share_list(output: str) -> list[dict]:
    shares: list[dict] = []
    in_shares = False
    for line in output.splitlines():
        if re.match(r"\s+Sharename\s+Type\s+Comment", line, re.IGNORECASE):
            in_shares = True
            continue
        if in_shares:
            m = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)", line, re.IGNORECASE)
            if m:
                shares.append({"name": m.group(1), "type": m.group(2), "comment": m.group(3).strip()})
            elif line.strip() == "" or re.match(r"\s+-+", line):
                if shares:
                    in_shares = False
    return shares


def _list_share_files(ip: str, share: str, username: str, password: str) -> list[str]:
    """Return filenames found at the root of the share."""
    if username:
        cmd = ["smbclient", f"//{ip}/{share}", "-U", f"{username}%{password}",
               "-c", "ls"]
    else:
        cmd = ["smbclient", f"//{ip}/{share}", "-N", "-c", "ls"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        files = []
        for line in proc.stdout.splitlines():
            m = re.match(r"\s+(\S+)\s+[ADHRSI]+\s+\d+", line)
            if m:
                name = m.group(1)
                if name not in (".", ".."):
                    files.append(name)
        return files
    except Exception:
        return []


def _ingest(ev_file: str, run_id: str, result: dict) -> None:
    try:
        from skg.kernel.engine import SKGKernel
        kernel = SKGKernel()
        kernel.ingest_events_file(ev_file)
        result["ingested"] = True
    except Exception:
        pass
