"""
silver_recon adapter
====================
Mass recon via Silver (masscan + parallel nmap + vulners CVE lookup).
Wraps /tools/silver/ and maps its JSON output to SKG precondition events.

What it observes:
  HO-01  — host reachable (any open port found)
  HO-02  — SSH service present
  HO-20  — RDP present
  HO-04  — WinRM present
  HO-19  — SMB present
  WB-01  — HTTP/HTTPS service present
  WB-13  — CVE version match (software version has known public exploit)
  DP-01  — database port open (MySQL/MSSQL/PostgreSQL)
  HO-25  — confirmed exploitable via searchsploit/vulners (RCE class)

Requires: masscan, nmap, (optional) vulners API key in VULNERS_API_KEY env.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

# Locate the silver tool relative to this adapter
_ADAPTER_DIR = Path(__file__).resolve().parent
_TOOLS_DIR   = _ADAPTER_DIR.parent.parent / "tools" / "silver"
_SILVER_PY   = _TOOLS_DIR / "silver.py"

# Port → (wicket_id, domain, label) mapping
_PORT_WICKETS: dict[str, tuple[str, str, str]] = {
    "22":   ("HO-02", "host", "ssh_service_exposed"),
    "2222": ("HO-02", "host", "ssh_service_exposed"),
    "3389": ("HO-20", "host", "rdp_service_exposed"),
    "5985": ("HO-04", "host", "winrm_http"),
    "5986": ("HO-04", "host", "winrm_https"),
    "139":  ("HO-19", "host", "smb_service_exposed"),
    "445":  ("HO-19", "host", "smb_service_exposed"),
    "80":   ("WB-01", "web",  "web_reachable"),
    "443":  ("WB-01", "web",  "web_reachable"),
    "8080": ("WB-01", "web",  "web_reachable"),
    "8443": ("WB-01", "web",  "web_reachable"),
    "8000": ("WB-01", "web",  "web_reachable"),
    "3306": ("DP-01", "data", "mysql_accessible"),
    "5432": ("DP-01", "data", "postgresql_accessible"),
    "1433": ("DP-01", "data", "mssql_accessible"),
}


def _ev(
    wicket_id: str,
    status: str,
    workload_id: str,
    domain: str,
    label: str,
    detail: str,
    confidence: float,
    target_ip: str,
) -> dict[str, Any]:
    """Build a compliant obs.attack.precondition event."""
    try:
        from skg.sensors.event_builder import make_precondition_event
        from skg.identity.workload import canonical_workload_id
        return make_precondition_event(
            wicket_id=wicket_id,
            status=status,
            workload_id=canonical_workload_id(workload_id, domain=domain),
            source_id="silver_recon_adapter",
            toolchain="skg-domains-redteam",
            target_ip=target_ip,
            domain=domain,
            label=label,
            detail=detail,
            evidence_rank=4,
            source_kind="silver_recon",
            confidence=confidence,
        )
    except ImportError:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "type": "obs.attack.precondition",
            "id": str(uuid.uuid4()),
            "ts": now,
            "source": {"source_id": "silver_recon_adapter", "toolchain": "skg-domains-redteam"},
            "payload": {
                "wicket_id": wicket_id,
                "workload_id": workload_id,
                "domain": domain,
                "status": status,
                "label": label,
                "detail": detail,
                "target_ip": target_ip,
            },
            "provenance": {
                "evidence_rank": 4,
                "evidence": {"source_kind": "silver_recon", "confidence": confidence},
            },
        }


def run_silver_recon(
    targets: list[str],
    out_dir: Path,
    *,
    rate: int = 5000,
    quick: bool = True,
    threads: int | None = None,
) -> list[dict[str, Any]]:
    """
    Run Silver mass scan against targets list (IPs, CIDRs, hostnames).
    Returns list of SKG precondition events.

    Parameters
    ----------
    targets : list[str]
        IP addresses, CIDR ranges, or hostnames to scan.
    out_dir : Path
        Working directory for Silver JSON output and event files.
    rate : int
        masscan packets per second (default 5000 — safe for lab networks).
    quick : bool
        Use top ~1000 ports only (default True for speed).
    threads : int | None
        Nmap parallelism (None = auto from CPU count).
    """
    if not targets:
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    result_file = out_dir / f"silver_result_{uuid.uuid4().hex[:8]}.json"

    # Build silver.py command
    if not _SILVER_PY.exists():
        return []

    # Add silver's own directory to path so its imports work
    _silver_dir = str(_TOOLS_DIR)
    if _silver_dir not in sys.path:
        sys.path.insert(0, _silver_dir)

    cmd = [
        sys.executable, str(_SILVER_PY),
        ",".join(targets),
        "-o", str(result_file),
        "-r", str(rate),
    ]
    if quick:
        cmd.append("--quick")
    if threads:
        cmd += ["-t", str(threads)]

    try:
        subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            env={**os.environ, "PYTHONPATH": _silver_dir}
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    if not result_file.exists():
        return []

    try:
        silver_data: dict[str, Any] = json.loads(result_file.read_text())
    except Exception:
        return []

    return map_silver_result_to_events(silver_data)


def map_silver_result_to_events(silver_data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Convert Silver JSON output to SKG precondition events.

    Silver JSON shape:
    {
      "192.168.1.5": {
        "ports": {
          "22": {"software": "OpenSSH", "version": "7.4", "vuln": false, ...},
          "80": {"software": "nginx", "version": "1.14", "vuln": true, ...}
        }
      }
    }
    """
    events: list[dict[str, Any]] = []

    for ip, host_data in silver_data.items():
        if not isinstance(host_data, dict):
            continue
        ports = host_data.get("ports") or {}
        if not ports:
            continue

        # HO-01: host is up (has at least one open port)
        events.append(_ev(
            "HO-01", "realized",
            workload_id=f"host::{ip}",
            domain="host",
            label="host_reachable",
            detail=f"Silver: {len(ports)} open ports on {ip}",
            confidence=0.95,
            target_ip=ip,
        ))

        for port_str, port_data in ports.items():
            if not isinstance(port_data, dict):
                continue

            software = str(port_data.get("software") or "").strip()
            version  = str(port_data.get("version")  or "").strip()
            is_vuln  = bool(port_data.get("vuln", False))

            # Port-specific service wickets
            if port_str in _PORT_WICKETS:
                wid, domain, label = _PORT_WICKETS[port_str]
                wid_domain = "web" if domain == "web" else domain
                detail = f"Port {port_str} open"
                if software:
                    detail += f" — {software} {version}".rstrip()
                events.append(_ev(
                    wid, "realized",
                    workload_id=f"{wid_domain}::{ip}",
                    domain=wid_domain,
                    label=label,
                    detail=detail,
                    confidence=0.92,
                    target_ip=ip,
                ))

            # CVE/exploit wicket when vulners flagged it
            if is_vuln and software:
                # Classify exploit severity by service
                _web_services = {"apache", "nginx", "tomcat", "iis", "lighttpd"}
                _db_services  = {"mysql", "postgres", "mariadb", "mssql", "mongo"}
                svc_lower = software.lower()
                if any(s in svc_lower for s in _web_services):
                    v_wid, v_domain = "WB-13", "web"
                elif any(s in svc_lower for s in _db_services):
                    v_wid, v_domain = "DP-06", "data"
                else:
                    v_wid, v_domain = "HO-25", "host"

                events.append(_ev(
                    v_wid, "realized",
                    workload_id=f"{v_domain}::{ip}",
                    domain=v_domain,
                    label="cve_version_match",
                    detail=f"vulners: {software} {version} on port {port_str} has known CVEs",
                    confidence=0.80,
                    target_ip=ip,
                ))

    return events
