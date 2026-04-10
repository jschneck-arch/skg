"""
theharvester.py
===============
OSINT reconnaissance via theHarvester (or pure-Python fallback).

Discovers:
  - Subdomains and hostnames associated with the target domain
  - Email addresses (for spear-phishing surface mapping)
  - Additional IP ranges from certificate transparency

Emits:
  HO-25: discovered service versions / infrastructure detail
  WB-01: web service reachable (newly discovered hosts with HTTP)
  AD-01: domain user discovered (from email addresses → username hints)

Pure-Python fallback via crt.sh certificate transparency API
works without any external binary.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("skg.gravity.adapter.theharvester")

INSTRUMENT_NAME = "theharvester"

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ip_to_domain(ip: str) -> str | None:
    """Attempt reverse DNS lookup to get a domain for the IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _domain_root(hostname: str) -> str:
    """Extract root domain from hostname: 'sub.example.com' → 'example.com'"""
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _crtsh_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh certificate transparency for subdomains.
    Returns list of discovered hostnames.
    """
    import urllib.request
    import urllib.error

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SKG-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        seen: set[str] = set()
        hosts: list[str] = []
        for entry in data:
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.")
                if name and "." in name and name not in seen:
                    seen.add(name)
                    hosts.append(name)
        return hosts[:200]
    except Exception as exc:
        log.debug(f"[crtsh] {domain}: {exc}")
        return []


def _resolve_hosts(hostnames: list[str]) -> list[dict]:
    """Resolve hostnames to IPs, return [{hostname, ip}] for reachable ones."""
    import concurrent.futures

    results: list[dict] = []

    def _resolve(hostname: str) -> dict | None:
        try:
            ip = socket.gethostbyname(hostname)
            return {"hostname": hostname, "ip": ip}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        for hit in pool.map(_resolve, hostnames[:100]):
            if hit:
                results.append(hit)
    return results


def _run_theharvester_binary(domain: str, out_dir: Path) -> list[str]:
    """Try theHarvester binary, return list of discovered hostnames/emails."""
    import subprocess
    import shutil

    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    if not binary:
        return []

    out_file = out_dir / f"theharvester_{domain.replace('.','_')}.json"
    cmd = [binary, "-d", domain, "-b", "all", "-f", str(out_file)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception:
        return []

    discovered: list[str] = []
    if out_file.with_suffix(".json").exists():
        try:
            data = json.loads(out_file.with_suffix(".json").read_text())
            discovered.extend(data.get("hosts", []))
            discovered.extend(data.get("emails", []))
        except Exception:
            pass
    return discovered


def _emit_host(hostname: str, ip: str, workload_id: str) -> dict:
    from skg.sensors import envelope, precondition_payload
    return envelope(
        event_type="obs.attack.precondition",
        source_id="skg.gravity.theharvester",
        toolchain="host",
        payload=precondition_payload(
            wicket_id="HO-25",
            label=f"OSINT host discovered: {hostname}",
            domain="host",
            workload_id=workload_id,
            realized=True,
            detail=f"crt.sh/harvester found {hostname} → {ip}",
        ),
        evidence_rank=3,
        source_kind="osint",
        confidence=0.70,
    )


def _emit_email(email: str, domain: str, workload_id: str) -> dict:
    from skg.sensors import envelope, precondition_payload
    # Extract username hint for AD domain (user@domain.com → AD-01 hint)
    user = email.split("@")[0] if "@" in email else email
    return envelope(
        event_type="obs.attack.precondition",
        source_id="skg.gravity.theharvester",
        toolchain="host",
        payload=precondition_payload(
            wicket_id="AD-01",
            label=f"email/username discovered: {user}",
            domain="host",
            workload_id=workload_id,
            realized=True,
            detail=f"OSINT found email: {email}",
        ),
        evidence_rank=3,
        source_kind="osint",
        confidence=0.65,
    )


def run(ip: str, target: dict, run_id: str, out_dir: Path,
        result: dict, *, authorized: bool = False, node_key: str = "",
        **kwargs) -> dict:
    """
    Run OSINT harvesting against the target domain.

    Does NOT require --authorized: this is passive OSINT from public sources.
    """
    out_path = Path(out_dir) if out_dir else Path("/tmp")
    out_path.mkdir(parents=True, exist_ok=True)

    workload_id = f"host::{node_key or ip}"

    # Get domain from target or via reverse DNS
    target_dict = target.get("target", target)
    domain = (
        target_dict.get("domain")
        or target_dict.get("hostname")
        or _ip_to_domain(ip)
    )
    if domain:
        domain = _domain_root(domain)

    if not domain:
        result["error"] = "Cannot determine domain for OSINT (no PTR record, no domain in target)"
        result["success"] = False
        return result

    log.info(f"[theharvester] domain={domain} ip={ip}")
    events: list[dict] = []

    # 1. Try theHarvester binary
    binary_results = _run_theharvester_binary(domain, out_path)
    emails = [r for r in binary_results if "@" in r]
    hosts_from_binary = [r for r in binary_results if "@" not in r]

    # 2. Always run crt.sh (free, no rate limit for casual queries)
    crt_hosts = _crtsh_subdomains(domain)

    all_hosts = list({*hosts_from_binary, *crt_hosts})

    # 3. Resolve hosts to IPs
    resolved = _resolve_hosts(all_hosts)

    for entry in resolved[:50]:
        events.append(_emit_host(entry["hostname"], entry["ip"], workload_id))

    for email in emails[:20]:
        events.append(_emit_email(email, domain, workload_id))

    if events:
        ev_file = out_path / f"gravity_osint_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
        with ev_file.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        result["events_file"] = str(ev_file)
        result["discovered_hosts"] = len(resolved)
        result["discovered_emails"] = len(emails)

    result["success"] = True
    result["unknowns_resolved"] = len(events)
    result["domain"] = domain
    return result
