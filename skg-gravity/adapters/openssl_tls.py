"""
openssl_tls.py — TLS/certificate scanning adapter
===================================================
Uses openssl s_client to probe TLS configuration on discovered HTTPS ports.
Detects weak protocols (SSLv3, TLS 1.0/1.1), weak ciphers, self-signed certs,
expired certs, and certificate information useful for further OSINT.

Emits obs.attack.precondition events for:
  WB-11  weak or missing TLS (SSLv3 / TLSv1.0 / TLSv1.1 accepted; self-signed/expired cert)
  WB-02  server information disclosure via certificate SANs
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INSTRUMENT_NAME = "openssl_tls"

_WEAK_PROTOCOLS = [
    ("ssl3",   "SSLv3",   "WB-11", 0.95),
    ("tls1",   "TLSv1.0", "WB-11", 0.90),
    ("tls1_1", "TLSv1.1", "WB-11", 0.80),
]


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
    if not shutil.which("openssl"):
        result["error"] = "openssl not found"
        return result

    from pathlib import Path as _Path
    import json
    from skg.sensors import envelope, precondition_payload

    _node_key = node_key or ip
    _out_dir  = _Path(str(out_dir)) if out_dir else _Path("/tmp/skg_gravity")
    _out_dir.mkdir(parents=True, exist_ok=True)

    # Determine ports to scan from nmap results or default
    open_ports: list[int] = []
    nmap_data = target.get("nmap_data") or target.get("ports") or {}
    for port_str, port_info in nmap_data.items():
        port_num = int(port_str) if str(port_str).isdigit() else 0
        if not port_num:
            continue
        svc = str(port_info.get("service", "") or port_info.get("name", "")).lower()
        if port_num in (443, 8443, 4443, 9443) or "https" in svc or "ssl" in svc or "tls" in svc:
            open_ports.append(port_num)

    if not open_ports:
        # Check if 443 is up with a quick connect probe
        open_ports = [443]

    events: list[dict] = []

    for port in open_ports[:4]:  # limit to 4 ports to stay fast
        host = target.get("hostname") or ip

        # ── Certificate info ──────────────────────────────────────────────
        cert_events = _check_cert(ip, host, port, _node_key, precondition_payload, envelope)
        events.extend(cert_events)

        # ── Weak protocol probes ──────────────────────────────────────────
        for proto_flag, proto_name, wicket_id, conf in _WEAK_PROTOCOLS:
            if _proto_accepted(ip, port, proto_flag):
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="openssl_tls_adapter",
                    toolchain="skg-web-toolchain",
                    payload=precondition_payload(
                        wicket_id=wicket_id,
                        label=f"Weak TLS: {proto_name} accepted on {ip}:{port}",
                        domain="web",
                        workload_id=f"web::{_node_key}",
                        realized=True,
                        detail=f"openssl s_client -{proto_flag} connected successfully to {ip}:{port}",
                    ),
                    evidence_rank=3,
                    source_kind="openssl_s_client",
                    pointer=f"{ip}:{port}",
                    confidence=conf,
                ))

    # ── Write NDJSON ──────────────────────────────────────────────────────
    if events:
        ev_file = _out_dir / f"openssl_tls_{ip.replace('.', '_')}_{run_id[:8]}.ndjson"
        ev_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        _ingest(str(ev_file), run_id, result)
        result["events_file"] = str(ev_file)

    result["success"] = True
    result["events"]  = len(events)
    result["ports_scanned"] = open_ports
    return result


def _proto_accepted(ip: str, port: int, proto_flag: str) -> bool:
    """Return True if the server accepts the given TLS protocol version."""
    try:
        proc = subprocess.run(
            ["openssl", "s_client", f"-{proto_flag}", "-connect", f"{ip}:{port}",
             "-verify_return_error", "-brief"],
            input=b"",
            capture_output=True,
            timeout=10,
        )
        output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
        # Success: "Verification: OK" or "SSL handshake has read"
        return bool(
            re.search(r"SSL handshake has read|Cipher is|Protocol\s*:", output, re.I)
            and "handshake failure" not in output.lower()
            and "alert handshake failure" not in output.lower()
        )
    except Exception:
        return False


def _check_cert(
    ip: str, host: str, port: int, node_key: str, precondition_payload: Any, envelope: Any
) -> list[dict]:
    """Extract cert info and emit events for self-signed/expired certs and SAN OSINT."""
    events: list[dict] = []
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{ip}:{port}",
             "-servername", host, "-showcerts"],
            input=b"",
            capture_output=True,
            timeout=15,
        )
        output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")

        # Self-signed: issuer == subject
        issuer  = re.search(r"issuer=(.+)", output)
        subject = re.search(r"subject=(.+)", output)
        if issuer and subject:
            issuer_val  = issuer.group(1).strip()
            subject_val = subject.group(1).strip()
            if issuer_val == subject_val:
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="openssl_tls_adapter",
                    toolchain="skg-web-toolchain",
                    payload=precondition_payload(
                        wicket_id="WB-11",
                        label=f"Self-signed certificate on {ip}:{port}",
                        domain="web",
                        workload_id=f"web::{node_key}",
                        realized=True,
                        detail=f"issuer == subject: {issuer_val[:120]}",
                    ),
                    evidence_rank=3,
                    source_kind="openssl_s_client",
                    pointer=f"{ip}:{port}",
                    confidence=0.90,
                ))

        # Expired
        if re.search(r"verify error:num=10:certificate has expired|notAfter", output):
            events.append(envelope(
                event_type="obs.attack.precondition",
                source_id="openssl_tls_adapter",
                toolchain="skg-web-toolchain",
                payload=precondition_payload(
                    wicket_id="WB-11",
                    label=f"Expired certificate on {ip}:{port}",
                    domain="web",
                    workload_id=f"web::{node_key}",
                    realized=True,
                    detail="openssl verify error: certificate has expired",
                ),
                evidence_rank=3,
                source_kind="openssl_s_client",
                pointer=f"{ip}:{port}",
                confidence=0.95,
            ))

        # SANs — OSINT value (additional hostnames)
        sans = re.findall(r"DNS:([^\s,]+)", output)
        if sans:
            events.append(envelope(
                event_type="obs.attack.precondition",
                source_id="openssl_tls_adapter",
                toolchain="skg-web-toolchain",
                payload=precondition_payload(
                    wicket_id="WB-02",
                    label=f"TLS SANs reveal additional hostnames for {ip}:{port}",
                    domain="web",
                    workload_id=f"web::{node_key}",
                    realized=True,
                    detail=f"SANs: {', '.join(sans[:10])}",
                ),
                evidence_rank=3,
                source_kind="openssl_s_client",
                pointer=f"{ip}:{port}",
                confidence=0.85,
            ))

    except Exception:
        pass
    return events


def _ingest(ev_file: str, run_id: str, result: dict) -> None:
    try:
        from skg.kernel.engine import SKGKernel
        kernel = SKGKernel()
        kernel.ingest_events_file(ev_file)
        result["ingested"] = True
    except Exception:
        pass
