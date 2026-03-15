"""
adapters/firmware_probe/probe.py
=================================
IoT firmware probe adapter for the SKG firmware toolchain.

Collects firmware indicators from a live IoT device via the network
and emits IF-* wicket events. Does NOT require the firmware image —
it works against the device's exposed services, banner strings,
and HTTP/telnet endpoints.

For offline firmware image analysis, use binwalk + strings against
the extracted filesystem and pipe the findings through this adapter.

Evidence ranks:
  rank 1 — live network probe (banner grab, version string from HTTP/telnet)
  rank 2 — firmware image analysis (binwalk, string extraction, SBOM)
  rank 3 — service config read (from SSH if accessible)
  rank 5 — CVE lookup without installed-version confirmation

Tri-state semantics for IoT:
  REALIZED  — vulnerable component confirmed present
  BLOCKED   — component absent or patched version confirmed
  UNKNOWN   — could not determine (no response, no banner, no version)

Targets supported:
  - Any device with an HTTP/HTTPS admin interface
  - Telnet-exposed devices (Dropbear, BusyBox shell)
  - SSH-accessible embedded Linux (OpenWRT, LEDE, etc.)
  - mDNS/UPnP discoverable devices

Usage:
  python probe.py --host 192.168.1.1 --out events.ndjson
  python probe.py --host 192.168.1.1 --user admin --password admin --out events.ndjson
  python probe.py --firmware-image /path/to/firmware.bin --out events.ndjson
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-iot_firmware-toolchain"
SOURCE_ID = "adapter.firmware_probe"

# Known vulnerable version patterns
# (package, version_pattern_re, wicket_id, cve, description)
VULNERABLE_PATTERNS = [
    # BusyBox — buffer overflow / code injection families
    ("BusyBox",   r"BusyBox\s+v?(1\.[0-9]+\.[0-9]+)",   "IF-03",
     "CVE-2021-42374", "BusyBox heap buffer overflow in LZMA"),
    ("BusyBox",   r"BusyBox\s+v?(1\.[0-9]+\.[0-9]+)",   "IF-08",
     "CVE-2022-28391", "BusyBox shell code injection via env variables"),
    # Dropbear SSH — hardcoded credentials / RCE
    ("Dropbear",  r"dropbear[_\s/-]+(20[0-9]{2}\.[0-9]+|[0-9]+\.[0-9]+\.?[0-9]*)",
     "IF-05", "CVE-2020-36254", "Dropbear hardcoded credentials in embedded builds"),
    ("Dropbear",  r"dropbear[_\s/-]+(20[0-9]{2}\.[0-9]+|[0-9]+\.[0-9]+\.?[0-9]*)",
     "IF-09", "CVE-2023-48795", "Dropbear remote code execution via SSH prefix truncation"),
    # OpenSSL — arbitrary code execution in embedded builds
    ("OpenSSL",   r"OpenSSL\s+(1\.[0-1]\.[0-9a-z]+)",  "IF-06",
     "CVE-2022-0778", "OpenSSL infinite loop / denial of service"),
    # dnsmasq — heap overflow
    ("dnsmasq",   r"dnsmasq-?(2\.[0-7][0-9])",          "IF-07",
     "CVE-2020-25681", "dnsmasq heap-based buffer overflow (DNSpooq)"),
    # curl / libcurl — use-after-free
    ("curl",      r"curl\s+(7\.[0-9]+\.[0-9]+|8\.[0-1]\.[0-9]+)", "IF-10",
     "CVE-2023-38545", "curl heap buffer overflow (SOCKS5 proxy)"),
]

# Version thresholds: (package, vulnerable_below, wicket_id)
# BLOCKED if installed >= fixed_version
VULN_THRESHOLDS: dict[str, tuple[str, str]] = {
    "IF-03": ("1.36.0",  "busybox"),
    "IF-04": ("1.35.0",  "busybox"),   # critical composite
    "IF-05": ("2022.83", "dropbear"),
    "IF-06": ("1.1.1s",  "openssl"),
    "IF-07": ("2.81",    "dnsmasq"),
    "IF-08": ("1.35.0",  "busybox"),
    "IF-09": ("2023.81", "dropbear"),
    "IF-10": ("8.4.0",   "curl"),
    "IF-11": ("1.36.0",  "busybox"),   # arb code exec
    "IF-12": ("1.34.0",  "busybox"),   # insecure defaults
    "IF-13": ("1.35.0",  "busybox"),   # denial of service
    "IF-14": ("1.35.0",  "busybox"),   # integer overflow
    "IF-15": ("1.35.0",  "busybox"),   # path traversal
}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ev(wicket_id: str, status: str, rank: int, confidence: float,
        detail: str, workload_id: str, run_id: str,
        attack_path_id: str) -> dict:
    now = iso_now()
    return {
        "id":   str(uuid.uuid4()), "ts": now,
        "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN, "version": "1.0.0"},
        "payload": {
            "wicket_id": wicket_id, "status": status,
            "workload_id": workload_id, "detail": detail,
            "attack_path_id": attack_path_id, "run_id": run_id,
            "observed_at": now,
        },
        "provenance": {
            "evidence_rank": rank,
            "evidence": {
                "source_kind": "firmware_probe", "pointer": workload_id,
                "collected_at": now, "confidence": confidence,
            },
        },
    }


# ── Network probes ────────────────────────────────────────────────────────

def probe_tcp_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Connect and read initial banner bytes."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(2.0)
            try:
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                return ""
    except Exception:
        return ""


def probe_http(host: str, port: int = 80, path: str = "/",
               timeout: float = 5.0) -> tuple[int, str, str]:
    """HTTP probe. Returns (status_code, headers, body_snippet)."""
    try:
        import urllib.request
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "SKG-FirmwareProbe/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = str(dict(resp.headers))
            body    = resp.read(2048).decode("utf-8", errors="replace")
            return resp.status, headers, body
    except Exception as exc:
        return 0, "", str(exc)


def extract_versions_from_text(text: str) -> dict[str, str]:
    """Extract component version strings from banner/HTTP response text."""
    versions: dict[str, str] = {}
    patterns = {
        "busybox":  r"BusyBox\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
        "dropbear": r"[Dd]ropbear[_\s/-]+([0-9]{4}\.[0-9]+|[0-9]+\.[0-9]+\.?[0-9]*)",
        "openssl":  r"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9a-z]+)",
        "dnsmasq":  r"[Dd]nsmasq-?([0-9]+\.[0-9]+)",
        "curl":     r"curl/([0-9]+\.[0-9]+\.[0-9]+)",
        "linux":    r"Linux\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "openwrt":  r"OpenWrt\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "lede":     r"LEDE\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    }
    for name, pattern in patterns.items():
        m = re.search(pattern, text)
        if m:
            versions[name] = m.group(1)
    return versions


def _version_tuple(v: str) -> tuple:
    """Parse version string into comparable tuple."""
    # Handle date-based versions like 2022.83
    parts = re.split(r'[.\-_]', str(v))
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    return tuple(result)


def _is_vulnerable(installed: str, fixed_at: str) -> bool:
    """Return True if installed version is older than fixed_at."""
    try:
        return _version_tuple(installed) < _version_tuple(fixed_at)
    except Exception:
        return False


# ── Firmware image analysis ───────────────────────────────────────────────

def analyze_firmware_image(image_path: str) -> dict[str, str]:
    """
    Extract version strings from a firmware image using strings(1) and binwalk.
    Returns dict of {component: version}.
    """
    versions: dict[str, str] = {}
    img = Path(image_path)
    if not img.exists():
        return versions

    # Run strings on the binary
    try:
        result = subprocess.run(
            ["strings", str(img)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            found = extract_versions_from_text(result.stdout)
            versions.update(found)
    except Exception:
        pass

    # Try binwalk for filesystem extraction hints
    try:
        result = subprocess.run(
            ["binwalk", "--term", str(img)],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            found = extract_versions_from_text(result.stdout)
            versions.update(found)
    except Exception:
        pass

    return versions


# ── Main probe ────────────────────────────────────────────────────────────

def probe_device(
    host: str,
    user: str = "admin",
    password: str = "admin",
    port_ssh: int = 22,
    workload_id: str = None,
    run_id: str = None,
    attack_path_id: str = "iot_firmware_rce_v1",
) -> list[dict]:
    """
    Probe a live IoT device for firmware version indicators.
    Collects banners from common ports, HTTP admin interfaces,
    and SSH if accessible.
    """
    wl     = workload_id or f"iot::{host}"
    run_id = run_id or str(uuid.uuid4())[:8]
    events: list[dict] = []
    all_versions: dict[str, str] = {}

    # IF-01: Is device reachable?
    reachable = False
    for port in [80, 443, 22, 23, 8080, 8443]:
        banner = probe_tcp_banner(host, port, timeout=2.0)
        if banner:
            reachable = True
            found = extract_versions_from_text(banner)
            all_versions.update(found)
            events.append(_ev("IF-01", "realized", 1, 0.95,
                               f"Device responds on port {port}: "
                               f"{banner[:80]}",
                               wl, run_id, attack_path_id))
            break

    if not reachable:
        events.append(_ev("IF-01", "unknown", 4, 0.60,
                           "No response on common IoT ports",
                           wl, run_id, attack_path_id))
        return events

    # IF-02: Service exposed
    http_status, http_headers, http_body = probe_http(host, 80, timeout=5.0)
    if http_status > 0:
        found = extract_versions_from_text(http_body + http_headers)
        all_versions.update(found)
        events.append(_ev("IF-02", "realized", 1, 0.90,
                           f"HTTP service on port 80: status={http_status}",
                           wl, run_id, attack_path_id))
    else:
        # Try 8080
        http_status2, _, http_body2 = probe_http(host, 8080, timeout=5.0)
        if http_status2 > 0:
            found = extract_versions_from_text(http_body2)
            all_versions.update(found)
            events.append(_ev("IF-02", "realized", 1, 0.85,
                               f"HTTP service on port 8080: status={http_status2}",
                               wl, run_id, attack_path_id))
        else:
            events.append(_ev("IF-02", "unknown", 4, 0.50,
                               "No HTTP service detected on 80 or 8080",
                               wl, run_id, attack_path_id))

    # SSH probe for Dropbear version
    ssh_banner = probe_tcp_banner(host, port_ssh, timeout=3.0)
    if ssh_banner:
        found = extract_versions_from_text(ssh_banner)
        all_versions.update(found)

    # Try telnet (port 23) — common on embedded devices
    telnet_banner = probe_tcp_banner(host, 23, timeout=2.0)
    if telnet_banner:
        found = extract_versions_from_text(telnet_banner)
        all_versions.update(found)

    # Evaluate collected versions against vulnerability thresholds
    events.extend(evaluate_versions(all_versions, wl, run_id, attack_path_id,
                                    evidence_rank=1))

    return events


def evaluate_versions(
    versions: dict[str, str],
    workload_id: str,
    run_id: str,
    attack_path_id: str,
    evidence_rank: int = 2,
) -> list[dict]:
    """
    Evaluate collected version strings against known vulnerability thresholds.
    Returns IF-* wicket events.
    """
    events: list[dict] = []
    emitted: set[str] = set()

    for wicket_id, (fixed_version, pkg_name) in VULN_THRESHOLDS.items():
        installed = versions.get(pkg_name.lower())

        if installed is None:
            if wicket_id not in emitted:
                events.append(_ev(
                    wicket_id, "unknown", evidence_rank, 0.40,
                    f"{pkg_name} not found in collected banners",
                    workload_id, run_id, attack_path_id
                ))
                emitted.add(wicket_id)
            continue

        is_vuln = _is_vulnerable(installed, fixed_version)
        status  = "realized" if is_vuln else "blocked"
        detail  = (
            f"{pkg_name}=={installed} is {'VULNERABLE' if is_vuln else 'patched'} "
            f"(fix requires >={fixed_version})"
        )
        confidence = 0.85 if evidence_rank == 1 else 0.70

        if wicket_id not in emitted:
            events.append(_ev(wicket_id, status, evidence_rank, confidence,
                               detail, workload_id, run_id, attack_path_id))
            emitted.add(wicket_id)

    return events


def probe_from_image(
    image_path: str,
    workload_id: str = None,
    run_id: str = None,
    attack_path_id: str = "iot_firmware_rce_v1",
) -> list[dict]:
    """Analyze a firmware image file and emit IF-* events."""
    wl     = workload_id or f"iot::firmware::{Path(image_path).name}"
    run_id = run_id or str(uuid.uuid4())[:8]

    versions = analyze_firmware_image(image_path)
    events   = evaluate_versions(versions, wl, run_id, attack_path_id,
                                  evidence_rank=2)

    if not versions:
        events.append(_ev("IF-01", "unknown", 2, 0.30,
                           f"No version strings extracted from {image_path}",
                           wl, run_id, attack_path_id))

    return events


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="SKG IoT firmware probe adapter")
    p.add_argument("--host",           default=None, help="Target device IP")
    p.add_argument("--user",           default="admin")
    p.add_argument("--password",       default="admin")
    p.add_argument("--port-ssh",       type=int, default=22, dest="port_ssh")
    p.add_argument("--firmware-image", default=None, dest="firmware_image",
                   help="Path to firmware binary for offline analysis")
    p.add_argument("--out",            required=True)
    p.add_argument("--workload-id",    dest="workload_id", default=None)
    p.add_argument("--attack-path-id", dest="attack_path_id",
                   default="iot_firmware_rce_v1")
    p.add_argument("--run-id",         dest="run_id", default=None)
    a = p.parse_args()

    if a.firmware_image:
        events = probe_from_image(
            a.firmware_image, a.workload_id, a.run_id, a.attack_path_id
        )
    elif a.host:
        events = probe_device(
            a.host, a.user, a.password, a.port_ssh,
            a.workload_id, a.run_id, a.attack_path_id
        )
    else:
        p.print_help()
        return

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"  {len(events)} IF-* events: {r}R {b}B {u}U → {out}")


if __name__ == "__main__":
    main()


def probe_network_only(host: str, ports: list, workload_id: str,
                       run_id: str, attack_path_id: str) -> list:
    """
    Network-only probe for IoT targets without SSH access or firmware images.
    
    Attempts banner grabs and HTTP probes on known IoT ports.
    Returns IF-* events with lower confidence (evidence_rank=6, scanner-grade).
    
    Observes:
      IF-01: Known-vulnerable firmware version   (from HTTP headers, server strings)
      IF-02: Default credentials exposed          (HTTP 200 on /admin with no auth)
      IF-03: Telnet enabled                       (port 23 responds)
      IF-06: Insecure HTTP management interface   (port 80/8080/8008 responds)
      IF-11: Network-accessible admin interface   (management ports reachable)
    """
    import socket, http.client, urllib.request, urllib.error
    from datetime import datetime, timezone
    import uuid

    now = datetime.now(timezone.utc).isoformat()
    events = []

    def make_event(wicket_id: str, status: str, confidence: float, detail: str) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "ts": now,
            "type": "obs.attack.precondition",
            "source": {"source_id": "adapter.iot_firmware.network_probe", "toolchain": "skg-iot_firmware-toolchain"},
            "payload": {
                "wicket_id": wicket_id,
                "status": status,
                "workload_id": workload_id,
                "attack_path_id": attack_path_id,
                "run_id": run_id,
                "detail": detail,
            },
            "provenance": {
                "evidence_rank": 6,
                "evidence": {
                    "source_kind": "network_probe",
                    "pointer": host,
                    "collected_at": now,
                    "confidence": confidence,
                }
            }
        }

    # Probe each port
    for port in (ports or [80, 443, 8080, 8008, 23, 7000, 8001, 8002]):
        try:
            # TCP reachability
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            conn_result = sock.connect_ex((host, port))
            sock.close()

            if conn_result != 0:
                continue  # Port not reachable

            # Port 23 = Telnet enabled (IF-03)
            if port == 23:
                events.append(make_event("IF-03", "realized", 0.85,
                    f"Telnet port 23 open on {host}"))
                continue

            # HTTP ports — try to grab headers and server string
            if port in (80, 443, 8080, 8008, 8009, 8001, 8002, 7000, 8000):
                scheme = "https" if port == 443 else "http"
                try:
                    req = urllib.request.Request(
                        f"{scheme}://{host}:{port}/",
                        headers={"User-Agent": "SKG-IoT-Probe/1.0"},
                    )
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    resp = urllib.request.urlopen(req, timeout=4, context=ctx)
                    server = resp.headers.get("Server", "")
                    body_start = resp.read(512).decode("utf-8", errors="ignore")

                    # IF-06: HTTP management interface reachable
                    events.append(make_event("IF-06", "realized", 0.75,
                        f"HTTP management port {port} reachable on {host}: Server={server}"))

                    # IF-11: Network-accessible admin
                    events.append(make_event("IF-11", "realized", 0.70,
                        f"Network-accessible interface on {host}:{port}"))

                    # Check for version strings in server header
                    versions = extract_versions_from_text(server + " " + body_start)
                    if versions:
                        vuln_events = evaluate_versions(
                            versions, workload_id=workload_id,
                            run_id=run_id, attack_path_id=attack_path_id,
                            evidence_rank=6,
                        )
                        events.extend(vuln_events)

                    # IF-02: Default credentials — check /admin, /login with no auth
                    for admin_path in ["/admin", "/setup", "/config"]:
                        try:
                            admin_req = urllib.request.Request(
                                f"{scheme}://{host}:{port}{admin_path}",
                                headers={"User-Agent": "SKG-IoT-Probe/1.0"},
                            )
                            admin_resp = urllib.request.urlopen(admin_req, timeout=3, context=ctx)
                            if admin_resp.status == 200:
                                events.append(make_event("IF-02", "realized", 0.65,
                                    f"Admin interface accessible without auth: {admin_path}"))
                                break
                        except Exception:
                            pass

                except urllib.error.HTTPError as he:
                    # Port reachable, got an HTTP error — still means IF-11
                    events.append(make_event("IF-11", "realized", 0.60,
                        f"HTTP port {port} reachable on {host} (HTTP {he.code})"))
                except Exception:
                    pass
        except Exception:
            continue

    if not events:
        # No ports responded — report everything as unknown
        events.append(make_event("IF-01", "unknown", 0.0,
            f"No IoT ports reachable on {host} — firmware probe inconclusive"))

    return events

