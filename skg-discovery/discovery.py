"""
skg :: discovery.py

Network discovery and attack surface mapping.

Sweeps the local environment, identifies live hosts and services,
classifies targets by applicable toolchain domain, runs collection
against each, and produces a unified attack surface view.

This is SKG's "eyes" — it looks at everything reachable and tells
you what it knows, what it doesn't know, and what it can attack.

Usage:
  python discovery.py --subnet 192.168.254.0/24 --out-dir /var/lib/skg/discovery/
  python discovery.py --subnet 192.168.254.0/24 172.17.0.0/16 --out-dir /var/lib/skg/discovery/
  python discovery.py --auto --out-dir /var/lib/skg/discovery/

Modes:
  --auto        Detect all local subnets and scan them
  --subnet X    Scan specific subnet(s)
  --docker      Also enumerate local Docker containers
  --deep        Run full collector phases (slower, more findings)
  --quick       Service fingerprint only (fast, maps the surface)
"""

import argparse
import json
import socket
import struct
import subprocess
import uuid
import re
import os
import sys
import time
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Utility ──────────────────────────────────────────────────────────────

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd: list, timeout: int = 30) -> str:
    """Run a command and return stdout, or empty string on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


# ── Network detection ────────────────────────────────────────────────────

def detect_local_subnets() -> list:
    """Detect all local subnets from interface addresses."""
    subnets = []
    output = run_cmd(["ip", "-4", "addr", "show"])
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            addr_cidr = parts[1]  # e.g. 192.168.254.5/24
            try:
                net = ipaddress.IPv4Network(addr_cidr, strict=False)
                # Skip loopback
                if net.network_address == ipaddress.IPv4Address("127.0.0.0"):
                    continue
                subnets.append(str(net))
            except Exception:
                continue
    return subnets


def detect_docker_networks() -> list:
    """Detect Docker bridge networks."""
    networks = []
    output = run_cmd(["docker", "network", "ls", "--format", "{{.Name}}"])
    for name in output.strip().splitlines():
        name = name.strip()
        if not name:
            continue
        inspect = run_cmd(["docker", "network", "inspect", name])
        try:
            data = json.loads(inspect)
            if data and isinstance(data, list):
                config = data[0].get("IPAM", {}).get("Config", [])
                for c in config:
                    subnet = c.get("Subnet")
                    if subnet:
                        networks.append(subnet)
        except Exception:
            continue
    return networks


def enumerate_docker_containers() -> list:
    """Get running Docker containers with their IPs and exposed ports."""
    containers = []
    output = run_cmd(["docker", "ps", "--format",
                      "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"])
    for line in output.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        cid, name, image, ports, status = parts[0], parts[1], parts[2], parts[3], parts[4]

        # Get container IP
        ip_out = run_cmd(["docker", "inspect", "-f",
                          "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid])
        ip = ip_out.strip()

        containers.append({
            "id": cid,
            "name": name,
            "image": image,
            "ports": ports,
            "status": status,
            "ip": ip,
        })
    return containers


# ── Host discovery ───────────────────────────────────────────────────────

def ping_sweep(subnet: str, timeout: float = 0.5) -> list:
    """
    Fast ping sweep using raw socket or falling back to system ping.
    Returns list of live host IPs.
    """
    live = []
    net = ipaddress.IPv4Network(subnet, strict=False)

    # For large subnets, limit scope
    hosts = list(net.hosts())
    if len(hosts) > 1024:
        print(f"  [!] Subnet {subnet} has {len(hosts)} hosts, limiting to first 1024")
        hosts = hosts[:1024]

    def check_host(ip):
        ip_str = str(ip)
        try:
            # Try TCP connect to common ports as a ping alternative
            # (doesn't require root like ICMP)
            for port in (80, 443, 22, 445, 135, 3389, 8080):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    result = s.connect_ex((ip_str, port))
                    s.close()
                    if result == 0:
                        return ip_str
                except Exception:
                    continue

            # Fall back to ICMP via system ping
            r = subprocess.run(["ping", "-c", "1", "-W", "1", ip_str],
                               capture_output=True, timeout=2)
            if r.returncode == 0:
                return ip_str
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(check_host, ip): ip for ip in hosts}
        for f in as_completed(futures):
            result = f.result()
            if result:
                live.append(result)

    return sorted(live, key=lambda x: ipaddress.IPv4Address(x))


# ── Service detection ────────────────────────────────────────────────────

# Port → service mapping
SERVICE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5432: "postgres",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9090: "http-alt",
    9200: "elasticsearch",
    9443: "https-alt",
    27017: "mongodb",
}

# Service → toolchain domain mapping
SERVICE_DOMAIN_MAP = {
    "http": ["web"],
    "https": ["web"],
    "http-alt": ["web"],
    "https-alt": ["web"],
    "ssh": ["host"],
    "smb": ["host", "ad_lateral"],
    "msrpc": ["ad_lateral"],
    "netbios": ["ad_lateral"],
    "rdp": ["host"],
    "winrm-http": ["host", "ad_lateral"],
    "winrm-https": ["host", "ad_lateral"],
    "mysql": ["web", "host"],
    "postgres": ["web", "host"],
    "mssql": ["web", "host", "ad_lateral"],
    "ftp": ["host"],
    "redis": ["host"],
    "elasticsearch": ["host", "web"],
    "mongodb": ["host"],
    "vnc": ["host"],
    "nfs": ["host"],
}


def scan_ports(ip: str, ports: list = None, timeout: float = 1.0) -> list:
    """Scan TCP ports on a host. Returns list of (port, service_name, banner)."""
    if ports is None:
        ports = list(SERVICE_PORTS.keys())

    open_ports = []

    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                banner = ""
                try:
                    # Try to grab a banner
                    if port in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090):
                        # HTTP banner grab
                        if port in (443, 8443, 9443):
                            import ssl
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            s = ctx.wrap_socket(s, server_hostname=ip)
                        s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                        banner = s.recv(1024).decode("utf-8", errors="replace")
                    else:
                        s.settimeout(2)
                        s.sendall(b"\r\n")
                        banner = s.recv(1024).decode("utf-8", errors="replace")
                except Exception:
                    pass
                s.close()
                svc = SERVICE_PORTS.get(port, "unknown")
                return (port, svc, banner.strip()[:200])
            s.close()
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(check_port, p): p for p in ports}
        for f in as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x[0])


def extract_http_info(banner: str) -> dict:
    """Extract server info from HTTP banner."""
    info = {}
    for line in banner.splitlines():
        lower = line.lower()
        if lower.startswith("server:"):
            info["server"] = line.split(":", 1)[1].strip()
        elif lower.startswith("x-powered-by:"):
            info["powered_by"] = line.split(":", 1)[1].strip()
        elif lower.startswith("location:"):
            info["redirect"] = line.split(":", 1)[1].strip()
    return info


# ── OS fingerprinting (lightweight) ─────────────────────────────────────

def guess_os(services: list, banners: dict) -> str:
    """Lightweight OS guess from open ports and banners."""
    ports = {s[0] for s in services}
    all_banners = " ".join(banners.values()).lower()

    # Windows indicators
    if ports & {135, 139, 445, 3389, 5985}:
        return "windows"
    if "microsoft" in all_banners or "iis" in all_banners:
        return "windows"

    # Linux indicators
    if 22 in ports and not (ports & {135, 445}):
        return "linux"
    if "apache" in all_banners or "nginx" in all_banners or "ubuntu" in all_banners:
        return "linux"

    if "freebsd" in all_banners:
        return "freebsd"

    return "unknown"


# ── Target classification ────────────────────────────────────────────────

def classify_target(ip: str, services: list, os_guess: str,
                    docker_containers: list) -> dict:
    """
    Classify a target: what toolchain domains apply, what attack paths
    are potentially relevant, what's known vs unknown.
    """
    domains = set()
    applicable_paths = []
    web_ports = []
    banners = {}

    for port, svc, banner in services:
        if svc in SERVICE_DOMAIN_MAP:
            domains.update(SERVICE_DOMAIN_MAP[svc])
        if svc in ("http", "https", "http-alt", "https-alt"):
            scheme = "https" if "https" in svc or port in (443, 8443, 9443) else "http"
            web_ports.append((port, scheme))
        if banner:
            banners[f"{port}/{svc}"] = banner

    # Check if this is a Docker host
    is_docker_host = False
    for c in docker_containers:
        if c["ip"] == ip:
            domains.add("container_escape")
            is_docker_host = True

    # Domain → applicable attack paths
    domain_paths = {
        "web": [
            "web_sqli_to_shell_v1", "web_sqli_data_theft_v1",
            "web_upload_to_shell_v1", "web_cmdi_to_shell_v1",
            "web_ssti_to_rce_v1", "web_path_traversal_cred_theft_v1",
            "web_default_creds_to_admin_v1", "web_ssrf_internal_access_v1",
            "web_source_disclosure_to_foothold_v1",
        ],
        "host": [
            # Will be populated when host toolchain is built
            "host_priv_esc_suid_v1", "host_priv_esc_kernel_v1",
            "host_cred_theft_v1",
        ],
        "ad_lateral": [
            "ad_kerberoast_v1", "ad_asrep_roast_v1",
            "ad_unconstrained_delegation_v1", "ad_constrained_delegation_v1",
            "ad_acl_abuse_v1", "ad_dcsync_v1",
        ],
        "container_escape": [
            "container_escape_privileged_v1", "container_escape_socket_v1",
            "container_escape_cap_v1",
        ],
    }

    for domain in domains:
        applicable_paths.extend(domain_paths.get(domain, []))

    return {
        "ip": ip,
        "os": os_guess,
        "services": [{"port": p, "service": s, "banner": b[:100]} for p, s, b in services],
        "web_ports": web_ports,
        "domains": sorted(domains),
        "applicable_attack_paths": applicable_paths,
        "is_docker_host": is_docker_host,
        "banners": banners,
    }


# ── Discovery engine ─────────────────────────────────────────────────────

def discover(subnets: list, out_dir: str, include_docker: bool = True,
             deep: bool = False, proxy: str = None):
    """
    Full network discovery and attack surface mapping.
    """
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid.uuid4())
    ts = iso_now()

    print(f"[SKG-DISCOVERY] Run:      {run_id}")
    print(f"[SKG-DISCOVERY] Time:     {ts}")
    print(f"[SKG-DISCOVERY] Subnets:  {', '.join(subnets)}")
    print(f"[SKG-DISCOVERY] Output:   {out_path}")
    print(f"[SKG-DISCOVERY] Mode:     {'deep' if deep else 'quick'}")
    print()

    # ── Phase A: Host discovery ──
    print("[Phase A] Host discovery...")
    all_live = []
    for subnet in subnets:
        print(f"  Sweeping {subnet}...")
        live = ping_sweep(subnet)
        print(f"  Found {len(live)} live hosts")
        all_live.extend(live)

    # Deduplicate
    all_live = sorted(set(all_live), key=lambda x: ipaddress.IPv4Address(x))
    print(f"  Total live hosts: {len(all_live)}")
    print()

    # ── Phase B: Docker enumeration ──
    docker_containers = []
    if include_docker:
        print("[Phase B] Docker enumeration...")
        docker_containers = enumerate_docker_containers()
        if docker_containers:
            print(f"  Found {len(docker_containers)} containers:")
            for c in docker_containers:
                print(f"    {c['name']} ({c['image']}) — {c['ip']} — {c['ports']}")
            # Add container IPs to scan list
            for c in docker_containers:
                if c["ip"] and c["ip"] not in all_live:
                    all_live.append(c["ip"])
        else:
            print("  No running containers found")
        print()

    # ── Phase C: Service detection ──
    print("[Phase C] Service detection...")
    targets = []
    for ip in all_live:
        print(f"  Scanning {ip}...")
        services = scan_ports(ip)
        if services:
            svc_str = ", ".join(f"{p}/{s}" for p, s, _ in services)
            print(f"    Open: {svc_str}")

            banners = {f"{p}/{s}": b for p, s, b in services if b}
            os_guess = guess_os(services, banners)
            target = classify_target(ip, services, os_guess, docker_containers)
            targets.append(target)

            print(f"    OS: {os_guess}  Domains: {', '.join(target['domains'])}")
        else:
            print(f"    No open ports (host may be filtered)")

    print(f"\n  Classified {len(targets)} targets")
    print()

    # ── Phase D: Web collection (if deep mode) ──
    web_events_files = []
    if deep:
        print("[Phase D] Deep web collection...")
        # Add the web_active collector's parent to path
        web_adapter_path = Path("/opt/skg/skg-web-toolchain/adapters/web_active")
        if web_adapter_path.exists():
            sys.path.insert(0, str(web_adapter_path))
            try:
                from collector import collect as web_collect

                for target in targets:
                    if "web" not in target["domains"]:
                        continue
                    for port, scheme in target["web_ports"]:
                        url = f"{scheme}://{target['ip']}:{port}"
                        events_file = out_path / f"web_events_{target['ip']}_{port}.ndjson"
                        print(f"  Collecting {url}...")
                        try:
                            web_collect(
                                target=url,
                                out_path=str(events_file),
                                attack_path_id="web_sqli_to_shell_v1",
                                proxy=proxy,
                                run_id=run_id,
                                workload_id=f"web::{target['ip']}:{port}",
                                timeout=8.0,
                            )
                            web_events_files.append(str(events_file))
                        except Exception as e:
                            print(f"    Error: {e}")
            except ImportError:
                print("  [!] Web collector not found at /opt/skg/skg-web-toolchain/")
        else:
            print("  [!] skg-web-toolchain not installed")
        print()

    # ── Build unified surface map ──
    print("[Phase E] Building attack surface map...")

    # Count wicket states across all targets
    total_realized = 0
    total_blocked = 0
    total_unknown = 0
    total_paths = 0

    surface = {
        "meta": {
            "run_id": run_id,
            "ts": ts,
            "subnets_scanned": subnets,
            "hosts_found": len(all_live),
            "targets_classified": len(targets),
            "docker_containers": len(docker_containers),
            "mode": "deep" if deep else "quick",
        },
        "targets": [],
        "attack_surface_summary": {},
        "domain_coverage": {},
        "gaps": [],
    }

    domain_counts = {}
    for target in targets:
        t_entry = {
            "ip": target["ip"],
            "os": target["os"],
            "services": target["services"],
            "domains": target["domains"],
            "attack_paths": [],
            "wicket_states": {},
        }

        # Count applicable attack paths
        for domain in target["domains"]:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

        total_paths += len(target["applicable_attack_paths"])

        # If we have events from deep scan, load wicket states
        for ef in web_events_files:
            if target["ip"] in ef:
                try:
                    with open(ef) as f:
                        for line in f:
                            event = json.loads(line.strip())
                            payload = event.get("payload", {})
                            wid = payload.get("wicket_id")
                            status = payload.get("status")
                            if wid and status:
                                t_entry["wicket_states"][wid] = status
                                if status == "realized":
                                    total_realized += 1
                                elif status == "blocked":
                                    total_blocked += 1
                                else:
                                    total_unknown += 1
                except Exception:
                    pass

        # For quick mode, everything applicable is unknown
        if not deep:
            for path in target["applicable_attack_paths"]:
                total_unknown += 1  # Approximate: 1 unknown per path

        t_entry["attack_paths"] = target["applicable_attack_paths"]
        surface["targets"].append(t_entry)

    # Summary
    surface["attack_surface_summary"] = {
        "total_attack_paths": total_paths,
        "wickets_realized": total_realized,
        "wickets_blocked": total_blocked,
        "wickets_unknown": total_unknown,
    }

    surface["domain_coverage"] = domain_counts

    # Identify gaps — things SKG can see but can't yet assess
    gaps = []
    for target in targets:
        for domain in target["domains"]:
            toolchain_path = Path(f"/opt/skg/skg-{domain.replace('_', '-')}-toolchain")
            if not toolchain_path.exists():
                gaps.append({
                    "type": "missing_toolchain",
                    "domain": domain,
                    "target": target["ip"],
                    "detail": f"No toolchain found at {toolchain_path}",
                })

        # Flag services with no domain mapping
        for svc in target["services"]:
            if svc["service"] == "unknown":
                gaps.append({
                    "type": "unclassified_service",
                    "target": target["ip"],
                    "port": svc["port"],
                    "detail": f"Port {svc['port']} open but service not classified",
                })

    surface["gaps"] = gaps

    # ── Write output ──
    surface_file = out_path / f"surface_{run_id[:8]}.json"
    with open(surface_file, "w") as f:
        json.dump(surface, f, indent=2)

    # ── Print report ──
    print()
    print("=" * 70)
    print("  SKG ATTACK SURFACE MAP")
    print("=" * 70)
    print()
    print(f"  Hosts discovered:    {len(all_live)}")
    print(f"  Targets classified:  {len(targets)}")
    print(f"  Docker containers:   {len(docker_containers)}")
    print(f"  Attack paths found:  {total_paths}")
    print()

    if domain_counts:
        print("  Domain coverage:")
        for domain, count in sorted(domain_counts.items()):
            print(f"    {domain:20s}  {count} targets")
        print()

    print("  Targets:")
    for t in surface["targets"]:
        svcs = ", ".join(f"{s['port']}/{s['service']}" for s in t["services"])
        domains = ", ".join(t["domains"]) if t["domains"] else "none"
        print(f"    {t['ip']:18s}  [{t['os']:8s}]  {svcs}")
        print(f"    {'':18s}  domains: {domains}")
        print(f"    {'':18s}  paths:   {len(t['attack_paths'])}")

        if t.get("wicket_states"):
            realized = sum(1 for v in t["wicket_states"].values() if v == "realized")
            blocked = sum(1 for v in t["wicket_states"].values() if v == "blocked")
            unknown = sum(1 for v in t["wicket_states"].values() if v == "unknown")
            print(f"    {'':18s}  wickets: {realized} realized, {blocked} blocked, {unknown} unknown")
        print()

    if gaps:
        print("  Gaps (what SKG can't yet assess):")
        for g in gaps[:20]:
            print(f"    [{g['type']}] {g.get('target', '')} — {g['detail']}")
        print()

    print(f"  Surface map written to: {surface_file}")
    print()

    return surface


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SKG Network Discovery — map the full attack surface")
    parser.add_argument("--subnet", nargs="*", default=None,
                        help="Subnet(s) to scan (e.g. 192.168.254.0/24)")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-detect all local subnets")
    parser.add_argument("--docker", action="store_true", default=True,
                        help="Enumerate Docker containers (default: true)")
    parser.add_argument("--no-docker", action="store_true",
                        help="Skip Docker enumeration")
    parser.add_argument("--deep", action="store_true",
                        help="Run full collection phases (slower)")
    parser.add_argument("--quick", action="store_true", default=True,
                        help="Service fingerprint only (default)")
    parser.add_argument("--proxy", default=None,
                        help="Proxy for web collection (socks5://...)")
    parser.add_argument("--out-dir", dest="out_dir",
                        default="/var/lib/skg/discovery",
                        help="Output directory")
    args = parser.parse_args()

    subnets = args.subnet or []

    if args.auto or not subnets:
        detected = detect_local_subnets()
        print(f"[SKG-DISCOVERY] Auto-detected subnets: {detected}")
        subnets = detected

    if not subnets:
        print("[!] No subnets to scan. Use --subnet or --auto.")
        sys.exit(1)

    include_docker = not args.no_docker
    deep = args.deep

    discover(
        subnets=subnets,
        out_dir=args.out_dir,
        include_docker=include_docker,
        deep=deep,
        proxy=args.proxy,
    )


if __name__ == "__main__":
    main()
