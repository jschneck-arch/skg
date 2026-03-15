"""
skg :: discovery.py

Network discovery and attack surface mapping.

Sweeps the local environment, identifies live hosts and services,
classifies targets by applicable toolchain domain, runs collection
against each, and produces a unified attack surface view.
"""

import argparse
import json
import socket
import subprocess
import uuid
import os
import sys
import time
import ipaddress
import glob
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Utility ──────────────────────────────────────────────────────────────

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd: list, timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


# ── Network detection ────────────────────────────────────────────────────

def detect_local_subnets() -> list:
    subnets = []
    output = run_cmd(["ip", "-4", "addr", "show"])
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            addr_cidr = parts[1]
            try:
                net = ipaddress.IPv4Network(addr_cidr, strict=False)
                if net.network_address == ipaddress.IPv4Address("127.0.0.0"):
                    continue
                subnets.append(str(net))
            except Exception:
                continue
    return subnets


def detect_docker_networks() -> list:
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
    containers = []
    output = run_cmd(["docker", "ps", "--format",
                      "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"])
    for line in output.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        cid, name, image, ports, status = parts[0], parts[1], parts[2], parts[3], parts[4]
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
    live = []
    net = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(net.hosts())

    if len(hosts) > 1024:
        print(f"  [!] Subnet {subnet} has {len(hosts)} hosts, limiting to first 1024")
        hosts = hosts[:1024]

    def check_host(ip):
        ip_str = str(ip)
        try:
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

SERVICE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5000: "http-alt", 5432: "postgres", 5900: "vnc", 5985: "winrm-http",
    5986: "winrm-https", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    9443: "https-alt", 27017: "mongodb",
    # IoT / Smart home
    1883: "mqtt",        # MQTT broker (cameras, sensors, home automation)
    8883: "mqtt-tls",    # MQTT over TLS
    5683: "coap",        # CoAP (constrained devices)
    1900: "upnp",        # UPnP (almost everything)
    5353: "mdns",        # mDNS/Bonjour (Apple, Chromecast, etc.)
    9100: "ipp",         # IPP printing
    631:  "ipp",         # CUPS/IPP
    554:  "rtsp",        # RTSP (IP cameras, streaming)
    8554: "rtsp-alt",
    1935: "rtmp",        # RTMP streaming
    49152: "upnp-alt",   # Dynamic UPnP
    # Samsung / Smart TV
    8001: "samsung-tv",  # Samsung SmartThings API
    8002: "samsung-tv-tls",
    55000: "samsung-tv-legacy",
    # PlayStation / gaming
    9295: "ps-remote",   # PS Remote Play
    9296: "ps-remote",
    3478: "stun",        # STUN/TURN for gaming
    3479: "stun",
    # Printers / NAS
    515:  "lpd",         # LPD printing
    9000: "http-alt",    # Synology/QNAP web UI
    # Android/ADB (debug bridge — critical finding if open)
    5555: "adb",
    # Apple
    7000: "airplay",     # AirPlay
    7100: "airplay",
    62078: "itunes-sync",
    # Roku
    8060: "roku-ecp",    # Roku External Control Protocol
    # Chromecast
    8008: "chromecast",
    8009: "chromecast-tls",
}

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
    # IoT
    "mqtt": ["iot_firmware"],
    "mqtt-tls": ["iot_firmware"],
    "coap": ["iot_firmware"],
    "upnp": ["iot_firmware"],
    "upnp-alt": ["iot_firmware"],
    "mdns": ["iot_firmware"],
    "rtsp": ["iot_firmware"],
    "rtsp-alt": ["iot_firmware"],
    "rtmp": ["iot_firmware"],
    "samsung-tv": ["iot_firmware", "web"],
    "samsung-tv-tls": ["iot_firmware", "web"],
    "samsung-tv-legacy": ["iot_firmware"],
    "ps-remote": ["iot_firmware"],
    "roku-ecp": ["iot_firmware", "web"],
    "chromecast": ["iot_firmware", "web"],
    "chromecast-tls": ["iot_firmware"],
    "adb": ["host", "iot_firmware"],  # ADB open = immediate compromise
    "airplay": ["iot_firmware"],
    "ipp": ["host"],
    "lpd": ["host"],
    "telnet": ["host", "iot_firmware"],
}


def scan_ports(ip: str, ports: list = None, timeout: float = 1.0) -> list:
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
                    if port in (80, 8080, 8000, 3000, 5000, 9090, 443, 8443, 9443):
                        req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
                        s.send(req)
                        banner = s.recv(256).decode(errors="replace")
                    else:
                        banner = s.recv(256).decode(errors="replace")
                except Exception:
                    pass
                finally:
                    s.close()
                return (port, SERVICE_PORTS.get(port, "unknown"), banner)
            s.close()
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(check_port, p): p for p in ports}
        for f in as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x[0])


# ── Target classification ────────────────────────────────────────────────

def _fingerprint_device(ip: str, ports: list) -> str:
    """
    Infer device type from open ports and banner grabs.

    Returns a string like "linux", "windows", "android", "ios",
    "samsung-tv", "ps5", "router", "printer", "camera", etc.

    Used to populate surface map OS field and to inform which
    toolchain domains are applicable.
    """
    port_set = {p for p, _, _ in ports}
    banners  = {p: b for p, _, b in ports if b}

    # Android Debug Bridge open = Android device in debug mode
    if 5555 in port_set:
        return "android-adb"

    # Samsung Smart TV
    if port_set & {8001, 8002, 55000}:
        return "samsung-tv"

    # PlayStation
    if port_set & {9295, 9296}:
        return "playstation"

    # Chromecast / Android TV
    if port_set & {8008, 8009}:
        return "chromecast"

    # Roku
    if 8060 in port_set:
        return "roku"

    # Apple AirPlay (iPhone/iPad/Mac/AppleTV)
    if port_set & {7000, 7100, 62078}:
        return "apple"

    # RTSP = IP camera / NVR
    if port_set & {554, 8554}:
        return "ipcamera"

    # MQTT broker = home automation hub (Home Assistant, etc.)
    if port_set & {1883, 8883}:
        return "iot-hub"

    # Printer
    if port_set & {515, 631, 9100}:
        return "printer"

    # Windows indicators
    if port_set & {135, 445, 3389}:
        banner_text = " ".join(banners.values()).lower()
        if "windows" in banner_text or "microsoft" in banner_text:
            return "windows"
        return "windows"

    # Router / gateway — typically has 80/443 admin + port 53
    if 53 in port_set and port_set & {80, 443}:
        return "router"

    # SSH-only Linux box
    if 22 in port_set and not port_set & {80, 443, 8080}:
        return "linux"

    # Generic web-only
    if port_set & {80, 443, 8080, 8443} and not port_set & {22, 445}:
        # Try to infer from banner
        for port in (80, 443, 8080):
            banner = banners.get(port, "").lower()
            if "openwrt" in banner or "lede" in banner:
                return "openwrt"
            if "dd-wrt" in banner:
                return "dd-wrt"
            if "ubnt" in banner or "ubiquiti" in banner:
                return "ubiquiti"
            if "mikrotik" in banner:
                return "mikrotik"
        return "linux"

    return "linux"


def classify_target(ip: str, services: list, os_guess: str = "unknown",
                    is_container: bool = False) -> dict:
    domains = set()
    applicable_paths = []

    for _, svc, _ in services:
        if svc in SERVICE_DOMAIN_MAP:
            domains.update(SERVICE_DOMAIN_MAP[svc])

    if is_container:
        domains.add("container_escape")

    catalogs = load_catalogs()
    for domain in domains:
        catalog = catalogs.get(domain, {})
        for ap_id in catalog.get("attack_paths", {}).keys():
            applicable_paths.append(ap_id)

    return {
        "ip": ip,
        "os": os_guess,
        "services": [{"port": p, "service": s, "banner": b} for p, s, b in services],
        "domains": sorted(domains),
        "applicable_attack_paths": applicable_paths,
    }


def load_catalogs() -> dict:
    catalogs = {}
    for catalog_file in glob.glob("/opt/skg/skg-*-toolchain/contracts/catalogs/*.json"):
        try:
            data = json.loads(Path(catalog_file).read_text())
            domain = data.get("domain", Path(catalog_file).stem)
            catalogs[domain] = data
        except Exception:
            continue
    return catalogs


# ── Event merge helpers ──────────────────────────────────────────────────

def _event_files_for_ip(ip: str, out_dir: Path) -> list[str]:
    patterns = [
        f"web_events_{ip}_*.ndjson",
        f"gravity_http_{ip}_*.ndjson",
        f"gravity_auth_{ip}_*.ndjson",
        f"gravity_events_{ip}_*.ndjson",
    ]
    files = []
    for pat in patterns:
        files.extend(glob.glob(str(out_dir / pat)))
    return sorted(set(files), key=lambda p: Path(p).stat().st_mtime)


def _load_latest_wicket_states_for_ip(ip: str, out_dir: Path) -> dict[str, str]:
    """
    Merge all relevant event streams for an IP. Latest event timestamp wins per wicket.
    """
    latest_ts: dict[str, str] = {}
    latest_state: dict[str, str] = {}

    for ef in _event_files_for_ip(ip, out_dir):
        try:
            with open(ef) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    event = json.loads(line)
                    payload = event.get("payload", {})
                    wid = payload.get("wicket_id")
                    status = payload.get("status")
                    if not wid or not status:
                        continue

                    workload_id = payload.get("workload_id", "")
                    if workload_id:
                        ip_from_workload = workload_id.split("::")[-1].split(":")[0] if "::" in workload_id else ""
                        if ip_from_workload and ip_from_workload != ip:
                            continue

                    ts = event.get("ts", "")
                    if wid in latest_ts and ts <= latest_ts[wid]:
                        continue

                    latest_ts[wid] = ts
                    latest_state[wid] = status
        except Exception:
            continue

    return latest_state


# ── Discovery main ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SKG discovery")
    parser.add_argument("--subnet", nargs="*", default=[])
    parser.add_argument("--auto", action="store_true")
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--out-dir", default="/var/lib/skg/discovery")
    args = parser.parse_args()

    out_path = Path(args.out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid.uuid4())
    deep = args.deep and not args.quick

    subnets = []
    if args.auto:
        subnets.extend(detect_local_subnets())
        subnets.extend(detect_docker_networks())
    if args.subnet:
        subnets.extend(args.subnet)

    subnets = sorted(set(subnets))
    if not subnets:
        print("[!] No subnets to scan")
        sys.exit(1)

    print(f"[SKG-DISCOVERY] Subnets: {', '.join(subnets)}")

    live_hosts = []
    for subnet in subnets:
        print(f"  Sweeping {subnet} ...")
        live_hosts.extend(ping_sweep(subnet))

    live_hosts = sorted(set(live_hosts), key=lambda x: ipaddress.IPv4Address(x))

    containers = enumerate_docker_containers() if args.docker or args.auto else []
    for c in containers:
        if c["ip"] and c["ip"] not in live_hosts:
            live_hosts.append(c["ip"])

    targets = []
    for ip in live_hosts:
        ports = scan_ports(ip)
        if not ports:
            continue

        is_container = any(c["ip"] == ip for c in containers)
        os_guess = _fingerprint_device(ip, ports)
        target = classify_target(ip, ports, os_guess=os_guess, is_container=is_container)
        targets.append(target)

        print(f"  {ip}")
        print(f"    OS: {os_guess}  Domains: {', '.join(target['domains'])}")
        print(f"    Services: {', '.join(str(p[0]) + '/' + p[1] for p in ports)}")

    total_paths = 0
    total_realized = 0
    total_blocked = 0
    total_unknown = 0

    surface = {
        "meta": {
            "run_id": run_id,
            "generated_at": iso_now(),
            "hosts_found": len(live_hosts),
            "targets_classified": len(targets),
            "docker_containers": len(containers),
            "mode": "deep" if deep else "quick",
        },
        "targets": [],
        "attack_surface_summary": {},
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

        for domain in target["domains"]:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

        total_paths += len(target["applicable_attack_paths"])

        merged_states = _load_latest_wicket_states_for_ip(target["ip"], out_path)
        t_entry["wicket_states"] = merged_states

        for status in merged_states.values():
            if status == "realized":
                total_realized += 1
            elif status == "blocked":
                total_blocked += 1
            else:
                total_unknown += 1

        if not deep and not merged_states:
            for _ in target["applicable_attack_paths"]:
                total_unknown += 1

        t_entry["attack_paths"] = target["applicable_attack_paths"]
        surface["targets"].append(t_entry)

    surface["attack_surface_summary"] = {
        "total_attack_paths": total_paths,
        "wickets_realized": total_realized,
        "wickets_blocked": total_blocked,
        "wickets_unknown": total_unknown,
        "domain_counts": domain_counts,
    }

    surface_file = out_path / f"surface_{run_id[:8]}.json"
    with open(surface_file, "w") as f:
        json.dump(surface, f, indent=2)

    print(f"\n  Surface map written to: {surface_file}")
    print(f"  Targets: {len(surface['targets'])}")
    print(f"  Paths:   {total_paths}")
    print(f"  Wickets: realized={total_realized} blocked={total_blocked} unknown={total_unknown}")

    print()
    for t in surface["targets"]:
        domains = ", ".join(t["domains"]) if t["domains"] else "none"
        print(f"  {t['ip']}")
        print(f"    domains: {domains}")
        print(f"    paths:   {len(t['attack_paths'])}")

        if t.get("wicket_states"):
            realized = sum(1 for v in t["wicket_states"].values() if v == "realized")
            blocked = sum(1 for v in t["wicket_states"].values() if v == "blocked")
            unknown = sum(1 for v in t["wicket_states"].values() if v == "unknown")
            print(f"    realized={realized} blocked={blocked} unknown={unknown}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
