#!/usr/bin/env python3
"""
adapter: nmap_scan
==================
Parses nmap XML output (-oX) and emits obs.attack.precondition events
for host network reachability and service exposure wickets.

Can also run nmap directly if given a target and the nmap binary is available.

Evidence rank: 4 (network scan — weaker than runtime/build/config evidence
but the only source for network exposure facts)

Usage (parse existing XML):
  python parse.py --xml /tmp/scan.xml --out /tmp/events.ndjson \\
    --attack-path-id host_network_exploit_v1 --workload-id 192.168.1.50

Usage (run nmap and parse):
  python parse.py --target 192.168.1.0/24 --out /tmp/events.ndjson \\
    --attack-path-id host_ssh_initial_access_v1 --workload-id lab_net
"""

import argparse, json, re, subprocess, uuid, xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-host-toolchain"
SOURCE_ID = "adapter.nmap_scan"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Services that map to specific host wickets
SERVICE_WICKET_MAP = {
    "ssh":      ("HO-02", 22),
    "winrm":    ("HO-04", 5985),
    "ms-wbt-server": ("HO-20", 3389),  # RDP
    "microsoft-ds":  ("HO-19", 445),   # SMB
    "netbios-ssn":   ("HO-19", 139),
    "nfs":           ("HO-21", 2049),
}

# Metasploit module names for known vulnerable service patterns
# Used to annotate HO-25 with exploit context
EXPLOIT_HINTS = {
    "ms17-010":  "EternalBlue (MS17-010) — SMB",
    "bluekeep":  "BlueKeep (CVE-2019-0708) — RDP",
    "log4j":     "Log4Shell (CVE-2021-44228)",
    "heartbleed": "Heartbleed (CVE-2014-0160) — OpenSSL",
    "shellshock": "Shellshock (CVE-2014-6271) — Bash",
}


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, source_kind: str, pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         notes: str = "", attributes: dict = None):
    now = iso_now()
    payload = {
        "wicket_id": wicket_id,
        "status": status,
        "attack_path_id": attack_path_id,
        "run_id": run_id,
        "workload_id": workload_id,
        "observed_at": now,
        "notes": notes,
    }
    if attributes:
        payload["attributes"] = attributes

    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN, "version": get_version()},
        "payload": payload,
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": source_kind,
                "pointer": pointer,
                "collected_at": now,
                "confidence": confidence,
            },
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def run_nmap(target: str, ports: str = None, flags: str = None) -> tuple[Path, str]:
    """Run nmap against a target and return the XML output path."""
    out_xml = Path(f"/tmp/skg_nmap_{uuid.uuid4().hex[:8]}.xml")
    cmd = ["nmap", "-oX", str(out_xml), "-sV", "--version-intensity", "5"]
    if ports:
        cmd += ["-p", ports]
    if flags:
        cmd += flags.split()
    cmd.append(target)
    print(f"[*] Running: {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"nmap failed: {result.stderr[:200]}")
    return out_xml, str(out_xml)


def parse_nmap_xml(xml_path: Path) -> list[dict]:
    """Parse nmap XML output into a list of host dicts."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host_el in root.findall("host"):
        state = host_el.find("status")
        if state is None or state.get("state") != "up":
            continue

        # Get primary address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "unknown")

        # Hostname
        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        # OS detection
        os_el = host_el.find("os/osmatch")
        os_name = os_el.get("name", "") if os_el is not None else ""
        os_accuracy = int(os_el.get("accuracy", "0")) if os_el is not None else 0

        # Ports
        open_ports = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            svc_product = svc_el.get("product", "") if svc_el is not None else ""
            svc_version = svc_el.get("version", "") if svc_el is not None else ""
            svc_extra = svc_el.get("extrainfo", "") if svc_el is not None else ""

            # Script output (vuln scripts)
            scripts = {}
            for script_el in port_el.findall("script"):
                scripts[script_el.get("id", "")] = script_el.get("output", "")

            open_ports.append({
                "port": portid,
                "proto": proto,
                "service": svc_name,
                "product": svc_product,
                "version": svc_version,
                "extra": svc_extra,
                "scripts": scripts,
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_name,
            "os_accuracy": os_accuracy,
            "open_ports": open_ports,
        })

    return hosts


def process_host(host: dict, out_path: Path, attack_path_id: str,
                 run_id: str, workload_id: str, pointer: str):
    """Emit wicket observations for a single nmap host result."""
    ip = host["ip"]
    wid = workload_id or ip

    # HO-01: host reachable
    emit(out_path, "HO-01", "realized", 4, "nmap_scan", pointer, 0.85,
         attack_path_id, run_id, wid,
         f"Host {ip} responded to nmap scan (state: up).",
         {"ip": ip, "hostname": host.get("hostname", ""), "os": host.get("os", "")})

    seen_wickets = set()
    exploit_services = []

    for port_info in host["open_ports"]:
        port = port_info["port"]
        svc = port_info["service"].lower()
        product = port_info["product"]
        version = port_info["version"]
        scripts = port_info.get("scripts", {})

        # Check service-to-wicket mapping
        for svc_key, (wicket_id, expected_port) in SERVICE_WICKET_MAP.items():
            if svc_key in svc or port == expected_port:
                if wicket_id not in seen_wickets:
                    seen_wickets.add(wicket_id)
                    svc_desc = f"{product} {version}".strip() or svc
                    emit(out_path, wicket_id, "realized", 4, "nmap_scan", pointer, 0.85,
                         attack_path_id, run_id, wid,
                         f"{svc_key.upper()} service open on port {port}: {svc_desc}",
                         {"port": port, "service": svc, "product": product, "version": version})

        # HO-25: exploitable service version
        version_str = f"{product} {version} {port_info.get('extra', '')}".lower()
        for exploit_key, exploit_desc in EXPLOIT_HINTS.items():
            if exploit_key in version_str or any(exploit_key in s.lower() for s in scripts.values()):
                exploit_services.append({
                    "port": port,
                    "service": svc,
                    "product": product,
                    "version": version,
                    "exploit_hint": exploit_desc,
                })

        # Check script output for known vuln signatures
        for script_id, script_out in scripts.items():
            if "VULNERABLE" in script_out or "State: VULNERABLE" in script_out:
                exploit_services.append({
                    "port": port,
                    "service": svc,
                    "script": script_id,
                    "script_output_snippet": script_out[:200],
                })

    if exploit_services:
        emit(out_path, "HO-25", "realized", 4, "nmap_scan", pointer, 0.75,
             attack_path_id, run_id, wid,
             f"Nmap identified {len(exploit_services)} potentially exploitable service(s).",
             {"exploitable_services": exploit_services[:5]})
    else:
        emit(out_path, "HO-25", "unknown", 4, "nmap_scan", pointer, 0.4,
             attack_path_id, run_id, wid,
             "No exploitable service versions identified by nmap version detection or vuln scripts.",
             {"open_port_count": len(host["open_ports"])})


def main():
    ap = argparse.ArgumentParser(description="SKG nmap scan adapter")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--xml", help="Path to existing nmap XML output (-oX)")
    group.add_argument("--target", help="Target to scan (IP, CIDR, or hostname)")
    ap.add_argument("--ports", default=None, help="Port spec for nmap (e.g. '22,80,443,445')")
    ap.add_argument("--nmap-flags", default=None, help="Extra nmap flags (e.g. '--script vuln')")
    ap.add_argument("--out", required=True, help="Output NDJSON file (append)")
    ap.add_argument("--attack-path-id", default="host_network_exploit_v1")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--workload-id", default=None)
    args = ap.parse_args()

    rid = args.run_id or str(uuid.uuid4())
    out_path = Path(args.out).expanduser().resolve()

    if args.xml:
        xml_path = Path(args.xml)
        pointer = f"file://{xml_path.resolve()}"
    else:
        xml_path, pointer = run_nmap(args.target, args.ports, args.nmap_flags)

    print(f"[*] Parsing nmap XML: {xml_path}", flush=True)
    hosts = parse_nmap_xml(xml_path)
    print(f"[*] Found {len(hosts)} live host(s)", flush=True)

    for host in hosts:
        wid = args.workload_id or host["ip"]
        process_host(host, out_path, args.attack_path_id, rid, wid, pointer)
        print(f"    {host['ip']}: {len(host['open_ports'])} open ports", flush=True)

    print(f"[OK] Nmap ingestion complete → {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
