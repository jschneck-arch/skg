"""
skg :: gravity_field.py

Gravity Field Engine — the operating principle of the substrate.

Gravity is not a scheduler. It is the field dynamics that gives
energy direction. Every sensor, adapter, and tool is an instrument
for introducing energy into the telemetry field. Gravity determines
which instrument to route to which region based on the entropy
gradient — not rules, not priority lists.

Physics:
  - Unknown wickets are high-entropy regions (superposition)
  - Observation collapses unknowns to realized or blocked (measurement)
  - Collapse is reversible — changing the instrument can re-emerge projections
  - Each instrument has observational reach (wavelength) — some regions
    are only visible to certain instruments
  - When an instrument fails to reduce entropy, gravity shifts to
    a different instrument rather than retrying
  - The system follows geodesics through the entropy landscape

Field energy: E = H(π | T) — Shannon entropy of projection given telemetry
  High E = many unknowns = strong gravitational pull
  Low E = mostly realized/blocked = weak pull
  E = 0 = fully determined = no pull

The gravity loop is continuous field dynamics:
  observation → energy change → entropy shift → gravity redirects → next observation

Usage:
  python gravity_field.py --auto --cycles 5
  python gravity_field.py --surface /var/lib/skg/discovery/surface_*.json
"""

import json
import sys
import os
import time
import uuid
import math
import glob
import re
import subprocess
from pathlib import Path

import sys
sys.path.insert(0, "/opt/skg")
from skg.forge.proposals import create_action
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict
from dataclasses import dataclass, field as dc_field

# Instrument paths
WEB_ADAPTER = Path("/opt/skg/skg-web-toolchain/adapters/web_active")
FEEDS_PATH = Path("/opt/skg/feeds")
DISCOVERY_DIR = Path("/var/lib/skg/discovery")
CVE_DIR = Path("/var/lib/skg/cve")
EVENTS_DIR = Path("/var/lib/skg/events")

if WEB_ADAPTER.exists():
    sys.path.insert(0, str(WEB_ADAPTER))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Instruments ──────────────────────────────────────────────────────────
# Each instrument has:
#   - name: identifier
#   - wavelength: what regions of state space it can observe
#   - cost: time/resource cost per observation
#   - reach: what wickets it can potentially resolve
#   - available: whether the instrument exists on this system

@dataclass
class Instrument:
    name: str
    description: str
    wavelength: list  # What kinds of unknowns it can resolve
    cost: float       # Relative cost (1.0 = baseline HTTP request)
    available: bool = False
    last_used_on: dict = dc_field(default_factory=dict)  # ip → timestamp
    entropy_history: dict = dc_field(default_factory=dict)  # ip → [entropy_before, entropy_after]

    def failed_to_reduce(self, ip: str) -> bool:
        """Did this instrument fail to reduce entropy on this target?"""
        history = self.entropy_history.get(ip, [])
        if len(history) >= 2:
            return history[-1] >= history[-2]  # Entropy didn't decrease
        return False


def detect_instruments() -> dict:
    """Detect which instruments are available on the system."""
    instruments = {}

    # HTTP collector — unauthenticated web scanning
    instruments["http_collector"] = Instrument(
        name="http_collector",
        description="Unauthenticated HTTP recon — headers, paths, forms, basic injection",
        wavelength=["WB-01", "WB-02", "WB-03", "WB-04", "WB-05", "WB-06",
                     "WB-09", "WB-11", "WB-12", "WB-17", "WB-18", "WB-19",
                     "WB-22", "WB-24"],
        cost=1.0,
        available=(WEB_ADAPTER / "collector.py").exists(),
    )

    # Authenticated scanner — post-auth surface with CSRF handling
    instruments["auth_scanner"] = Instrument(
        name="auth_scanner",
        description="Authenticated scanning — CSRF-aware login, post-auth injection testing",
        wavelength=["WB-06", "WB-07", "WB-08", "WB-09", "WB-10", "WB-11",
                     "WB-12", "WB-13", "WB-14", "WB-15", "WB-22"],
        cost=3.0,
        available=(WEB_ADAPTER / "auth_scanner.py").exists(),
    )

    # NVD feed — CVE intelligence for discovered services
    instruments["nvd_feed"] = Instrument(
        name="nvd_feed",
        description="NVD CVE lookup — maps service versions to known vulnerabilities",
        wavelength=["CVE-*", "WB-20"],  # CVE wickets + db privilege indicators
        cost=2.0,
        available=(FEEDS_PATH / "nvd_ingester.py").exists() and bool(os.environ.get("NIST_NVD_API_KEY")),
    )

    # Metasploit — exploitation framework
    msf_available = bool(subprocess.run(
        ["which", "msfconsole"], capture_output=True).returncode == 0)
    instruments["metasploit"] = Instrument(
        name="metasploit",
        description="Metasploit auxiliary/exploit modules — can bypass app-layer defenses",
        wavelength=["WB-09", "WB-10", "WB-14", "WB-20", "WB-21",
                     "CE-*", "HO-*", "AD-*"],
        cost=5.0,
        available=msf_available,
    )

    # Tshark/pcap — network-layer observation
    tshark_available = bool(subprocess.run(
        ["which", "tshark"], capture_output=True).returncode == 0)
    instruments["pcap"] = Instrument(
        name="pcap",
        description="Packet capture — observes interactions from the wire, bypasses app-layer opacity",
        wavelength=["WB-09", "WB-15", "WB-16", "WB-18",
                     "HO-*", "AD-*"],
        cost=2.0,
        available=tshark_available,
    )

    # SSH sensor — direct host access
    instruments["ssh_sensor"] = Instrument(
        name="ssh_sensor",
        description="SSH remote enumeration — kernel, SUID, sudo, creds, services",
        wavelength=["HO-*", "CE-*"],
        cost=2.0,
        available=Path("/opt/skg/skg/sensors/ssh_sensor.py").exists(),
    )

    # Nmap — network scanner
    nmap_available = bool(subprocess.run(
        ["which", "nmap"], capture_output=True).returncode == 0)
    instruments["nmap"] = Instrument(
        name="nmap",
        description="Network scanner — service detection, version fingerprinting, NSE scripts",
        wavelength=["WB-01", "WB-02", "WB-17", "HO-*"],
        cost=3.0,
        available=nmap_available,
    )

    # BloodHound — AD domain enumeration via BloodHound CE REST API or Neo4j
    # Wavelength: all AD lateral wickets (kerberoastable, delegation, ACLs, etc.)
    # Availability: requires BH CE running on localhost:8080 or Neo4j on 7687
    bh_url = os.environ.get("BH_URL", "http://localhost:8080")
    bh_user = os.environ.get("BH_USERNAME", "admin")
    bh_pass = os.environ.get("BH_PASSWORD", "")
    neo4j_pass = os.environ.get("NEO4J_PASSWORD", "")
    bh_available = bool(bh_pass or neo4j_pass)
    if bh_available:
        # Quick reachability check — don't block startup if BH is down
        try:
            import urllib.request
            urllib.request.urlopen(bh_url, timeout=2)
        except Exception:
            bh_available = False
    instruments["bloodhound"] = Instrument(
        name="bloodhound",
        description="BloodHound CE — AD object graph: kerberoastable, ACLs, delegation, stale DAs",
        wavelength=["AD-01", "AD-02", "AD-03", "AD-04", "AD-05",
                     "AD-06", "AD-07", "AD-08", "AD-09", "AD-10",
                     "AD-11", "AD-12", "AD-13", "AD-14", "AD-15",
                     "AD-16", "AD-17", "AD-18", "AD-19", "AD-20",
                     "AD-21", "AD-22", "AD-23", "AD-24", "AD-25"],
        cost=4.0,
        available=bh_available,
    )

    # Data pipeline profiler — connects to databases and emits DP-* wicket events
    # Wavelength: all DP-01..DP-15 wickets
    # Availability: requires SQLAlchemy and at least one configured data source
    data_profiler_path = Path("/opt/skg/skg-data-toolchain/adapters/db_profiler/profile.py")
    data_sources_configured = bool(os.environ.get("SKG_DATA_SOURCES") or
                                    Path("/etc/skg/data_sources.yaml").exists())
    try:
        import importlib.util
        spec = importlib.util.find_spec("sqlalchemy")
        sqlalchemy_available = spec is not None
    except Exception:
        sqlalchemy_available = False
    instruments["data_profiler"] = Instrument(
        name="data_profiler",
        description="DB profiler — schema, completeness, freshness, drift, integrity for data pipelines",
        wavelength=["DP-01", "DP-02", "DP-03", "DP-04", "DP-05",
                     "DP-06", "DP-07", "DP-08", "DP-09", "DP-10",
                     "DP-11", "DP-12", "DP-13", "DP-14", "DP-15"],
        cost=2.0,
        available=data_profiler_path.exists() and (sqlalchemy_available or True),
    )

    # Binary analysis — checksec, rabin2, radare2, ROPgadget, pwndbg
    # Directed toward BA-* wickets when binary integrity unknowns are high-entropy
    # Available when at least one analysis tool is present
    binary_tools = ["checksec", "rabin2", "r2", "ROPgadget", "ltrace"]
    binary_available = any(
        subprocess.run(["which", t], capture_output=True).returncode == 0
        for t in binary_tools
    )

    # System auditor — filesystem, process, and log integrity via SSH
    sysaudit_path = Path("/opt/skg/skg-host-toolchain/adapters/sysaudit/audit.py")
    instruments["sysaudit"] = Instrument(
        name="sysaudit",
        description="System integrity audit — filesystem hashes, process manifest, log integrity",
        wavelength=[
            "FI-01", "FI-02", "FI-03", "FI-04", "FI-05",
            "FI-06", "FI-07", "FI-08",
            "PI-01", "PI-02", "PI-03", "PI-04", "PI-05",
            "PI-06", "PI-07", "PI-08",
            "LI-01", "LI-02", "LI-03", "LI-04", "LI-05",
            "LI-06", "LI-07", "LI-08",
        ],
        cost=3.0,
        available=sysaudit_path.exists(),
    )

    # Binary analysis — checksec, rabin2, ltrace, ROPgadget
    # Wavelength: BA-01..BA-06  Cost: 4.0 (static + dynamic)
    instruments["binary_analysis"] = Instrument(
        name="binary_analysis",
        description="Binary exploitation analysis — NX/ASLR/canary, dangerous functions, ROP gadgets",
        wavelength=["BA-01", "BA-02", "BA-03", "BA-04", "BA-05", "BA-06"],
        cost=4.0,
        available=binary_available,
    )

    # IoT firmware probe — network-side + offline image analysis
    # Wavelength: IF-01..IF-15
    iot_probe_path = Path("/opt/skg/skg-iot_firmware-toolchain/adapters/firmware_probe/probe.py")
    instruments["iot_firmware"] = Instrument(
        name="iot_firmware",
        description="IoT firmware probe — banner grab + CVE version check for embedded components",
        wavelength=[f"IF-{i:02d}" for i in range(1, 16)],
        cost=2.0,
        available=iot_probe_path.exists(),
    )

    # Supply chain SBOM checker — SSH package collection + CVE cross-reference
    # Wavelength: SC-01..SC-12
    sc_probe_path = Path("/opt/skg/skg-supply-chain-toolchain/adapters/sbom_check/check.py")
    instruments["supply_chain"] = Instrument(
        name="supply_chain",
        description="Supply chain SBOM check — installed packages vs CVE catalog",
        wavelength=[f"SC-{i:02d}" for i in range(1, 13)],
        cost=2.0,
        available=sc_probe_path.exists(),
    )

    return instruments


# ── Field energy computation ─────────────────────────────────────────────

def load_wicket_states(ip: str) -> dict:
    """
    Load all wicket observations for a target from all event sources.

    Sources (latest observation per wicket_id wins by timestamp):
      DISCOVERY_DIR  — web_events, gravity_events, gravity_pcap, gravity_ssh
      EVENTS_DIR     — sensor loop output (net_sensor, ssh_sensor, bloodhound,
                       web_sensor, cve_sensor, msf_sensor, agent, usb)
      CVE_DIR        — NVD feed output
      /tmp           — auth events written by auth_scanner
    """
    states = {}
    # Web collector and gravity field direct events
    for ef in glob.glob(f"{DISCOVERY_DIR}/web_events_{ip}_*.ndjson"):
        _load_events_file(ef, states)
    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_events_{ip}_*.ndjson"):
        _load_events_file(ef, states)
    # HTTP collector output (gravity_http_{ip}_{port}.ndjson)
    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_http_{ip}_*.ndjson"):
        _load_events_file(ef, states)
    # nmap output
    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_nmap_{ip}_*.ndjson"):
        _load_events_file(ef, states)
    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_pcap_{ip}_*.ndjson"):
        _load_events_file(ef, states)
    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_ssh_{ip}_*.ndjson"):
        _load_events_file(ef, states)
    # Auth scanner (written to /tmp in old auth_scanner, DISCOVERY_DIR in new)
    for ef in glob.glob(f"/tmp/*auth*events*.ndjson"):
        _load_events_file(ef, states, filter_ip=ip)
    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_auth_{ip}_*.ndjson"):
        _load_events_file(ef, states)
    # Sensor loop output (net_sensor, ssh_sensor, bloodhound, web_sensor, etc.)
    # These use workload_id or target_ip to identify the host
    for ef in glob.glob(f"{EVENTS_DIR}/*.ndjson"):
        _load_events_file(ef, states, filter_ip=ip)
    # NVD CVE feed events
    for ef in glob.glob(f"{CVE_DIR}/cve_events_*.ndjson"):
        _load_events_file(ef, states, filter_ip=ip)
    return states


def _load_events_file(path: str, states: dict, filter_ip: str = None):
    """Load events from an NDJSON file into states dict."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                payload = event.get("payload", {})

                # Filter by IP if specified
                if filter_ip:
                    wid_ip = payload.get("workload_id", "")
                    target_ip = payload.get("target_ip", "")
                    if filter_ip not in wid_ip and filter_ip not in target_ip:
                        continue

                wid = payload.get("wicket_id")
                status = payload.get("status")
                detail = payload.get("detail", "")
                ts = event.get("ts", "")

                if wid and status:
                    prev_ts = states.get(wid, {}).get("ts", "")
                    if ts >= prev_ts:
                        states[wid] = {
                            "status": status,
                            "detail": detail,
                            "ts": ts,
                        }
    except Exception:
        pass


def field_entropy(states: dict, applicable_wickets: set) -> float:
    """
    Compute field energy E for a target.
    E = count of unknown wickets in the applicable set.  (Work 3 Section 4.2)

    E = 0   → fully determined (all wickets realized or blocked).
    E = n   → fully unknown (maximum gravitational pull).

    NOT Shannon entropy. Shannon fails at all-unknown (gives 0, not maximum).
    Count-based E is monotonically correct: more unknowns = more pull.
    """
    if not applicable_wickets:
        return 0.0

    n = len(applicable_wickets)
    unknown_count = 0

    for wid in applicable_wickets:
        s = states.get(wid, {})
        # Handle both dict and string formats
        if isinstance(s, dict):
            status = s.get("status", "unknown")
        elif isinstance(s, str):
            status = s
        else:
            status = "unknown"

        if status == "unknown" or status == "":
            unknown_count += 1

    # Field energy = unknowns as proportion of total, scaled by surface size
    # E ranges from 0 (fully determined) to n (fully unknown)
    return float(unknown_count)


def entropy_reduction_potential(instrument: Instrument, states: dict,
                                 applicable_wickets: set,
                                 target_ip: str = "") -> float:
    """
    Estimate how much entropy this instrument could reduce.
    Based on how many unknown wickets fall within the instrument's wavelength.
    Penalizes instruments that previously failed to reduce entropy on this target.
    """
    unknown_in_reach = 0
    for wid in applicable_wickets:
        s = states.get(wid, {})
        if isinstance(s, dict):
            status = s.get("status", "unknown")
        elif isinstance(s, str):
            status = s
        else:
            status = "unknown"

        if status != "unknown":
            continue
        # Check if this wicket is in the instrument's wavelength
        for pattern in instrument.wavelength:
            if pattern.endswith("*"):
                prefix = pattern[:-1]
                if wid.startswith(prefix):
                    unknown_in_reach += 1
                    break
            elif wid == pattern:
                unknown_in_reach += 1
                break

    if unknown_in_reach == 0:
        return 0.0

    # Potential reduction = unknowns resolvable / cost
    # Penalize instruments that previously failed on this specific target
    penalty = 1.0
    if target_ip and instrument.failed_to_reduce(target_ip):
        penalty = 0.2  # Heavy penalty — try something else

    return (unknown_in_reach / instrument.cost) * penalty


# ── Catalog loading ──────────────────────────────────────────────────────

def load_all_wicket_ids() -> dict:
    """Load wicket IDs from all catalogs, grouped by domain."""
    domain_wickets = {}
    for catalog_file in glob.glob("/opt/skg/skg-*-toolchain/contracts/catalogs/*.json"):
        try:
            data = json.loads(Path(catalog_file).read_text())
            domain = data.get("domain", "unknown")
            wickets = set(data.get("wickets", {}).keys())
            domain_wickets[domain] = wickets
        except Exception:
            continue
    return domain_wickets


# ── Instrument execution ────────────────────────────────────────────────

def execute_instrument(instrument: Instrument, target: dict,
                       run_id: str, out_dir: Path) -> dict:
    """
    Execute an instrument against a target.
    Returns dict with results and entropy change.
    """
    ip = target["ip"]
    result = {
        "instrument": instrument.name,
        "target": ip,
        "events_before": 0,
        "events_after": 0,
        "new_findings": [],
        "success": False,
    }

    # Count events before
    states_before = load_wicket_states(ip)
    unknown_before = sum(1 for s in states_before.values() if s.get("status") == "unknown")

    if instrument.name == "http_collector":
        result = _exec_http_collector(ip, target, run_id, out_dir, result)

    elif instrument.name == "auth_scanner":
        result = _exec_auth_scanner(ip, target, run_id, out_dir, result)

    elif instrument.name == "nvd_feed":
        result = _exec_nvd_feed(ip, target, run_id, out_dir, result)

    elif instrument.name == "metasploit":
        result = _exec_metasploit(ip, target, run_id, out_dir, result)

    elif instrument.name == "pcap":
        result = _exec_pcap(ip, target, run_id, out_dir, result)

    elif instrument.name == "nmap":
        result = _exec_nmap(ip, target, run_id, out_dir, result)

    elif instrument.name == "ssh_sensor":
        result = _exec_ssh_sensor(ip, target, run_id, out_dir, result)

    elif instrument.name == "bloodhound":
        result = _exec_bloodhound(ip, target, run_id, out_dir, result)

    elif instrument.name == "iot_firmware":
        result = _exec_iot_firmware(ip, target, run_id, out_dir, result)

    elif instrument.name == "supply_chain":
        result = _exec_supply_chain(ip, target, run_id, out_dir, result)

    elif instrument.name == "data_profiler":
        result = _exec_data_profiler(ip, target, run_id, out_dir, result)

    elif instrument.name == "sysaudit":
        result = _exec_sysaudit(ip, target, run_id, out_dir, result)

    elif instrument.name == "iot_firmware":
        result = _exec_iot_firmware(ip, target, run_id, out_dir, result)

    elif instrument.name == "supply_chain":
        result = _exec_supply_chain(ip, target, run_id, out_dir, result)



    elif instrument.name == "binary_analysis":
        result = _exec_binary_analysis(ip, target, run_id, out_dir, result)

    # Count events after
    states_after = load_wicket_states(ip)
    unknown_after = sum(1 for s in states_after.values() if s.get("status") == "unknown")
    result["unknowns_resolved"] = unknown_before - unknown_after

    # Track entropy history for this instrument
    instrument.entropy_history.setdefault(ip, []).append(unknown_after)
    instrument.last_used_on[ip] = iso_now()

    return result


def _exec_bloodhound(ip, target, run_id, out_dir, result):
    """
    Run the BloodHound adapter for Active Directory enumeration.
    Connects to BloodHound CE REST API or Neo4j bolt, runs the
    adapter, writes AD-* wicket events to DISCOVERY_DIR.
    """
    bh_url      = os.environ.get("BH_URL",      "http://localhost:8080")
    bh_user     = os.environ.get("BH_USERNAME",  "admin")
    bh_pass     = os.environ.get("BH_PASSWORD",  "")
    neo4j_pass  = os.environ.get("NEO4J_PASSWORD","")
    workload_id = target.get("workload_id", f"ad::{ip}")
    attack_path_id = "ad_lateral_movement_v1"

    if not bh_pass and not neo4j_pass:
        result["error"] = (
            "No BloodHound credentials — set BH_PASSWORD or NEO4J_PASSWORD "
            "in /etc/skg/skg.env, then: systemctl restart skg"
        )
        result["success"] = False
        return result

    try:
        sys.path.insert(0, "/opt/skg")
        sys.path.insert(0, "/opt/skg/skg-ad-lateral-toolchain")
        from skg.sensors.bloodhound_sensor import BLOODHOUND_CE_URL
        from skg.sensors.adapter_runner import run_bloodhound
    except ImportError as exc:
        result["error"] = f"BloodHound adapter not available: {exc}"
        return result

    bh_dir = out_dir
    try:
        events = run_bloodhound(bh_dir, workload_id, attack_path_id, run_id)
    except Exception as exc:
        result["error"] = f"BloodHound run failed: {exc}"
        return result

    if not events:
        result["success"] = False
        result["error"]   = "BloodHound returned no events"
        return result

    ev_file = out_dir / f"gravity_bh_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(ev_file)
    print(f"    [BH] {ip}: {len(events)} AD wicket events → {ev_file.name}")
    return result


def _exec_http_collector(ip, target, run_id, out_dir, result):
    """Run the web collector."""
    web_ports = target.get("web_ports", [])
    if not web_ports:
        # Infer from services
        for svc in target.get("services", []):
            if svc["service"] in ("http", "https", "http-alt", "https-alt"):
                scheme = "https" if "https" in svc["service"] else "http"
                web_ports.append((svc["port"], scheme))

    for port, scheme in web_ports[:2]:
        url = f"{scheme}://{ip}:{port}"
        events_file = out_dir / f"gravity_http_{ip}_{port}.ndjson"
        try:
            from collector import collect
            collect(target=url, out_path=str(events_file),
                    attack_path_id="web_sqli_to_shell_v1",
                    run_id=run_id, workload_id=f"web::{ip}",
                    timeout=8.0)
            # Stamp target_ip into every event for cross-file filtering
            if events_file.exists():
                lines = events_file.read_text().splitlines()
                stamped = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                        ev.setdefault("payload", {})["target_ip"] = ip
                        stamped.append(json.dumps(ev))
                    except Exception:
                        stamped.append(line)
                events_file.write_text("\n".join(stamped) + "\n")
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)

    return result


def _exec_auth_scanner(ip, target, run_id, out_dir, result):
    """Run the authenticated scanner."""
    web_ports = []
    for svc in target.get("services", []):
        if svc["service"] in ("http", "https", "http-alt", "https-alt"):
            scheme = "https" if "https" in svc["service"] else "http"
            web_ports.append((svc["port"], scheme))

    # Load per-target web credentials from targets.yaml
    username = None
    password = None
    targets_file = Path("/etc/skg/targets.yaml")
    if targets_file.exists():
        try:
            import yaml as _yaml
            data = _yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip or t.get("url", "").find(ip) >= 0:
                    auth = t.get("auth", {})
                    username = auth.get("user") or t.get("web_user")
                    password = auth.get("password") or t.get("web_password")
                    break
        except Exception:
            pass

    for port, scheme in web_ports[:1]:
        url = f"{scheme}://{ip}:{port}"
        events_file = out_dir / f"gravity_auth_{ip}_{port}.ndjson"
        try:
            from auth_scanner import auth_scan
            auth_scan(target=url, out_path=str(events_file),
                      attack_path_id="web_sqli_to_shell_v1",
                      try_defaults=True, run_id=run_id,
                      workload_id=f"web::{ip}:{port}",
                      username=username,   # None → falls through to DEFAULT_CREDS
                      password=password,
                      timeout=10.0)
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)

    return result


def _exec_nvd_feed(ip, target, run_id, out_dir, result):
    """Run NVD CVE lookup for discovered services."""
    api_key = os.environ.get("NIST_NVD_API_KEY", "")
    if not api_key:
        result["error"] = "No NVD API key"
        return result

    # Extract service versions from events
    states = load_wicket_states(ip)
    wb02 = states.get("WB-02", {})
    detail = wb02.get("detail", "")

    services_to_check = []
    try:
        headers = json.loads(detail)
        for val in headers.values():
            services_to_check.append(val)
    except (json.JSONDecodeError, TypeError):
        if detail:
            services_to_check.append(detail)

    if not services_to_check:
        result["error"] = "No service versions discovered"
        return result

    try:
        sys.path.insert(0, str(FEEDS_PATH))
        from nvd_ingester import ingest_service
        CVE_DIR.mkdir(parents=True, exist_ok=True)
        events_file = CVE_DIR / f"cve_events_{ip}_{run_id[:8]}.ndjson"

        total_candidates = 0
        for svc in services_to_check:
            candidates = ingest_service(svc, ip, events_file, api_key, run_id)
            total_candidates += len(candidates)

        result["success"] = True
        result["cve_candidates"] = total_candidates
    except Exception as e:
        result["error"] = str(e)

    return result


def _exec_metasploit(ip, target, run_id, out_dir, result):
    """
    Use Metasploit for targeted auxiliary scanning.
    Generates an RC script and creates an operator-triggerable field_action proposal.
    """
    web_ports = [svc["port"] for svc in target.get("services", [])
                 if svc["service"] in ("http", "https", "http-alt", "https-alt")]

    if not web_ports:
        result["error"] = "No web ports for MSF modules"
        return result

    port = web_ports[0]

    rc_lines = [
        f"setg RHOSTS {ip}",
        f"setg RPORT {port}",
        "setg THREADS 4",
        "",
        "# SQL injection scanner",
        "use auxiliary/scanner/http/sql_injection",
        f"set RHOSTS {ip}",
        f"set RPORT {port}",
        "set TARGETURI /",
        "run",
        "",
        "# Directory scanner",
        "use auxiliary/scanner/http/dir_scanner",
        f"set RHOSTS {ip}",
        f"set RPORT {port}",
        "run",
        "",
        "exit",
    ]

    rc_file = out_dir / f"msf_{ip}_{run_id[:8]}.rc"
    rc_file.write_text("\n".join(rc_lines))

    proposal = create_action(
        domain="web",
        description=f"Metasploit follow-on observation for {ip}:{port}",
        attack_surface=f"{ip}:{port}",
        hosts=[ip],
        category="runtime_observation",
        evidence=f"Gravity selected metasploit as follow-on instrument for {ip}:{port}",
        action={
            "instrument": "msf",
            "target_ip": ip,
            "port": port,
            "rc_file": str(rc_file),
            "module_candidates": [
                {
                    "module": "auxiliary/scanner/http/sql_injection",
                    "confidence": 0.80,
                    "module_class": "auxiliary",
                },
                {
                    "module": "auxiliary/scanner/http/dir_scanner",
                    "confidence": 0.60,
                    "module_class": "auxiliary",
                },
            ],
            "dispatch": {
                "kind": "msf_rc_script",
                "command_hint": f"msfconsole -r {rc_file}",
            },
        },
    )

    print(f"    [MSF] RC script written: {rc_file}")
    print(f"    [MSF] Proposal queued: {proposal['id']}")
    print(f"    [MSF] Trigger after approval: skg proposals trigger {proposal['id']}")

    result["success"] = True
    result["action"] = "operator"
    result["rc_file"] = str(rc_file)
    result["proposal_id"] = proposal["id"]
    result["suggestion"] = f"skg proposals trigger {proposal['id']}"

    return result

    # Build RC script for relevant auxiliary modules
    rc_lines = [
        f"setg RHOSTS {ip}",
        f"setg RPORT {web_ports[0]}",
        "setg THREADS 4",
        "",
        "# SQL injection scanner",
        "use auxiliary/scanner/http/sql_injection",
        f"set RHOSTS {ip}",
        f"set RPORT {web_ports[0]}",
        "set TARGETURI /",
        "run",
        "",
        "# Directory scanner",
        "use auxiliary/scanner/http/dir_scanner",
        f"set RHOSTS {ip}",
        f"set RPORT {web_ports[0]}",
        "run",
        "",
        "exit",
    ]

    rc_file = out_dir / f"msf_{ip}_{run_id[:8]}.rc"
    rc_file.write_text("\n".join(rc_lines))
    print(f"    [MSF] RC script written: {rc_file}")
    print(f"    [MSF] Run manually: msfconsole -r {rc_file}")
    print(f"    [MSF] Or: msfconsole -q -x 'resource {rc_file}'")

    # Don't auto-execute MSF — suggest to operator
    result["success"] = True
    result["action"] = "operator"
    result["rc_file"] = str(rc_file)
    result["suggestion"] = f"Run: msfconsole -r {rc_file}"

    return result


def _exec_pcap(ip, target, run_id, out_dir, result):
    """
    Capture traffic to/from the target and parse it into wicket events.

    Runs tshark synchronously (30s window) then uses net_sensor's
    _parse_tshark_fields / _flows_to_events to emit obs.attack.precondition
    events into DISCOVERY_DIR.  The next load_wicket_states() call picks
    them up so the entropy calculation reflects what was seen on the wire:
    SSH banners (HO-02), Kerberos AS-REP (AD-08), Docker API (CE-04),
    JNDI in HTTP (AP-L8), unusual outbound ports (AP-L7), etc.

    Running synchronously means gravity waits 30s but the entropy delta
    after the call is accurate — non-blocking would always read zero change.
    """
    events_file = out_dir / f"gravity_pcap_{ip}_{run_id[:8]}.ndjson"
    duration = 30

    print(f"    [PCAP] Capturing traffic to/from {ip} for {duration}s...")

    try:
        proc = subprocess.run(
            ["tshark", "-i", "any", "-f", f"host {ip}",
             "-a", f"duration:{duration}",
             "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.dstport", "-e", "tcp.srcport",
             "-e", "udp.dstport", "-e", "udp.srcport",
             "-e", "ssh.protocol", "-e", "kerberos.msg_type",
             "-e", "http.request.uri", "-e", "dns.qry.name",
             "-e", "_ws.col.Protocol",
             "-E", "separator=|", "-E", "occurrence=f"],
            capture_output=True, text=True, timeout=duration + 15,
        )
        raw_output = proc.stdout
    except subprocess.TimeoutExpired:
        result["error"] = "tshark timed out"
        return result
    except FileNotFoundError:
        result["error"] = "tshark not found — install: pacman -S wireshark-cli"
        return result
    except Exception as exc:
        result["error"] = f"tshark error: {exc}"
        return result

    if not raw_output.strip():
        result["success"] = True
        result["flows"] = 0
        print(f"    [PCAP] No traffic captured")
        return result

    try:
        from skg.sensors.net_sensor import _parse_tshark_fields, _flows_to_events
        flows  = _parse_tshark_fields(raw_output)
        events = _flows_to_events(flows, seen_flows=set())
        if events:
            with open(events_file, "w") as fh:
                for ev in events:
                    # Stamp target_ip so the IP filter in _load_events_file matches
                    ev.setdefault("payload", {})["target_ip"] = ip
                    fh.write(json.dumps(ev) + "\n")
        result["success"]      = True
        result["flows"]        = len(flows)
        result["events"]       = len(events)
        result["events_file"]  = str(events_file)
        print(f"    [PCAP] {ip}: {len(flows)} flows → {len(events)} wicket events")
    except Exception as exc:
        result["success"] = True          # capture worked even if parse failed
        result["parse_error"] = str(exc)
        print(f"    [PCAP] capture done, parse error: {exc}")

    return result


def _exec_nmap(ip, target, run_id, out_dir, result):
    """
    Run nmap version detection and emit wicket events from the results.

    Parses nmap XML output into obs.attack.precondition events:
      - Open ports    → HO-01 (reachable), HO-02 (SSH), WB-01 (web), CE-04 (Docker)
      - Service banner → WB-02 (version disclosed, feeds NVD)
      - NSE script hits → HO-06, HO-07, HO-11 (vuln indicators)

    Writes events to DISCOVERY_DIR so load_wicket_states reads them.
    """
    import xml.etree.ElementTree as ET

    xml_file    = out_dir / f"nmap_{ip}_{run_id[:8]}.xml"
    events_file = out_dir / f"gravity_nmap_{ip}_{run_id[:8]}.ndjson"

    ports = [str(svc["port"]) for svc in target.get("services", [])]
    port_arg = ",".join(ports) if ports else "22,80,443,445,2375,2376,8080,8443"

    print(f"    [NMAP] Scanning {ip} ports {port_arg} with version detection...")

    try:
        subprocess.run(
            ["nmap", "-sV", "--script=default,vulners",
             "-p", port_arg, "-oX", str(xml_file), "--open", ip],
            capture_output=True, timeout=120
        )
    except FileNotFoundError:
        result["error"] = "nmap not found — install: pacman -S nmap"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result

    if not xml_file.exists():
        result["error"] = "nmap produced no output"
        return result

    # Parse XML and emit events
    events = []
    now = iso_now()

    def _ev(wicket_id, status, rank, confidence, detail):
        return {
            "id": str(uuid.uuid4()), "ts": now,
            "type": "obs.attack.precondition",
            "source": {"source_id": "nmap", "toolchain": "skg-host-toolchain", "version": "0"},
            "payload": {
                "wicket_id": wicket_id, "status": status,
                "workload_id": f"nmap::{ip}", "target_ip": ip,
                "detail": detail, "run_id": run_id,
            },
            "provenance": {
                "evidence_rank": rank,
                "evidence": {"source_kind": "nmap_scan", "pointer": f"nmap://{ip}",
                             "collected_at": now, "confidence": confidence},
            },
        }

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        host_el = root.find("host")
        if host_el is None:
            result["error"] = "nmap: host not found in output (host may be down)"
            return result

        # Host is up → HO-01
        events.append(_ev("HO-01", "realized", 4, 0.95,
                          f"Host responded to nmap scan"))

        for port_el in host_el.findall(".//port"):
            portid   = port_el.get("portid", "")
            state_el = port_el.find("state")
            svc_el   = port_el.find("service")

            if state_el is None or state_el.get("state") != "open":
                continue

            svc_name    = svc_el.get("name", "") if svc_el is not None else ""
            product     = svc_el.get("product", "") if svc_el is not None else ""
            version_str = svc_el.get("version", "") if svc_el is not None else ""
            banner = f"{product} {version_str}".strip() if (product or version_str) else svc_name

            # Port-specific wickets
            if portid in ("22", "2222"):
                events.append(_ev("HO-02", "realized", 4, 0.95,
                                  f"SSH on port {portid}" + (f" — {banner}" if banner else "")))

            if portid in ("80", "443", "8080", "8443", "8000"):
                events.append(_ev("WB-01", "realized", 4, 0.90,
                                  f"Web service on port {portid}" + (f" — {banner}" if banner else "")))

            if portid in ("2375", "2376"):
                events.append(_ev("CE-04", "realized", 6, 0.98,
                                  f"Docker API exposed on port {portid} — unauthenticated socket"))

            if portid == "445":
                events.append(_ev("AD-16", "unknown", 4, 0.50,
                                  f"SMB on {portid} — signing status unknown, check with enum4linux"))

            # Version disclosure (feeds NVD)
            if banner:
                events.append(_ev("WB-02", "realized", 4, 0.85,
                                  json.dumps({svc_name: banner})))

        # NSE script hits — look for vuln indicators
        for script_el in host_el.findall(".//script"):
            script_id  = script_el.get("id", "")
            script_out = script_el.get("output", "")

            if "vuln" in script_id or "CVE" in script_out:
                # Extract CVE IDs if present
                cve_ids = re.findall(r"CVE-\d{4}-\d+", script_out)
                for cve_id in cve_ids:
                    events.append(_ev(cve_id, "realized", 6, 0.75,
                                      f"nmap NSE {script_id}: {script_out[:120]}"))
                if not cve_ids:
                    events.append(_ev("HO-11", "realized", 5, 0.65,
                                      f"nmap NSE {script_id}: {script_out[:120]}"))

            if "sudo" in script_out.lower() and "NOPASSWD" in script_out:
                events.append(_ev("HO-06", "realized", 5, 0.80,
                                  f"nmap NSE: sudo NOPASSWD detected"))

    except ET.ParseError as exc:
        result["error"] = f"nmap XML parse error: {exc}"
        return result

    # Write events
    if events:
        with open(events_file, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    result["success"]     = True
    result["nmap_xml"]    = str(xml_file)
    result["events"]      = len(events)
    result["events_file"] = str(events_file)
    print(f"    [NMAP] {ip}: {len(events)} wicket events → {events_file.name}")
    return result


def _exec_binary_analysis(ip, target, run_id, out_dir, result):
    """
    Run binary exploitation analysis on binaries found on the target.

    Gravity selects this instrument when BA-* wickets are unknown — typically
    after HO-07 (SUID binary present) or FI-04 (executable in /tmp) fires,
    which propagate intra-target to elevate BA-* priors.

    Process:
      1. Find candidate binaries via SSH (SUID bins, bins in /tmp, service exes)
      2. Fetch each binary to local /tmp via SCP
      3. Run checksec → BA-01/02/03
      4. Run rabin2 -i → BA-04 (dangerous imports)
      5. Run ltrace with crafted input → BA-05 (controlled input reachable)
      6. Run ROPgadget → BA-06 (chain constructible)
      7. Emit events to DISCOVERY_DIR

    Falls back to the exploit_dispatch analyze_binary() function if available.
    """
    import subprocess as _sp
    import shutil as _sh

    # Load SSH credentials
    targets_file = Path("/etc/skg/targets.yaml")
    ssh_target = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    workload_id  = f"binary::{ip}"
    attack_path_id = "binary_stack_overflow_v1"
    all_events: list[dict] = []

    def _ev(wid, status, rank, conf, detail):
        return {
            "id":   str(uuid.uuid4()),
            "ts":   datetime.now(timezone.utc).isoformat(),
            "type": "obs.attack.precondition",
            "source": {"source_id": "gravity.binary_analysis",
                       "toolchain": "skg-binary-toolchain", "version": "0.1.0"},
            "payload": {
                "wicket_id": wid, "status": status,
                "workload_id": workload_id, "detail": detail[:400],
                "attack_path_id": attack_path_id, "run_id": run_id,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "target_ip": ip,
            },
            "provenance": {"evidence_rank": rank,
                           "evidence": {"source_kind": "binary_scanner",
                                        "pointer": f"ssh://{ip}",
                                        "collected_at": datetime.now(timezone.utc).isoformat(),
                                        "confidence": conf}},
        }

    # Step 1: find candidate binaries via SSH
    candidate_binaries: list[str] = []

    if ssh_target:
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            user = ssh_target.get("user", "root")
            key  = ssh_target.get("key")
            port = int(ssh_target.get("port", 22))
            if key:
                client.connect(ip, port=port, username=user,
                               key_filename=str(Path(key).expanduser()),
                               timeout=15)
            else:
                client.connect(ip, port=port, username=user,
                               password=ssh_target.get("password", ""),
                               timeout=15)

            # SUID binaries (already partially known from HO-07)
            _, stdout, _ = client.exec_command(
                "find / -perm -4000 -type f 2>/dev/null "
                "| grep -v '^/proc\\|^/sys' | head -10", timeout=30)
            candidate_binaries += [l.strip() for l in
                                    stdout.read().decode(errors="replace").splitlines()
                                    if l.strip()]

            # Executables in /tmp
            _, stdout2, _ = client.exec_command(
                "find /tmp /var/tmp -type f -executable 2>/dev/null | head -5",
                timeout=10)
            candidate_binaries += [l.strip() for l in
                                    stdout2.read().decode(errors="replace").splitlines()
                                    if l.strip()]
            client.close()
        except Exception as exc:
            print(f"    [BIN] SSH failed for {ip}: {exc}")

    # Step 2: Use exploit_dispatch analyze_binary if available (skips remote fetch)
    dispatch_path = Path("/opt/skg/skg-gravity/exploit_dispatch.py")
    if dispatch_path.exists():
        try:
            sys.path.insert(0, str(dispatch_path.parent))
            from exploit_dispatch import analyze_binary

            # For remote binaries, we need to fetch them first
            # For now emit one pass on any locally accessible path
            fetched_any = False
            for remote_path in candidate_binaries[:3]:
                local_tmp = Path(f"/tmp/skg_bin_{run_id[:8]}_{Path(remote_path).name}")
                try:
                    if ssh_target:
                        import paramiko
                        t = paramiko.SSHClient()
                        t.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        user = ssh_target.get("user", "root")
                        key  = ssh_target.get("key")
                        port = int(ssh_target.get("port", 22))
                        if key:
                            t.connect(ip, port=port, username=user,
                                      key_filename=str(Path(key).expanduser()),
                                      timeout=15)
                        else:
                            t.connect(ip, port=port, username=user,
                                      password=ssh_target.get("password",""),
                                      timeout=15)
                        sftp = t.open_sftp()
                        sftp.get(remote_path, str(local_tmp))
                        sftp.close()
                        t.close()

                    if local_tmp.exists():
                        print(f"    [BIN] Analyzing {remote_path}...")
                        evs = analyze_binary(str(local_tmp))
                        # Stamp target_ip
                        for ev in evs:
                            ev.setdefault("payload", {})["target_ip"] = ip
                            ev["payload"]["workload_id"] = workload_id
                        all_events.extend(evs)
                        fetched_any = True
                        local_tmp.unlink(missing_ok=True)
                except Exception:
                    pass

            if not fetched_any and not candidate_binaries:
                # No binaries found — emit unknowns for all BA-* wickets
                for wid in ["BA-01","BA-02","BA-03","BA-04","BA-05","BA-06"]:
                    all_events.append(_ev(wid, "unknown", 6, 0.40,
                                         "No candidate binaries found on target"))
        except ImportError:
            pass

    if not all_events:
        # No analysis ran — emit unknowns
        for wid in ["BA-01","BA-02","BA-03","BA-04","BA-05","BA-06"]:
            all_events.append(_ev(wid, "unknown", 6, 0.40,
                                  "Binary analysis tools not available "
                                  "(install: checksec rabin2 ROPgadget)"))
        result["success"] = False
        result["action"]  = "operator"
        result["suggestion"] = (
            f"Install binary analysis tools, then: "
            f"skg exploit binary /path/to/suid_binary"
        )

    if all_events:
        ev_file = out_dir / f"gravity_binary_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
        with open(ev_file, "w") as fh:
            for ev in all_events:
                fh.write(json.dumps(ev) + "\n")
        r = sum(1 for e in all_events if e["payload"]["status"] == "realized")
        b = sum(1 for e in all_events if e["payload"]["status"] == "blocked")
        u = sum(1 for e in all_events if e["payload"]["status"] == "unknown")
        print(f"    [BIN] {ip}: {len(all_events)} BA-* events ({r}R {b}B {u}U)")
        result["success"]     = True
        result["events"]      = len(all_events)
        result["events_file"] = str(ev_file)

    return result


def _exec_iot_firmware(ip, target, run_id, out_dir, result):
    """Run the IoT firmware probe against ip (live) or a local firmware image."""
    import sys as _sys
    _sys.path.insert(0, "/opt/skg/skg-iot_firmware-toolchain/adapters/firmware_probe")
    try:
        from probe import probe_device, probe_from_image
    except ImportError:
        result["error"] = "firmware_probe adapter not found at /opt/skg"
        return result

    targets_file = Path("/etc/skg/targets.yaml")
    ssh_target   = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    workload_id = f"iot::{ip}"
    apid        = "iot_firmware_network_exploit_v1"

    if ssh_target:
        events = probe_device(
            host=ip, user=ssh_target.get("user", "root"),
            password=ssh_target.get("password", ""),
            port_ssh=int(ssh_target.get("port", 22)),
            workload_id=workload_id, run_id=run_id,
            attack_path_id=apid,
        )
    else:
        # No SSH creds — try local firmware image
        image_candidates = (
            list(Path("/var/lib/skg").glob(f"firmware_{ip.replace('.','_')}*.bin")) +
            list(Path("/var/lib/skg").glob("firmware_*.bin"))
        )
        if image_candidates:
            events = probe_from_image(
                str(image_candidates[0]), workload_id=workload_id,
                run_id=run_id, attack_path_id=apid,
            )
        else:
            result["success"]    = False
            result["action"]     = "operator"
            result["suggestion"] = (
                f"Add {ip} to /etc/skg/targets.yaml or place firmware image at "
                f"/var/lib/skg/firmware_{ip.replace('.','_')}.bin"
            )
            return result

    if not events:
        result["success"] = True
        result["events"]  = 0
        return result

    ev_file = out_dir / f"gravity_iot_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"    [IOT] {ip}: {len(events)} events ({r}R {b}B {u}U)")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(ev_file)
    return result


def _exec_supply_chain(ip, target, run_id, out_dir, result):
    """Run the supply chain SBOM check against a target."""
    import sys as _sys
    _sys.path.insert(0, "/opt/skg/skg-supply-chain-toolchain/adapters/sbom_check")
    try:
        from check import evaluate_packages, collect_via_ssh
    except ImportError:
        result["error"] = "sbom_check adapter not found"
        return result

    targets_file = Path("/etc/skg/targets.yaml")
    ssh_target   = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    workload_id = f"supply_chain::{ip}"
    apid        = "supply_chain_rce_via_dependency_v1"

    if not ssh_target:
        result["success"]    = False
        result["action"]     = "operator"
        result["suggestion"] = (
            f"Add {ip} to /etc/skg/targets.yaml to enable supply chain analysis, "
            f"or use: skg supply --host {ip}"
        )
        return result

    try:
        packages = collect_via_ssh(
            host=ip, user=ssh_target.get("user","root"),
            key=ssh_target.get("key"), password=ssh_target.get("password"),
            port=int(ssh_target.get("port",22)),
        )
        events = evaluate_packages(packages, workload_id=workload_id,
                                   run_id=run_id, attack_path_id=apid)
    except Exception as exc:
        result["error"] = f"supply_chain collection failed: {exc}"
        return result

    if not events:
        result["success"] = True
        result["events"]  = 0
        return result

    ev_file = out_dir / f"gravity_sc_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"    [SC] {ip}: {len(events)} events ({r}R {b}B {u}U)")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(ev_file)
    return result


def _exec_sysaudit(ip, target, run_id, out_dir, result):
    """
    Run the sysaudit adapter against the target via SSH.

    Loads credentials from targets.yaml, opens a paramiko session, calls
    run_sysaudit() which executes all FI/PI/LI checks on the remote host,
    writes events to DISCOVERY_DIR with target_ip stamped.

    Gravity selects this instrument when FI-*, PI-*, or LI-* wickets are
    unknown — the same wavelength-matching logic that selects http_collector
    for WB-* unknowns. The entropy reduction signal is real: after a first
    run all wickets collapse to realized/blocked/unknown based on live state.
    Subsequent runs detect changes (new SUID, crontab modification, log shrink).

    Falls back to an operator suggestion if no credentials are configured.
    """
    import sys as _sys

    # Load credentials from targets.yaml
    targets_file = Path("/etc/skg/targets.yaml")
    ssh_target = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip or t.get("workload_id", "").endswith(ip):
                    ssh_target = t
                    break
        except Exception:
            pass

    if ssh_target is None:
        result["success"] = False
        result["action"]  = "operator"
        result["suggestion"] = (
            f"Add {ip} to /etc/skg/targets.yaml, then: "
            f"skg audit scan --target {ip}"
        )
        print(f"    [AUDIT] No credentials for {ip} — {result['suggestion']}")
        return result

    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko not installed"
        return result

    user     = ssh_target.get("user", "root")
    key      = ssh_target.get("key")
    port     = int(ssh_target.get("port", 22))
    password = ssh_target.get("password")
    workload_id = ssh_target.get("workload_id", f"audit::{ip}")
    attack_path_id = "full_system_integrity_v1"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if key:
            client.connect(ip, port=port, username=user,
                           key_filename=str(Path(key).expanduser()),
                           timeout=20)
        elif password:
            import os as _os
            client.connect(ip, port=port, username=user,
                           password=_os.path.expandvars(password),
                           timeout=20)
        else:
            client.connect(ip, port=port, username=user, timeout=20)
    except Exception as exc:
        result["error"] = f"SSH connect failed: {exc}"
        return result

    print(f"    [AUDIT] Running FI/PI/LI checks on {ip}...")

    try:
        _sys.path.insert(0, "/opt/skg/skg-host-toolchain/adapters/sysaudit")
        from audit import run_sysaudit

        events = run_sysaudit(
            client, ip, workload_id, attack_path_id, run_id,
        )
    except Exception as exc:
        result["error"] = f"sysaudit failed: {exc}"
        client.close()
        return result

    client.close()

    if not events:
        result["success"] = True
        result["events"]  = 0
        return result

    # Write events with target_ip stamped for load_wicket_states
    ev_file = out_dir / f"gravity_audit_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"    [AUDIT] {ip}: {len(events)} events ({r}R {b}B {u}U) → {ev_file.name}")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(ev_file)
    return result


def _exec_data_profiler(ip, target, run_id, out_dir, result):
    """
    Run the database profiler against configured data sources for this target.

    The data profiler is directed by gravity exactly like any other instrument:
    gravity selects it when DP-* wickets are unknown, runs it, and measures
    the entropy change. The same physics — wavelength, cost, penalty, shifting
    — apply without modification.

    'target' for a data source has the same shape as a network target but
    the 'ip' field is a workload_id like 'banking::orders' and the 'services'
    list contains data source descriptors instead of port/service pairs.

    Data sources are read from:
      1. target['data_sources'] if present (gravity-generated target)
      2. /etc/skg/data_sources.yaml (operator-declared)
      3. skg_config.yaml sensors.data.sources
    """
    import sys as _sys
    import os as _os

    _sys.path.insert(0, "/opt/skg/skg-data-toolchain")

    # Find data sources for this target
    # For network targets, look up any data sources bound to this IP
    # For data workload targets, ip IS the workload_id
    data_sources = target.get("data_sources", [])

    if not data_sources:
        # Try config file
        config_file = Path("/etc/skg/data_sources.yaml")
        if config_file.exists():
            try:
                import yaml
                cfg = yaml.safe_load(config_file.read_text())
                all_sources = cfg.get("data_sources", [])
                # Filter to sources matching this IP (by host in URL or workload_id)
                for src in all_sources:
                    url = src.get("url", "")
                    wid = src.get("workload_id", "")
                    if ip in url or ip in wid or not ip.replace(".","").isdigit():
                        data_sources.append(src)
            except Exception as exc:
                result["error"] = f"data_sources.yaml parse error: {exc}"
                return result

    if not data_sources:
        result["error"] = (
            "No data sources configured for this target. "
            "Add data_sources to /etc/skg/data_sources.yaml"
        )
        return result

    try:
        from adapters.db_profiler.profile import profile_table
    except ImportError:
        result["error"] = (
            "db_profiler not found at /opt/skg/skg-data-toolchain. "
            "Run setup_arch.sh to install."
        )
        return result

    total_events = 0
    events_files = []

    for src in data_sources:
        url         = src.get("url", "")
        table       = src.get("table", "")
        workload_id = src.get("workload_id") or f"data::{table}"
        contract    = src.get("contract")
        apid        = src.get("attack_path_id", "data_completeness_failure_v1")

        if not url or not table:
            continue

        print(f"    [DATA] Profiling {table} ({workload_id})")

        try:
            events = profile_table(
                url=url, table=table,
                workload_id=workload_id,
                contract_path=contract,
                attack_path_id=apid,
                run_id=run_id,
            )
        except Exception as exc:
            print(f"    [DATA] Profile failed: {exc}")
            continue

        if not events:
            continue

        # Write to gravity output dir with target_ip stamped
        ev_file = out_dir / f"gravity_data_{workload_id.replace('::', '_')}_{run_id}.ndjson"
        with open(ev_file, "w") as fh:
            for ev in events:
                ev.setdefault("payload", {})["target_ip"] = ip
                fh.write(json.dumps(ev) + "\n")

        total_events += len(events)
        events_files.append(str(ev_file))

        r = sum(1 for e in events if e["payload"]["status"] == "realized")
        b = sum(1 for e in events if e["payload"]["status"] == "blocked")
        u = sum(1 for e in events if e["payload"]["status"] == "unknown")
        print(f"    [DATA] {workload_id}: {len(events)} events ({r}R {b}B {u}U)")

    result["success"]      = total_events > 0
    result["events"]       = total_events
    result["events_files"] = events_files
    if not result["success"]:
        result["error"] = "No events produced — check data source config"
    return result



    """
    Collect the AD domain graph from BloodHound CE and emit AD wicket events.

    BloodHound sees the whole domain, not just one host — so we use the
    domain_sid from skg_config.yaml to scope which domain this target belongs
    to, then run the full BH collection.  Events are written to out_dir with
    target_ip = ip so load_wicket_states() picks them up for this target's
    entropy calculation.

    The AD wickets this resolves (kerberoastable, delegation, stale DAs,
    LAPS gaps, password-in-description, ACL abuses, domain properties)
    are all read from the BH object graph — no agent on the target needed.

    Falls back to Neo4j bolt if the BH CE REST API is unreachable.
    """
    import sys as _sys
    import os as _os

    bh_url   = _os.environ.get("BH_URL",      "http://localhost:8080")
    bh_user  = _os.environ.get("BH_USERNAME", "admin")
    bh_pass  = _os.environ.get("BH_PASSWORD", "")
    neo4j_url  = _os.environ.get("NEO4J_URL",      "bolt://localhost:7687")
    neo4j_user = _os.environ.get("NEO4J_USER",     "neo4j")
    neo4j_pass = _os.environ.get("NEO4J_PASSWORD", "")

    # Infer workload_id — use domain (from target domains list) or IP
    domains_for_target = target.get("domains", [])
    workload_id = next(
        (d for d in domains_for_target if "ad" in d.lower()),
        f"ad::{ip}"
    )
    attack_path_id = "ad_kerberoast_v1"

    print(f"    [BH] Collecting AD graph from {bh_url} for workload {workload_id}...")

    try:
        _sys.path.insert(0, "/opt/skg")
        from skg.sensors.bloodhound_sensor import (
            BloodHoundCEClient, Neo4jClient,
            collect_via_api, collect_via_neo4j,
            write_bh_dir,
        )
        from skg.sensors.adapter_runner import run_bloodhound
        from skg.core.paths import SKG_STATE_DIR
    except ImportError as exc:
        result["error"] = f"BloodHound sensor import failed: {exc}"
        return result

    data = None

    if bh_pass:
        try:
            client = BloodHoundCEClient(bh_url, bh_user, bh_pass)
            data = collect_via_api(client)
        except Exception as exc:
            print(f"    [BH] CE API failed ({exc}), trying Neo4j...")

    if data is None and neo4j_pass:
        try:
            client = Neo4jClient(neo4j_url, neo4j_user, neo4j_pass)
            data = collect_via_neo4j(client)
            client.close()
        except Exception as exc:
            result["error"] = f"Neo4j also unavailable: {exc}"
            return result

    if data is None:
        result["error"] = "No BloodHound source reachable (set BH_PASSWORD or NEO4J_PASSWORD)"
        return result

    # Write normalized BH data and run the adapter
    bh_dir = SKG_STATE_DIR / "bh_cache" / run_id[:8]
    write_bh_dir(data, bh_dir)

    try:
        events = run_bloodhound(bh_dir, workload_id, attack_path_id, run_id)
    except Exception as exc:
        result["error"] = f"BloodHound adapter failed: {exc}"
        return result

    # Write events to gravity output dir with target_ip stamped
    events_file = out_dir / f"gravity_bh_{ip}_{run_id[:8]}.ndjson"
    if events:
        with open(events_file, "w") as fh:
            for ev in events:
                ev.setdefault("payload", {})["target_ip"] = ip
                fh.write(json.dumps(ev) + "\n")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(events_file)
    print(f"    [BH]  {workload_id}: {len(events)} AD wicket events → {events_file.name}")

    return result


def _exec_ssh_sensor(ip, target, run_id, out_dir, result):
    """
    Run the SSH sensor against the target.

    Loads target credentials from targets.yaml, opens a paramiko session,
    and runs the host toolchain adapter directly.  Writes events to out_dir
    so load_wicket_states() picks them up on the next entropy calculation.

    Falls back to an operator suggestion if no credentials are configured.
    """
    from pathlib import Path as _P
    import sys as _sys

    # Find target credentials from targets.yaml
    targets_file = _P("/etc/skg/targets.yaml")
    ssh_target = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip or t.get("workload_id", "").endswith(ip):
                    ssh_target = t
                    break
        except Exception:
            pass

    if ssh_target is None:
        # No credentials configured — emit an operator suggestion but
        # don't count this as a success (gravity should not penalise)
        print(f"    [SSH] No credentials for {ip} in targets.yaml")
        print(f"    [SSH] Add target then run: skg collect --target {ip}")
        result["success"] = False
        result["action"] = "operator"
        result["suggestion"] = f"Add {ip} to /etc/skg/targets.yaml then: skg collect --target {ip}"
        return result

    # Credentials found — run collection
    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko not installed"
        return result

    user     = ssh_target.get("user", "root")
    key      = ssh_target.get("key")
    port     = int(ssh_target.get("port", 22))
    password = ssh_target.get("password")
    workload_id = ssh_target.get("workload_id", f"ssh::{ip}")
    attack_path_id = ssh_target.get("attack_path_id", "host_ssh_initial_access_v1")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if key:
            client.connect(ip, port=port, username=user,
                           key_filename=_P(key).expanduser().__str__(),
                           timeout=20)
        elif password:
            import os as _os
            client.connect(ip, port=port, username=user,
                           password=_os.path.expandvars(password),
                           timeout=20)
        else:
            client.connect(ip, port=port, username=user, timeout=20)
    except Exception as exc:
        result["error"] = f"SSH connect failed: {exc}"
        return result

    events_file = out_dir / f"gravity_ssh_{ip}_{run_id[:8]}.ndjson"

    try:
        # Import and run the host toolchain adapter directly
        _sys.path.insert(0, "/opt/skg")
        from skg.sensors.adapter_runner import run_ssh_host
        events = run_ssh_host(
            client, ip, workload_id, attack_path_id, run_id,
            out_file=events_file, user=user,
            auth_type="key" if key else "password",
            port=port,
        )
        # Write events to the gravity output directory
        if events:
            with open(events_file, "a") as fh:
                for ev in events:
                    fh.write(json.dumps(ev) + "\n")
        result["success"] = True
        result["events_file"] = str(events_file)
        print(f"    [SSH] {ip}: {len(events)} events → {events_file.name}")
    except Exception as exc:
        result["error"] = f"SSH collection failed: {exc}"
    finally:
        client.close()

    return result


# ── The Field ────────────────────────────────────────────────────────────

def gravity_field_cycle(surface_path: str, out_dir: str,
                        cycle_num: int, instruments: dict) -> dict:
    """
    One cycle of the gravity field dynamics.

    Not observe-orient-decide-act. Continuous field dynamics:
    1. Run FoldDetector — structural/contextual/temporal/projection gaps
    2. Compute entropy landscape across all targets (E = unknowns + fold_weight)
    3. Follow the gradient — highest entropy region
    4. Select instrument that maximizes entropy reduction potential
    5. If that instrument previously failed here, shift to next best
    6. Execute and measure entropy change
    7. The changed entropy reshapes the landscape for next cycle

    Folds add to E because they represent structural uncertainty —
    dark regions of state space the system knows it cannot yet evaluate.
    A target with 10 unknown wickets and a structural fold for redis (p=0.85)
    has E ≈ 11.85, not E = 10.
    """
    surface = json.loads(Path(surface_path).read_text())
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())

    domain_wickets = load_all_wicket_ids()
    all_wickets = set()
    for wids in domain_wickets.values():
        all_wickets.update(wids)

    print(f"\n{'='*70}")
    print(f"  GRAVITY FIELD — CYCLE {cycle_num}")
    print(f"  {iso_now()}")
    print(f"{'='*70}")

    # ── Run FoldDetector ─────────────────────────────────────────────────────
    # Build per-IP fold map before entropy calculation so folds
    # are included in E for each target.
    fold_manager_by_ip: dict[str, object] = {}
    try:
        from skg.kernel.folds import FoldDetector, FoldManager
        detector = FoldDetector()
        all_new_folds = detector.detect_all(
            events_dir=EVENTS_DIR,
            cve_dir=CVE_DIR,
            toolchain_dir=Path("/opt/skg"),
        )
        # Group folds by IP — location is workload_id which contains IP
        for fold in all_new_folds:
            # Extract IP from location strings like "ssh::172.17.0.2",
            # "cve::172.17.0.2", or raw workload_id
            loc = fold.location
            ip_match = None
            for target in surface.get("targets", []):
                tip = target["ip"]
                if tip in loc or loc.endswith(tip):
                    ip_match = tip
                    break
            if ip_match:
                if ip_match not in fold_manager_by_ip:
                    fold_manager_by_ip[ip_match] = FoldManager()
                fold_manager_by_ip[ip_match].add(fold)

        # Report fold summary
        total_folds = sum(
            len(fm.all()) for fm in fold_manager_by_ip.values()
        )
        if total_folds > 0:
            print(f"\n  [FOLDS] {total_folds} active folds detected:")
            fold_counts: dict[str, int] = {}
            for fm in fold_manager_by_ip.values():
                for f in fm.all():
                    fold_counts[f.fold_type] = fold_counts.get(f.fold_type, 0) + 1
            for ft, count in sorted(fold_counts.items()):
                print(f"    {ft:14s}: {count}")
        else:
            print(f"\n  [FOLDS] No folds detected this cycle")

    except Exception as exc:
        print(f"\n  [FOLDS] FoldDetector unavailable: {exc}")
        fold_manager_by_ip = {}

    # ── Compute entropy landscape ──
    print("\n  [FIELD] Computing entropy landscape...\n")

    landscape = []
    for target in surface.get("targets", []):
        ip = target["ip"]
        states = load_wicket_states(ip)

        # Determine applicable wickets based on target domains
        applicable = set()
        for domain in target.get("domains", []):
            applicable.update(domain_wickets.get(domain, set()))

        # Base E: count of unknown catalogued wickets
        E_base = field_entropy(states, applicable)

        # Fold contribution: structural uncertainty on top of unknown nodes
        # E = E_base + Σ fold.gravity_weight()
        # This is the extended Work 3 formula — folds add to gravitational pull
        fold_manager = fold_manager_by_ip.get(ip)
        fold_boost   = fold_manager.total_gravity_weight() if fold_manager else 0.0
        E            = E_base + fold_boost

        unknowns = sum(1 for w in applicable
                       if states.get(w, {}).get("status", "unknown") == "unknown")
        realized = sum(1 for w in applicable
                       if states.get(w, {}).get("status") == "realized")
        blocked = sum(1 for w in applicable
                      if states.get(w, {}).get("status") == "blocked")
        n_folds  = len(fold_manager.all()) if fold_manager else 0

        landscape.append({
            "ip": ip,
            "entropy":           E,
            "E_base":            E_base,
            "fold_boost":        fold_boost,
            "n_folds":           n_folds,
            "unknowns":          unknowns,
            "realized":          realized,
            "blocked":           blocked,
            "total_wickets":     len(applicable),
            "applicable_wickets": applicable,
            "states":            states,
            "domains":           target.get("domains", []),
            "services":          target.get("services", []),
            "target":            target,
            "fold_manager":      fold_manager,
        })

    # Sort by entropy — follow the gradient
    landscape.sort(key=lambda x: x["entropy"], reverse=True)

    # Display field — show E breakdown: base unknowns + fold boost
    print(f"  {'IP':18s} {'E':>7s} {'Unk':>5s} {'Folds':>5s} {'Fold+':>6s} {'Real':>5s} {'Blk':>5s}")
    print(f"  {'-'*18} {'-'*7} {'-'*5} {'-'*5} {'-'*6} {'-'*5} {'-'*5}")
    for t in landscape:
        fold_str = f"+{t['fold_boost']:.1f}" if t['fold_boost'] > 0 else "     "
        print(f"  {t['ip']:18s} {t['entropy']:7.2f} "
              f"{t['unknowns']:5d} {t['n_folds']:5d} {fold_str:>6s} "
              f"{t['realized']:5d} {t['blocked']:5d}")

        # Print fold details for high-entropy targets
        if t['n_folds'] > 0 and t['fold_manager']:
            for fold in sorted(t['fold_manager'].all(),
                                key=lambda f: -f.gravity_weight())[:3]:
                print(f"    ↳ [{fold.fold_type:12s}] p={fold.discovery_probability:.2f} "
                      f"{fold.detail[:70]}")

    # ── Available instruments ──
    print(f"\n  [INSTRUMENTS]")
    for name, inst in instruments.items():
        status = "ready" if inst.available else "unavailable"
        print(f"    {name:20s} [{status:12s}] {inst.description[:50]}")

    # ── Follow the gradient ──
    print(f"\n  [GRADIENT] Following entropy gradient...\n")

    actions_taken = 0
    entropy_reduced = 0.0

    for t in landscape:
        if t["entropy"] == 0:
            continue  # Fully determined — no gravitational pull

        ip = t["ip"]
        fold_note = (f", {t['n_folds']} folds (+{t['fold_boost']:.1f})"
                     if t['n_folds'] > 0 else "")
        print(f"  → {ip} (E={t['entropy']:.2f}, "
              f"{t['unknowns']} unknowns{fold_note})")

        # Score each available instrument by entropy reduction potential
        candidates = []
        for name, inst in instruments.items():
            if not inst.available:
                continue

            potential = entropy_reduction_potential(
                inst, t["states"], t["applicable_wickets"], target_ip=ip)

            # Show penalty status
            if inst.failed_to_reduce(ip):
                print(f"    {name:20s} potential={potential:.1f} (penalized — no entropy reduction last time)")
            elif potential > 0:
                print(f"    {name:20s} potential={potential:.1f}")

            if potential > 0:
                candidates.append((potential, name, inst))

        if not candidates:
            print(f"    No instruments can reduce entropy here")
            continue

        # Select highest potential
        candidates.sort(key=lambda x: x[0], reverse=True)
        _, best_name, best_inst = candidates[0]

        print(f"    Selected: {best_name} (potential={candidates[0][0]:.1f})")

        # Execute
        E_before = t["entropy"]   # includes fold boost
        result = execute_instrument(best_inst, t["target"], run_id, out_path)

        # Measure entropy change — recompute including fold contribution
        # so delta_E reflects the full field energy shift, not just wicket changes
        new_states   = load_wicket_states(ip)
        E_after_base = field_entropy(new_states, t["applicable_wickets"])
        # Re-detect folds after instrument ran (structural folds may resolve
        # if a toolchain was created; temporal folds may refresh)
        new_fold_boost = t["fold_boost"]  # conservative: assume folds unchanged
        try:
            from skg.kernel.folds import FoldDetector, FoldManager
            new_fd = FoldDetector()
            new_folds = new_fd.detect_all(EVENTS_DIR, CVE_DIR, Path("/opt/skg"))
            new_fm = FoldManager()
            for f in new_folds:
                if ip in f.location or f.location.endswith(ip):
                    new_fm.add(f)
            new_fold_boost = new_fm.total_gravity_weight()
        except Exception:
            pass
        E_after = E_after_base + new_fold_boost
        delta_E = E_before - E_after

        if result.get("success"):
            actions_taken += 1
            entropy_reduced += delta_E

            if delta_E > 0:
                print(f"    ✓ Entropy reduced: {E_before:.2f} → {E_after:.2f} (ΔE={delta_E:+.2f})")
                resolved = result.get("unknowns_resolved", 0)
                if resolved:
                    print(f"      {resolved} unknowns collapsed")
            elif result.get("action") == "operator":
                # Operator-pending action (MSF proposal, SSH suggestion).
                # Do NOT record as a failure — the action hasn't been executed
                # yet.  Gravity should not penalise this instrument; it should
                # come back to it after the operator acts.  We record a neutral
                # entropy history entry (current E, not 999) so the penalty
                # trigger doesn't fire.
                print(f"    ⊕ Pending operator action: {result.get('suggestion', '')}")
                if result.get("proposal_id"):
                    print(f"      Proposal: {result['proposal_id']}")
                    print(f"      Approve:  skg proposals trigger {result['proposal_id']}")
                # Record current E (not a higher value) — neutral, not penalised
                best_inst.entropy_history.setdefault(ip, []).append(E_after)
            else:
                print(f"    ○ No entropy change (E={E_after:.2f})")
                # Genuine failure to reduce entropy — record double entry
                # so failed_to_reduce() fires and gravity shifts instruments
                best_inst.entropy_history.setdefault(ip, []).append(E_after)
                best_inst.entropy_history[ip].append(E_after)

        else:
            error = result.get("error", "unknown")
            print(f"    ✗ Failed: {error}")
            # Hard failure (connection refused, binary missing, etc.)
            # Record 999 so failed_to_reduce() fires immediately
            best_inst.entropy_history.setdefault(ip, []).append(999)

        # Only process top 3 targets per cycle to avoid rate limits
        if actions_taken >= 3:
            break

    # ── Cycle summary ──
    total_unknown   = sum(t["unknowns"] for t in landscape)
    total_folds     = sum(t["n_folds"]  for t in landscape)
    total_fold_boost = sum(t["fold_boost"] for t in landscape)
    total_entropy   = sum(t["entropy"]  for t in landscape)

    print(f"\n{'='*70}")
    print(f"  CYCLE {cycle_num} COMPLETE")
    print(f"  Actions : {actions_taken}")
    print(f"  ΔE      : {entropy_reduced:+.2f}")
    print(f"  Unknowns: {total_unknown}  Folds: {total_folds} (+{total_fold_boost:.2f})")
    print(f"  Total E : {total_entropy:.2f}  "
          f"(base {total_entropy - total_fold_boost:.2f} + "
          f"fold {total_fold_boost:.2f})")

    # Surface folds that need operator attention
    high_weight_folds = []
    for t in landscape:
        if t["fold_manager"]:
            for fold in t["fold_manager"].all():
                if fold.gravity_weight() >= 0.80:
                    high_weight_folds.append((t["ip"], fold))

    if high_weight_folds:
        print(f"\n  High-weight folds requiring attention:")
        for ip, fold in sorted(high_weight_folds,
                                key=lambda x: -x[1].gravity_weight())[:5]:
            print(f"    {ip:18s} [{fold.fold_type:12s}] p={fold.discovery_probability:.2f} "
                  f"Φ={fold.gravity_weight():.2f}")
            print(f"      {fold.detail[:90]}")

    print(f"{'='*70}")

    # Persist fold state for this cycle
    try:
        fold_state_dir = Path(out_dir) / "folds"
        fold_state_dir.mkdir(parents=True, exist_ok=True)
        for ip, fm in fold_manager_by_ip.items():
            fm.persist(fold_state_dir / f"folds_{ip.replace('.', '_')}.json")
    except Exception as exc:
        pass  # non-fatal

    return {
        "cycle":           cycle_num,
        "actions_taken":   actions_taken,
        "entropy_reduced": entropy_reduced,
        "total_entropy":   total_entropy,
        "total_unknowns":  total_unknown,
        "total_folds":     total_folds,
        "fold_boost":      round(total_fold_boost, 4),
    }


# ── Main loop ────────────────────────────────────────────────────────────

def gravity_field_loop(surface_path: str, out_dir: str, max_cycles: int = 5):
    """
    Run the gravity field dynamics.
    Continues until entropy stabilizes or max cycles reached.
    """
    instruments = detect_instruments()

    print(f"[SKG-GRAVITY] Gravity Field Engine v2")
    print(f"[SKG-GRAVITY] Surface: {surface_path}")
    print(f"[SKG-GRAVITY] Instruments: {sum(1 for i in instruments.values() if i.available)} available")
    print(f"[SKG-GRAVITY] Max cycles: {max_cycles}")

    prev_entropy = float('inf')

    for i in range(1, max_cycles + 1):
        result = gravity_field_cycle(surface_path, out_dir, i, instruments)

        current_entropy = result["total_entropy"]

        # Check for convergence — entropy stabilized
        if result["actions_taken"] == 0:
            print(f"\n[SKG-GRAVITY] No actions possible — field stabilized.")
            break

        if abs(current_entropy - prev_entropy) < 0.01 and i > 1:
            print(f"\n[SKG-GRAVITY] Entropy converged (ΔE < 0.01) — field stable.")
            break

        prev_entropy = current_entropy

        if i < max_cycles:
            print(f"\n[SKG-GRAVITY] Pausing 2s before next cycle...")
            time.sleep(2)

    print(f"\n[SKG-GRAVITY] Field dynamics complete.")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SKG Gravity Field Engine — entropy-driven field dynamics")
    parser.add_argument("--surface", default=None)
    parser.add_argument("--auto", action="store_true")
    parser.add_argument("--cycles", type=int, default=5)
    parser.add_argument("--out-dir", dest="out_dir",
                        default="/var/lib/skg/discovery")
    args = parser.parse_args()

    surface_path = args.surface
    if args.auto or not surface_path:
        surfaces = sorted(glob.glob("/var/lib/skg/discovery/surface_*.json"), key=os.path.getmtime)
        if not surfaces:
            print("[!] No surface files. Run discovery first.")
            sys.exit(1)
        surface_path = surfaces[-1]
        print(f"[SKG-GRAVITY] Using: {surface_path}")

    gravity_field_loop(surface_path, args.out_dir, max_cycles=args.cycles)


if __name__ == "__main__":
    main()
