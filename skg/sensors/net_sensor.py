"""
skg.sensors.net_sensor
======================
Passive network capture sensor using tshark.

No root required after: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark

What gets observed and mapped:
  Network observation                   → wicket
  ─────────────────────────────────────────────────
  SSH connection attempt/success        → HO-01, HO-02
  SSH banner exchange                   → HO-02
  SMB traffic                           → AD-16 (signing unknown → check)
  Kerberos AS-REQ / TGT request         → AD-01 (domain user active)
  Kerberos AS-REP (no preauth)          → AD-08 (ASREPRoastable)
  LDAP bind / query                     → AD-01
  DNS query for domain controller       → AD-01
  HTTP/HTTPS to known C2 patterns       → AP-L7 (egress callback)
  JNDI lookup string in HTTP            → AP-L8
  Docker API (2375/2376) traffic        → CE-04 (docker exposed)
  Outbound connection on unusual port   → AP-L7

Strategy:
  - Short capture windows (30s by default) on a sweep schedule
  - tshark writes PDML/JSON, we parse flow summaries
  - No full packet storage — metadata only
  - Interface auto-detected from default route

Config (sensors.net):
  interface: auto          # or enp3s0, wlp2s0, etc.
  capture_duration_s: 30
  capture_filter: ""       # BPF filter (empty = all traffic)
  enabled: true
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.sensors import BaseSensor, envelope, precondition_payload, register
from skg.core.paths import SKG_STATE_DIR

log = logging.getLogger("skg.sensors.net")

NET_STATE_FILE = SKG_STATE_DIR / "net_sensor.state.json"

# ── Port → service context ────────────────────────────────────────────────────
PORT_CONTEXT = {
    22:   ("HO-02", "ssh_service_exposed",         "host",           True,  5),
    445:  ("AD-16", "smb_signing_disabled",         "ad_lateral",     None,  3),
    139:  ("AD-16", "smb_signing_disabled",         "ad_lateral",     None,  3),
    389:  ("AD-01", "domain_user_enumerated",       "ad_lateral",     None,  3),
    636:  ("AD-01", "domain_user_enumerated",       "ad_lateral",     None,  3),
    88:   ("AD-01", "domain_user_enumerated",       "ad_lateral",     None,  4),
    2375: ("CE-04", "docker_api_exposed",           "container_escape", True, 7),
    2376: ("CE-04", "docker_api_exposed",           "container_escape", True, 7),
    4444: ("AP-L7", "outbound_egress_permits_callback", "aprs",       True,  6),
    1099: ("AP-L7", "outbound_egress_permits_callback", "aprs",       None,  5),
    8080: ("HO-01", "host_reachable_and_responsive","host",           True,  4),
    443:  ("HO-01", "host_reachable_and_responsive","host",           True,  4),
    80:   ("HO-01", "host_reachable_and_responsive","host",           True,  3),
}

# ── Protocol pattern detectors ────────────────────────────────────────────────

# Kerberos AS-REP without preauth (ASREPRoast opportunity)
RE_ASREP = re.compile(r'KRB5.*AS-REP', re.I)
# JNDI lookup in HTTP data
RE_JNDI  = re.compile(r'\$\{jndi:', re.I)
# DNS query for _kerberos, _ldap, _gc (DC discovery)
RE_DC_DNS = re.compile(r'_(?:kerberos|ldap|gc)\._tcp', re.I)
# SSH banner
RE_SSH_BANNER = re.compile(r'SSH-\d\.\d-\S+')
# SMB signing negotiation
RE_SMB_NOSIGN = re.compile(r'SecurityMode.*0x00', re.I)


def _get_default_interface() -> str:
    """Get the interface used for the default route."""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r'dev\s+(\S+)', result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    # Fallback: first non-loopback interface
    try:
        result = subprocess.run(['ip', '-o', 'link', 'show'],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if 'LOOPBACK' not in line and 'lo:' not in line:
                m = re.search(r'^\d+:\s+(\S+):', line)
                if m:
                    return m.group(1).rstrip('@').split('@')[0]
    except Exception:
        pass
    return "enp3s0"


def _run_tshark(interface: str, duration: int,
                capture_filter: str = "") -> str | None:
    """
    Run tshark for a short capture window.
    Returns CSV fields output or None on failure.
    Fields: ip.src,ip.dst,tcp.dstport,tcp.srcport,udp.dstport,
            ssh.protocol,kerberos.msg_type,http.request.uri,
            dns.qry.name,_ws.col.Protocol
    """
    cmd = [
        "sudo", "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.srcport",
        "-e", "udp.dstport",
        "-e", "udp.srcport",
        "-e", "ssh.protocol",
        "-e", "kerberos.msg_type",
        "-e", "http.request.uri",
        "-e", "dns.qry.name",
        "-e", "_ws.col.Protocol",
        "-E", "separator=|",
        "-E", "occurrence=f",
    ]
    if capture_filter:
        cmd += ["-f", capture_filter]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 15,
        )
        if result.returncode not in (0, 1):
            if "permission denied" in result.stderr.lower():
                log.warning("[net] tshark permission denied — "
                            "run: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark")
                return None
            log.debug(f"[net] tshark stderr: {result.stderr[:200]}")
        return result.stdout if result.stdout.strip() else None
    except subprocess.TimeoutExpired:
        log.debug("[net] tshark capture timed out")
        return None
    except FileNotFoundError:
        log.warning("[net] tshark not found — install: pacman -S wireshark-cli")
        return None
    except Exception as e:
        log.debug(f"[net] tshark failed: {e}")
        return None


def _parse_tshark_fields(raw: str) -> list[dict]:
    """
    Parse tshark pipe-delimited fields output into flow dicts.
    Columns: src|dst|tcp.dport|tcp.sport|udp.dport|udp.sport|
             ssh|krb_type|http_uri|dns_name|proto
    """
    flows = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split('|')
        if len(parts) < 11:
            parts += [''] * (11 - len(parts))
        flow = {
            "src":      parts[0].strip(),
            "dst":      parts[1].strip(),
            "dport":    _first_int(parts[2]),
            "sport":    _first_int(parts[3]),
            "udp_dport": _first_int(parts[4]),
            "udp_sport": _first_int(parts[5]),
            "ssh":      parts[6].strip() or None,
            "krb_type": parts[7].strip() or None,
            "http_uri": parts[8].strip() or None,
            "dns_name": parts[9].strip() or None,
            "proto":    parts[10].strip(),
        }
        # Use UDP port if no TCP port
        if not flow["dport"] and flow["udp_dport"]:
            flow["dport"] = flow["udp_dport"]
        if flow["src"] or flow["dst"]:
            flows.append(flow)
    return flows


def _first_int(val) -> int:
    if not val:
        return 0
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return 0


def _flows_to_events(flows: list[dict], seen_flows: set) -> list[dict]:
    """Convert parsed flows to SKG wicket events."""
    events   = []
    # Deduplicate by (src, dst, dport) — don't emit the same flow twice
    seen_new = set()

    for flow in flows:
        src   = flow["src"]
        dst   = flow["dst"]
        dport = flow["dport"]
        sport = flow["sport"]
        proto = flow["proto"].upper() if flow["proto"] else ""

        flow_key = f"{src}→{dst}:{dport}"
        if flow_key in seen_flows or flow_key in seen_new:
            continue
        seen_new.add(flow_key)

        workload_id = f"net::{dst}" if dst else f"net::{src}"
        pointer     = f"net://flow/{flow_key}"

        # Port-based wicket mapping
        if dport in PORT_CONTEXT:
            wid, label, domain, realized, rank = PORT_CONTEXT[dport]
            events.append(_ev(wid, label, domain, workload_id,
                               realized, rank,
                               f"{proto} {src}→{dst}:{dport}",
                               pointer))

        # SSH banner seen
        if flow["ssh"]:
            banner = flow["ssh"]
            events.append(_ev("HO-02", "ssh_service_exposed",
                               "host", workload_id, True, 6,
                               f"SSH banner: {banner}",
                               pointer))

        # Kerberos AS-REP (msg_type=11) without preauth → ASREPRoastable
        if flow["krb_type"] == "11":
            events.append(_ev("AD-08", "kerberoastable_hash_captured",
                               "ad_lateral", workload_id, True, 6,
                               f"Kerberos AS-REP from {src} — no preauth",
                               pointer))

        # Kerberos AS-REQ (msg_type=10) → domain user active
        if flow["krb_type"] == "10":
            events.append(_ev("AD-01", "domain_user_enumerated",
                               "ad_lateral", workload_id, None, 4,
                               f"Kerberos AS-REQ from {src}",
                               pointer))

        # DNS DC discovery
        if flow["dns_name"] and RE_DC_DNS.search(flow["dns_name"]):
            events.append(_ev("AD-01", "domain_user_enumerated",
                               "ad_lateral", workload_id, None, 4,
                               f"DC DNS query: {flow['dns_name']}",
                               pointer))

        # JNDI in HTTP URI
        if flow["http_uri"] and RE_JNDI.search(flow["http_uri"]):
            events.append(_ev("AP-L8", "jndi_lookup_reachable",
                               "aprs", workload_id, True, 8,
                               f"JNDI lookup in HTTP: {flow['http_uri'][:80]}",
                               pointer,
                               confidence=0.95))

        # Unusual outbound port → possible C2 egress
        if dport in (4444, 4445, 8443, 1337, 31337) and src:
            events.append(_ev("AP-L7", "outbound_egress_permits_callback",
                               "aprs", workload_id, True, 6,
                               f"Outbound to {dst}:{dport} — possible C2",
                               pointer))

        # Docker API exposed
        if dport in (2375, 2376):
            events.append(_ev("CE-04", "docker_api_exposed",
                               "container_escape", workload_id, True, 8,
                               f"Docker API traffic to {dst}:{dport}",
                               pointer,
                               confidence=0.95))

    seen_flows.update(seen_new)
    return events


def _ev(wicket_id, label, domain, workload_id, realized, rank,
        detail, pointer, confidence=0.85):
    return envelope(
        event_type="obs.attack.precondition",
        source_id=f"net_sensor/{wicket_id}/{workload_id}",
        toolchain=domain,
        payload=precondition_payload(
            wicket_id=wicket_id, label=label, domain=domain,
            workload_id=workload_id, realized=realized,
            detail=detail,
        ),
        evidence_rank=rank,
        source_kind="net_capture",
        pointer=pointer,
        confidence=confidence,
    )


# ── Sensor ────────────────────────────────────────────────────────────────────

@register("net")
class NetSensor(BaseSensor):
    """
    Passive network capture sensor.
    Short tshark windows on each sweep, metadata only.
    """

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.interface  = cfg.get("interface", "auto")
        self.duration   = int(cfg.get("capture_duration_s", 30))
        self.bpf_filter = cfg.get("capture_filter", "")
        self._state     = self._load_state()

    def _load_state(self) -> dict:
        if NET_STATE_FILE.exists():
            try:
                return json.loads(NET_STATE_FILE.read_text())
            except Exception:
                pass
        return {"seen_flows": []}

    def _save_state(self, seen_flows: set):
        # Keep last 1000 flows to bound state file size
        NET_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        flows_list = list(seen_flows)[-1000:]
        self._state["seen_flows"] = flows_list
        NET_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def run(self) -> list[str]:
        iface = (self.interface if self.interface != "auto"
                 else _get_default_interface())
        log.info(f"[net] capture: {iface} for {self.duration}s")

        raw = _run_tshark(iface, self.duration, self.bpf_filter)
        if not raw:
            log.debug("[net] no capture output")
            return []

        flows = _parse_tshark_fields(raw)
        log.info(f"[net] {len(flows)} flows parsed")

        seen = set(self._state.get("seen_flows", []))
        events = _flows_to_events(flows, seen)
        log.info(f"[net] {len(events)} wicket events")

        self._save_state(seen)
        return self.emit(events)
