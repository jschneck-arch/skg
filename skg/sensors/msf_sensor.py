"""
skg.sensors.msf_sensor
======================
Drains Metasploit Framework loot, session data, and credential captures
into SKG envelope events.

Transport priority:
  1. pymetasploit3 (MSF RPC, preferred — full loot/cred/session access)
  2. msfrpc subprocess (curl-based XML-RPC fallback)
  3. msfdb export (offline — parse loot dir directly from disk)

What gets mapped:
  MSF Loot type                    → wickets
  -----------------------------------------------
  host.os.uname                    → AD-01 (linux host enumerated)
  host.credentials                 → AD-08 (kerberoastable hash captured)
  windows.hashdump                 → AD-07 (password hashes)
  auxiliary.scanner.portscan       → AP-L7 (egress observable)
  exploit.multi.handler session    → CE-01 (code execution achieved)
  post/multi/gather.env_vars       → AP-L8 (JNDI env vars present)
  post/windows/gather.credentials  → AD-21 (LAPS absent implied)
  bloodhound_ingest                → AD-01..AD-25 (BloodHound data)
  nmap_xml                         → various (scanner results)

MSF session loot is also parsed for direct wicket signals:
  - Privileged session (is_admin)  → CE-01 realized
  - Session arch/platform          → domain context
  - Session info (hostname/ip)     → workload_id

Config (sensors.msf):
  host: 127.0.0.1
  port: 55553
  user: msf
  password: "${MSF_PASSWORD}"
  loot_dir: ~/.msf4/loot         # for offline fallback
  poll_interval_s: 60
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from skg.sensors import BaseSensor, envelope, precondition_payload, register
from skg.core.paths import SKG_STATE_DIR

log = logging.getLogger("skg.sensors.msf")

MSF_STATE_FILE = SKG_STATE_DIR / "msf_sensor.state.json"

# ── Loot type → (domain, wicket_id, label, realized, rank) ───────────────────

LOOT_WICKET_MAP = {
    # keyed on loot_type substring (lowercase match)
    "host.os.uname":               [("ad_lateral", "AD-01", "domain_user_enumerated",       True, 1)],
    "host.credentials":            [("ad_lateral", "AD-08", "kerberoastable_hash_captured",  True, 1)],
    "windows.hashdump":            [("ad_lateral", "AD-07", "ntlm_hash_available",           True, 1)],
    "smb.shares":                  [("ad_lateral", "AD-16", "smb_signing_disabled",          None, 4)],
    "bloodhound":                  [("ad_lateral", "AD-01", "domain_user_enumerated",        True, 3)],
    "auxiliary.scanner.portscan":  [("aprs",        "AP-L7", "outbound_egress_permits_callback", True, 4)],
    "post/multi/gather.env_vars":  [("aprs",        "AP-L8", "jndi_lookup_reachable",        None, 1)],
    "post/windows/gather.cred":    [("ad_lateral", "AD-21", "laps_absent",                  None, 1)],
    "exploit.multi.handler":       [("container_escape", "CE-01", "container_privileged",   True, 1)],
    "nmap_xml":                    [("aprs",        "AP-L7", "outbound_egress_permits_callback", None, 6)],
}

SESSION_WICKET_MAP = {
    # is_admin True → code execution with elevated privs
    "admin": [("container_escape", "CE-01", "container_privileged", True, 1)],
    # any session → execution context
    "any":   [("aprs", "AP-L4", "log4j_loaded_at_runtime", True, 1)],
}


def _loot_to_events(loot_items: list[dict], seen: set) -> list[dict]:
    """Convert MSF loot list to envelope events."""
    events = []
    for item in loot_items:
        loot_id = str(item.get("id", item.get("ltype", "")))
        if loot_id in seen:
            continue
        seen.add(loot_id)

        ltype = item.get("ltype", "").lower()
        host  = item.get("host",  item.get("address", "unknown"))
        workload_id = f"msf::{host}"
        pointer = f"msf://loot/{loot_id}"

        for (lkey, mappings) in LOOT_WICKET_MAP.items():
            if lkey in ltype:
                for (domain, wicket_id, label, realized, rank) in mappings:
                    events.append(envelope(
                        event_type="obs.attack.precondition",
                        source_id=f"msf_sensor/loot/{loot_id}",
                        toolchain=domain,
                        payload=precondition_payload(
                            wicket_id=wicket_id,
                            label=label,
                            domain=domain,
                            workload_id=workload_id,
                            realized=realized,
                            detail=f"MSF loot type: {item.get('ltype','')} @ {host}",
                        ),
                        evidence_rank=rank,
                        source_kind="msf_loot",
                        pointer=pointer,
                        confidence=0.95,
                    ))
    return events


def _session_to_events(sessions: dict, seen: set) -> list[dict]:
    """Convert MSF session dict to envelope events."""
    events = []
    for sid, sess in sessions.items():
        key = f"sess:{sid}"
        if key in seen:
            continue
        seen.add(key)

        host = sess.get("target_host", sess.get("via_exploit", "unknown"))
        workload_id = f"msf::sess::{host}"
        is_admin = sess.get("is_admin", False)

        # Any session = code execution achieved
        for (domain, wicket_id, label, realized, rank) in SESSION_WICKET_MAP["any"]:
            events.append(envelope(
                event_type="obs.attack.precondition",
                source_id=f"msf_sensor/session/{sid}",
                toolchain=domain,
                payload=precondition_payload(
                    wicket_id=wicket_id, label=label, domain=domain,
                    workload_id=workload_id, realized=realized,
                    detail=f"MSF session {sid} active on {host}",
                ),
                evidence_rank=rank,
                source_kind="msf_session",
                pointer=f"msf://session/{sid}",
                confidence=1.0,
            ))

        # Admin session → privileged execution
        if is_admin:
            for (domain, wicket_id, label, realized, rank) in SESSION_WICKET_MAP["admin"]:
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id=f"msf_sensor/session/{sid}/admin",
                    toolchain=domain,
                    payload=precondition_payload(
                        wicket_id=wicket_id, label=label, domain=domain,
                        workload_id=workload_id, realized=True,
                        detail=f"Elevated MSF session {sid} on {host}",
                    ),
                    evidence_rank=rank,
                    source_kind="msf_session",
                    pointer=f"msf://session/{sid}",
                    confidence=1.0,
                ))

    return events


def _parse_loot_dir(loot_dir: Path, seen: set) -> list[dict]:
    """Offline fallback: parse ~/.msf4/loot directory structure."""
    events = []
    if not loot_dir.exists():
        return events
    for loot_file in loot_dir.glob("*"):
        if not loot_file.is_file():
            continue
        fid = loot_file.name
        if fid in seen:
            continue
        seen.add(fid)
        name_lower = fid.lower()
        for (lkey, mappings) in LOOT_WICKET_MAP.items():
            if lkey.replace("/", "_").replace(".", "_") in name_lower.replace("-", "_"):
                host = "msf_loot_dir"
                for (domain, wicket_id, label, realized, rank) in mappings:
                    events.append(envelope(
                        event_type="obs.attack.precondition",
                        source_id=f"msf_sensor/loot_dir/{fid}",
                        toolchain=domain,
                        payload=precondition_payload(
                            wicket_id=wicket_id, label=label, domain=domain,
                            workload_id=f"msf::{host}", realized=realized,
                            detail=f"Loot dir file: {fid}",
                        ),
                        evidence_rank=rank,
                        source_kind="msf_loot_file",
                        pointer=str(loot_file),
                        confidence=0.70,
                    ))
    return events


@register("msf")
class MsfSensor(BaseSensor):
    """
    Drains MSF loot and session data into SKG envelope events.
    Tries RPC first, falls back to loot dir scan.
    """

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.host     = cfg.get("host", os.environ.get("MSF_HOST", "127.0.0.1"))
        self.port     = int(cfg.get("port", os.environ.get("MSF_PORT", "55553")))
        self.user     = cfg.get("user", "msf")
        self.password = os.path.expandvars(cfg.get("password", os.environ.get("MSF_PASSWORD", "msf")))
        self.loot_dir = Path(os.path.expanduser(cfg.get("loot_dir", "~/.msf4/loot")))
        self._state   = self._load_state()

    def _load_state(self) -> dict:
        if MSF_STATE_FILE.exists():
            try:
                return json.loads(MSF_STATE_FILE.read_text())
            except Exception:
                pass
        return {"seen": []}

    def _save_state(self):
        MSF_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._state["seen"] = list(self._seen)
        MSF_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def run(self) -> list[str]:
        self._seen: set = set(self._state.get("seen", []))
        events = []

        # Try pymetasploit3 RPC
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            client = MsfRpcClient(
                self.password, server=self.host, port=self.port,
                username=self.user, ssl=True
            )
            # Drain loot
            try:
                loot = list(client.db.loots.list)
                events.extend(_loot_to_events(loot, self._seen))
                log.info(f"[msf] RPC: {len(loot)} loot items")
            except Exception as exc:
                log.debug(f"MSF loot list failed: {exc}")

            # Drain sessions
            try:
                sessions = dict(client.sessions.list)
                events.extend(_session_to_events(sessions, self._seen))
                log.info(f"[msf] RPC: {len(sessions)} sessions")
            except Exception as exc:
                log.debug(f"MSF session list failed: {exc}")

        except ImportError:
            log.debug("pymetasploit3 not available, trying loot dir")
            events.extend(_parse_loot_dir(self.loot_dir, self._seen))
        except Exception as exc:
            log.debug(f"MSF RPC unavailable ({exc}), falling back to loot dir")
            events.extend(_parse_loot_dir(self.loot_dir, self._seen))

        self._save_state()
        return self.emit(events)
