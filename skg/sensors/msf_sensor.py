"""
skg.sensors.msf_sensor
======================
Console-based MSF sensor. No database required.

Transport: pymetasploit3 RPC console
  - Creates a persistent console session
  - Runs modules directly, captures stdout
  - Parses output into SKG wicket events
  - No msfdb/postgres dependency

Two modes:
  1. DRAIN — read existing session list and any pending console output
  2. COLLECT — run specific auxiliary modules against unknown wicket nodes
     (only when operator has set engagement_mode: active on the target)

Wicket mapping:
  MSF output pattern                    → wicket
  ─────────────────────────────────────────────────
  open port (portscan output)           → HO-01, HO-02
  SSH banner / version                  → HO-02
  valid credential                      → HO-03
  active session                        → HO-10 (initial access / code exec achieved)
  admin/root session                    → HO-14 (privesc realized)
  SMB signing disabled                  → AD-16
  Kerberos enumeration result           → AD-01
  credential capture in session         → AD-08
  nmap XML via console                  → HO-01 + service wickets
  vuln scan hit (auxiliary/scanner)     → domain-specific wicket

Config (sensors.msf):
  host: 127.0.0.1
  port: 55553
  user: msf
  password: "${MSF_PASSWORD}"
  ssl: true
  console_timeout_s: 30
  engagement_mode: passive   # passive | active
                             # passive: drain sessions only
                             # active:  run collection modules (operator authorized)
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.identity import parse_workload_ref
from skg.sensors import BaseSensor, register
from skg_core.config.paths import SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR
try:
    from skg_protocol.events import (
        build_event_envelope as envelope,
        build_precondition_payload as precondition_payload,
    )
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import envelope, precondition_payload

log = logging.getLogger("skg.sensors.msf")

MSF_STATE_FILE = SKG_STATE_DIR / "msf_sensor.state.json"


def _targets_config_path() -> Path:
    candidates = [
        SKG_CONFIG_DIR / "targets.yaml",
        SKG_HOME / "config" / "targets.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _workload_target_candidates(workload_id: str) -> set[str]:
    text = str(workload_id or "").strip()
    if not text:
        return set()
    candidates = {text}
    parsed = parse_workload_ref(text)
    candidates.update({
        str(parsed.get("identity_key", "") or "").strip(),
        str(parsed.get("host", "") or "").strip(),
        str(parsed.get("manifestation_key", "") or "").strip(),
    })
    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    if ip_match:
        candidates.add(ip_match.group(0))
    return {candidate for candidate in candidates if candidate}

# ── Output parsers ────────────────────────────────────────────────────────────

# TCP portscan: "[+] 192.168.1.1:22 - TCP OPEN"
RE_PORT_OPEN  = re.compile(
    r'\[\+\]\s+([\d\.]+):(\d+)\s+-\s+(?:TCP\s+)?OPEN', re.I)

# SSH version banner: "[+] 192.168.1.1:22 SSH-2.0-OpenSSH_8.9"
RE_SSH_BANNER = re.compile(
    r'\[\+\]\s+([\d\.]+):\d+\s+(SSH-[\d\.]+-\S+)', re.I)

# Valid credential: "[+] 192.168.1.1:22 - Success: 'user:pass'"
RE_VALID_CRED = re.compile(
    r'\[\+\]\s+([\d\.]+):\d+\s+-\s+Success.*?[\'"](\S+:\S+)[\'"]', re.I)

# SMB signing: "[-] Signing is required" or "[+] not required"
RE_SMB_SIGNING_OFF = re.compile(
    r'\[\+\].*signing.*not required', re.I)

# Session opened: "[*] Meterpreter session 1 opened"
RE_SESSION_OPEN = re.compile(
    r'session\s+(\d+)\s+opened.*?([\d\.]+)', re.I)

# Kerberos user enum: "[+] Found user: administrator"
RE_KERB_USER = re.compile(
    r'\[\+\]\s+(?:Found\s+)?[Uu]ser[:\s]+(\S+)', re.I)

# Vuln confirmed: "[+] ... is vulnerable"
RE_VULN_CONFIRMED = re.compile(
    r'\[\+\].+?is\s+vulnerable', re.I)

RE_ANSI = re.compile(r'\x1b\[[0-9;]*m')

# Dir scanner/web enum: "[+] Found http://host:80/phpMyAdmin/ 200 (host)"
RE_FOUND_HTTP = re.compile(
    r'\[\+\]\s+Found\s+(https?://\S+?)\s+(\d{3})\s+\(([\d\.]+)\)', re.I)

# Resource script / module failures that should be surfaced in reports
RE_MODULE_LOAD_FAIL = re.compile(
    r'Failed to load module:\s+(\S+)', re.I)
RE_UNKNOWN_COMMAND = re.compile(
    r'Unknown command:\s+(\S+)', re.I)


def _parse_console_output(output: str, workload_id: str,
                           module_name: str = "") -> list[dict]:
    """
    Parse MSF console output into SKG wicket events.
    Pure text parsing — no database required.
    """
    events = []
    clean = RE_ANSI.sub("", output)
    lines  = clean.splitlines()

    for line in lines:
        # Open port → host reachable + service exposed
        m = RE_PORT_OPEN.search(line)
        if m:
            host, port = m.group(1), m.group(2)
            wid = f"msf::console::{host}"
            events.append(_ev("HO-01", "host_reachable_and_responsive",
                               "host", wid, True, 5,
                               f"Port {port} open on {host}",
                               f"msf://console/{module_name}"))
            if port in ("22", "2222"):
                events.append(_ev("HO-02", "ssh_service_exposed",
                                   "host", wid, True, 5,
                                   f"SSH on {host}:{port}",
                                   f"msf://console/{module_name}"))
            elif port in ("445", "139"):
                events.append(_ev("AD-16", "smb_signing_disabled",
                                   "ad_lateral", wid, None, 4,
                                   f"SMB on {host}:{port} — signing unknown",
                                   f"msf://console/{module_name}"))
            continue

        # SSH banner → SSH confirmed
        m = RE_SSH_BANNER.search(line)
        if m:
            host, banner = m.group(1), m.group(2)
            wid = f"msf::console::{host}"
            events.append(_ev("HO-02", "ssh_service_exposed",
                               "host", wid, True, 6,
                               f"SSH banner: {banner}",
                               f"msf://console/{module_name}"))
            continue

        # Valid credential → SSH credential valid
        m = RE_VALID_CRED.search(line)
        if m:
            host, cred = m.group(1), m.group(2)
            wid = f"msf::console::{host}"
            events.append(_ev("HO-03", "ssh_credential_valid",
                               "host", wid, True, 7,
                               f"Valid credential on {host}: {cred[:20]}",
                               f"msf://console/{module_name}",
                               confidence=1.0))
            continue

        # SMB signing disabled
        if RE_SMB_SIGNING_OFF.search(line):
            events.append(_ev("AD-16", "smb_signing_disabled",
                               "ad_lateral", workload_id, True, 5,
                               "SMB signing not required",
                               f"msf://console/{module_name}"))
            continue

        # Session opened
        m = RE_SESSION_OPEN.search(line)
        if m:
            sid, host = m.group(1), m.group(2)
            wid = f"msf::sess::{host}"
            events.append(_ev("HO-10", "elevated_privileges",
                               "host", wid, True, 8,
                               f"MSF session {sid} on {host}",
                               f"msf://session/{sid}",
                               confidence=1.0))
            continue

        # Kerberos user found
        m = RE_KERB_USER.search(line)
        if m and 'kerb' in module_name.lower():
            user = m.group(1)
            events.append(_ev("AD-01", "domain_user_enumerated",
                               "ad_lateral", workload_id, True, 4,
                               f"Kerberos user: {user}",
                               f"msf://console/{module_name}"))
            continue

        # Vuln confirmed
        if RE_VULN_CONFIRMED.search(line):
            events.append(_ev("HO-11", "vuln_packages_installed",
                               "host", workload_id, True, 7,
                               f"Vulnerability confirmed: {line.strip()[:120]}",
                               f"msf://console/{module_name}"))
            continue

        # HTTP path discovery from dir_scanner and similar modules.
        # Feed it back as web reachability + exposed path evidence.
        m = RE_FOUND_HTTP.search(line)
        if m:
            url, status_code, host = m.group(1), m.group(2), m.group(3)
            wid = f"msf::console::{host}"
            detail = f"Metasploit discovered {url} ({status_code})"
            events.append(_ev("WB-01", "http_service_reachable",
                               "web", wid, True, 4,
                               f"Web service responded during MSF scan: {url}",
                               f"msf://console/{module_name}"))
            if status_code in {"200", "401", "403"}:
                events.append(_ev("WB-05", "sensitive_paths_exposed",
                                   "web", wid, True, 5,
                                   detail,
                                   f"msf://console/{module_name}"))
            continue

    return events


def summarize_console_output(output: str) -> dict[str, list[str]]:
    """
    Extract a compact human-readable summary from MSF output.
    Used for proposal reporting even when no structured events are emitted.
    """
    clean = RE_ANSI.sub("", output or "")
    findings: list[str] = []
    errors: list[str] = []
    for line in clean.splitlines():
        m = RE_FOUND_HTTP.search(line)
        if m:
            findings.append(f"{m.group(1)} [{m.group(2)}]")
            continue
        m = RE_MODULE_LOAD_FAIL.search(line)
        if m:
            errors.append(f"module load failed: {m.group(1)}")
            continue
        m = RE_UNKNOWN_COMMAND.search(line)
        if m:
            errors.append(f"unknown command after module failure: {m.group(1)}")
            continue
        if RE_VULN_CONFIRMED.search(line):
            findings.append(line.strip()[:140])
    return {
        "findings": findings[:10],
        "errors": errors[:10],
    }


def _ev(wicket_id, label, domain, workload_id, realized, rank,
        detail, pointer, confidence=0.9):
    return envelope(
        event_type="obs.attack.precondition",
        source_id=f"msf_sensor/console/{wicket_id}",
        toolchain=domain,
        payload=precondition_payload(
            wicket_id=wicket_id, label=label, domain=domain,
            workload_id=workload_id, realized=realized,
            detail=detail,
        ),
        evidence_rank=rank,
        source_kind="msf_console",
        pointer=pointer,
        confidence=confidence,
    )


# ── MSF console runner ────────────────────────────────────────────────────────

class MsfConsole:
    """Thin wrapper around pymetasploit3 console with output draining."""

    def __init__(self, client, timeout_s: int = 30):
        self._c    = client
        self._to   = timeout_s
        self._con  = None

    def __enter__(self):
        self._con = self._c.consoles.console()
        # Drain welcome banner
        time.sleep(1)
        self._con.read()
        return self

    def __exit__(self, *_):
        try:
            self._con.destroy()
        except Exception:
            pass

    def run(self, cmd: str, wait: float = 3.0) -> str:
        """Run a console command and return full output."""
        self._con.write(cmd + '\n')
        time.sleep(wait)
        output = ''
        deadline = time.time() + self._to
        while time.time() < deadline:
            r = self._con.read()
            output += r.get('data', '')
            if not r.get('busy', True):
                break
            time.sleep(0.5)
        return output

    def run_module(self, module: str, options: dict[str, str],
                   wait: float = 15.0) -> str:
        """Use a module, set options, run, return output."""
        self.run(f'use {module}', wait=1.0)
        for k, v in options.items():
            self.run(f'set {k} {v}', wait=0.5)
        return self.run('run', wait=wait)


# ── Collection module definitions ─────────────────────────────────────────────
# Each entry: wicket_id that triggers it → module + options template + parse wait
# Only runs when engagement_mode == "active" and wicket is unknown

COLLECTION_MODULES = {
    # Unknown HO-01: is target reachable?
    "HO-01": {
        "module":  "auxiliary/scanner/portscan/tcp",
        "options": {"RHOSTS": "{target}", "PORTS": "22,80,443,445,3389,8080",
                    "THREADS": "10"},
        "wait":    10.0,
    },
    # Unknown HO-02: is SSH exposed?
    "HO-02": {
        "module":  "auxiliary/scanner/ssh/ssh_version",
        "options": {"RHOSTS": "{target}", "THREADS": "5"},
        "wait":    10.0,
    },
    # Unknown HO-03: can we authenticate?
    "HO-03": {
        "module":  "auxiliary/scanner/ssh/ssh_login",
        "options": {"RHOSTS": "{target}", "USER_FILE": "/usr/share/metasploit-framework/data/wordlists/unix_users.txt",
                    "PASS_FILE": "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt",
                    "STOP_ON_SUCCESS": "true", "THREADS": "5"},
        "wait":    30.0,
    },
    # Unknown AD-16: is SMB signing disabled?
    "AD-16": {
        "module":  "auxiliary/scanner/smb/smb_signing",
        "options": {"RHOSTS": "{target}", "THREADS": "5"},
        "wait":    10.0,
    },
}


# ── Sensor ────────────────────────────────────────────────────────────────────

@register("msf")
class MsfSensor(BaseSensor):
    """
    Console-based MSF sensor. No database required.
    Drains sessions + runs collection modules for unknown wickets.
    """

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.host            = cfg.get("host", os.environ.get("MSF_HOST", "127.0.0.1"))
        self.port            = int(cfg.get("port", os.environ.get("MSF_PORT", "55553")))
        self.user            = cfg.get("user", "msf")
        self.password        = os.path.expandvars(
                                   cfg.get("password",
                                           os.environ.get("MSF_PASSWORD", "")))
        self.ssl             = cfg.get("ssl", True)
        self.timeout_s       = int(cfg.get("console_timeout_s", 30))
        self.engagement_mode = cfg.get("engagement_mode", "passive")
        self._state          = self._load_state()

    def _load_state(self) -> dict:
        if MSF_STATE_FILE.exists():
            try:
                return json.loads(MSF_STATE_FILE.read_text())
            except Exception:
                pass
        return {"seen_sessions": [], "last_sweep": ""}

    def _save_state(self, seen_sessions: list):
        MSF_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._state["seen_sessions"] = seen_sessions
        self._state["last_sweep"]    = datetime.now(timezone.utc).isoformat()
        MSF_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def _connect(self):
        from pymetasploit3.msfrpc import MsfRpcClient
        return MsfRpcClient(
            self.password,
            server=self.host,
            port=self.port,
            username=self.user,
            ssl=self.ssl,
        )

    def _drain_sessions(self, client, seen: set) -> list[dict]:
        """Drain active MSF sessions into wicket events."""
        events = []
        try:
            sessions = dict(client.sessions.list)
            log.info(f"[msf] sessions: {len(sessions)}")
            for sid, sess in sessions.items():
                key = f"sess:{sid}"
                if key in seen:
                    continue
                host = sess.get("target_host",
                               sess.get("tunnel_peer", "unknown").split(":")[0])
                wid  = f"msf::sess::{host}"

                # Any session = initial access / code execution on host
                events.append(_ev("HO-10", "elevated_privileges",
                                   "host", wid, True, 8,
                                   f"MSF session {sid} active on {host} "
                                   f"via {sess.get('via_exploit','?')}",
                                   f"msf://session/{sid}",
                                   confidence=1.0))
                seen.add(key)

                # Admin session = privilege escalation realized
                if sess.get("is_admin") or sess.get("via_exploit", "").endswith("admin"):
                    events.append(_ev("HO-14", "local_privesc_sudo_possible",
                                       "host", wid, True, 8,
                                       f"Elevated session {sid} on {host}",
                                       f"msf://session/{sid}",
                                       confidence=1.0))

                # Session type context
                platform = sess.get("platform", "")
                if "windows" in platform.lower():
                    events.append(_ev("AD-01", "domain_user_enumerated",
                                       "ad_lateral", wid, None, 3,
                                       f"Windows session {sid} — AD enumeration possible",
                                       f"msf://session/{sid}"))
        except Exception as e:
            log.debug(f"[msf] session drain failed: {e}")
        return events

    def _run_collection(self, client, unknown_wickets: list[str],
                        targets: list[str]) -> list[dict]:
        """
        Run collection modules for unknown wickets.
        Only called when engagement_mode == 'active'.
        Each execution is logged to the audit trail.
        """
        if not targets:
            log.info("[msf] active mode but no targets configured — skipping")
            return []

        events = []
        audit  = []

        with MsfConsole(client, timeout_s=self.timeout_s) as con:
            for wicket_id in unknown_wickets:
                mod_def = COLLECTION_MODULES.get(wicket_id)
                if not mod_def:
                    continue
                for target in targets:
                    module = mod_def["module"]
                    opts   = {k: v.replace("{target}", target)
                              for k, v in mod_def["options"].items()}
                    log.info(f"[msf] collecting {wicket_id} via {module} against {target}")

                    # Audit entry — every execution recorded
                    audit_entry = {
                        "timestamp":    datetime.now(timezone.utc).isoformat(),
                        "wicket_id":    wicket_id,
                        "module":       module,
                        "options":      opts,
                        "target":       target,
                        "authorized_by": "operator",  # operator set engagement_mode=active
                    }

                    try:
                        output = con.run_module(module, opts, wait=mod_def["wait"])
                        audit_entry["output_chars"] = len(output)
                        parsed = _parse_console_output(
                            output, f"msf::{target}", module)
                        events.extend(parsed)
                        audit_entry["events_emitted"] = len(parsed)
                        log.info(f"[msf] {wicket_id}: {len(parsed)} events from {module}")
                    except Exception as e:
                        audit_entry["error"] = str(e)
                        log.warning(f"[msf] module {module} failed: {e}")

                    audit.append(audit_entry)

        # Write audit log
        if audit:
            audit_file = (SKG_STATE_DIR / "msf_audit" /
                          f"msf_audit_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
            audit_file.parent.mkdir(parents=True, exist_ok=True)
            audit_file.write_text(json.dumps(audit, indent=2))
            log.info(f"[msf] audit: {len(audit)} entries → {audit_file}")

        return events

    def _get_unknown_wickets(self) -> tuple[list[str], list[str]]:
        """
        Read latest interp files to find unknown wickets and their targets.
        Returns (unknown_wicket_ids, target_hosts).
        """
        import glob
        unknown = set()
        targets = set()
        interp_dir = SKG_STATE_DIR / "interp"
        for f in sorted(interp_dir.glob("host_*.json")):
            try:
                d = json.loads(Path(f).read_text())
                for w in d.get("unknown", []):
                    unknown.add(w)
                # Extract target from workload_id or attack_path options
                wid = d.get("workload_id", "")
                if wid and wid != "cve_sensor::global":
                    # workload_id maps to a target — check targets.yaml
                    targets.add(wid)
            except Exception:
                continue
        return list(unknown), list(targets)

    def _resolve_targets(self, workload_ids: list[str]) -> list[str]:
        """Map workload_ids to IP addresses from targets.yaml."""
        requested = set()
        for workload_id in workload_ids or []:
            requested.update(_workload_target_candidates(workload_id))
        if not requested:
            return []

        resolved: list[str] = []
        for candidate in sorted(requested):
            if "::" not in candidate:
                resolved.append(candidate)

        targets_file = _targets_config_path()
        if not targets_file.exists():
            return list(dict.fromkeys(resolved))
        try:
            import yaml

            data = yaml.safe_load(targets_file.read_text()) or {}
            targets = data if isinstance(data, list) else data.get("targets", [])
            for target in targets:
                host = str(target.get("host") or target.get("ip") or "").strip()
                if not host:
                    continue
                target_keys = {
                    host,
                    str(target.get("ip") or "").strip(),
                    str(target.get("host") or "").strip(),
                    str(target.get("workload_id") or "").strip(),
                }
                target_url = str(target.get("url") or "")
                if target_keys & requested or any(token and token in target_url for token in requested):
                    resolved.append(host)
        except Exception:
            pass
        return list(dict.fromkeys(resolved))

    def run(self) -> list[str]:
        if not self.password:
            log.warning("[msf] MSF_PASSWORD not set — skipping")
            return []

        events      = []
        seen        = set(self._state.get("seen_sessions", []))

        try:
            client = self._connect()
            log.info(f"[msf] connected: MSF {client.core.version.get('version','?')}")

            # Always drain sessions
            events.extend(self._drain_sessions(client, seen))

            # Active collection if authorized
            if self.engagement_mode == "active":
                unknown, workload_ids = self._get_unknown_wickets()
                if unknown:
                    targets = self._resolve_targets(workload_ids)
                    log.info(f"[msf] active: {len(unknown)} unknown wickets, "
                             f"{len(targets)} targets")
                    events.extend(self._run_collection(client, unknown, targets))
                else:
                    log.info("[msf] active mode: no unknown wickets — nothing to collect")

        except ImportError:
            log.warning("[msf] pymetasploit3 not installed")
        except Exception as e:
            log.warning(f"[msf] RPC unavailable: {e}")

        self._save_state(list(seen))
        return self.emit(events)
