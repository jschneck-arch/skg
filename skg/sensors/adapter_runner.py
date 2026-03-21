"""
skg.sensors.adapter_runner
===========================
Routes collected data through toolchain adapters.

This is the intelligence bridge. Sensors collect raw data.
Adapters parse it into wicket observations. This module wires them together.

Every adapter follows the same contract:
  - Takes collected data (file paths or in-memory) 
  - Writes NDJSON events to an output path
  - Returns the output path

The runner then reads those events and returns them as dicts
for the sensor to emit into EVENTS_DIR under the envelope schema.

Adapter dispatch table:
  domain + collection_type → adapter module + call convention

Collection types:
  usb_drop      — drop directory from USB/autorun agent
  ssh_collect   — paramiko live SSH collection  
  bloodhound    — BloodHound JSON directory
  container_inspect — docker inspect JSON
  agent_callback — HTTP agent payload (deserialized dict)
  net_sandbox   — network egress test results
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import json
import logging
import sys
import tempfile
import uuid
from pathlib import Path
from datetime import datetime, timezone

log = logging.getLogger("skg.sensors.adapter_runner")

SKG_HOME = Path(os.environ.get('SKG_HOME', Path(__file__).resolve().parents[2]))


def _adapter_module(toolchain: str, adapter: str):
    """Dynamically import an adapter's parse module."""
    tc_dir = SKG_HOME / toolchain
    adapter_path = tc_dir / "adapters" / adapter
    parse_file = adapter_path / "parse.py"
    if not parse_file.exists():
        raise ImportError(f"Adapter not found: {parse_file}")
    spec = importlib.util.spec_from_file_location(
        f"skg_adapter_{toolchain}_{adapter}", parse_file
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read_ndjson(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except Exception:
                pass
    return events


def run_container_inspect(
    inspect_json: dict | list,
    workload_id: str,
    attack_path_id: str = "container_escape_privileged_v1",
    run_id: str | None = None,
) -> list[dict]:
    """
    Run the container_inspect adapter against a parsed docker inspect blob.
    Returns list of envelope events.
    """
    run_id = run_id or str(uuid.uuid4())
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        inspect_file = tmp / "inspect.json"
        out_file = tmp / "events.ndjson"

        # docker inspect returns a list; adapter handles both
        data = inspect_json if isinstance(inspect_json, list) else [inspect_json]
        inspect_file.write_text(json.dumps(data))

        try:
            mod = _adapter_module("skg-container-escape-toolchain", "container_inspect")
            mod.main.__func__ if hasattr(mod.main, '__func__') else None  # check callable
        except Exception as exc:
            log.warning(f"container_inspect adapter load failed: {exc}")
            return []

        try:
            # Adapter main() uses argparse — call the parse logic directly
            inspect_data = data[0] if data else {}
            caps_raw = inspect_data.get("HostConfig", {}).get("CapAdd") or []
            caps = {c.upper() for c in caps_raw}
            if inspect_data.get("HostConfig", {}).get("Privileged"):
                caps.add("SYS_ADMIN")

            for fn_name in [
                "check_running_as_root", "check_privileged", "check_docker_socket",
                "check_cap_sys_admin", "check_cap_sys_ptrace", "check_host_pid",
                "check_host_network", "check_sensitive_mounts", "check_seccomp_apparmor",
                "check_cap_net_admin", "check_host_ipc", "check_user_namespace",
            ]:
                fn = getattr(mod, fn_name, None)
                if fn is None:
                    continue
                try:
                    if fn_name in ("check_privileged", "check_cap_sys_admin",
                                   "check_cap_sys_ptrace", "check_seccomp_apparmor",
                                   "check_cap_net_admin"):
                        fn(inspect_data, caps, out_file, attack_path_id, run_id, workload_id)
                    else:
                        fn(inspect_data, out_file, attack_path_id, run_id, workload_id)
                except Exception as exc:
                    log.debug(f"container_inspect {fn_name}: {exc}")

        except Exception as exc:
            log.warning(f"container_inspect run error: {exc}")

        events = _read_ndjson(out_file)

    return events


# ---------------------------------------------------------------------------
# AD lateral — BloodHound
# ---------------------------------------------------------------------------

def run_bloodhound(
    bh_dir: Path,
    workload_id: str,
    attack_path_id: str = "ad_kerberoast_v1",
    run_id: str | None = None,
) -> list[dict]:
    """
    Run the BloodHound adapter against a directory of BH JSON files.
    Returns list of envelope events.
    """
    run_id = run_id or str(uuid.uuid4())
    if not bh_dir.exists():
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "events.ndjson"
        try:
            mod = _adapter_module("skg-ad-lateral-toolchain", "bloodhound")
            data = mod.load_bh_dir(bh_dir)

            # Run all check functions
            checks = [
                ("check_kerberoastable",        (data["users"], data["groups"])),
                ("check_asrep",                 (data["users"], data["groups"])),
                ("check_delegation",            (data["computers"], data["users"])),
                ("check_acls",                  (data["acls"], data["groups"])),
                ("check_dcsync_accounts_enabled", (data["users"], data["acls"])),
                ("check_passwords_in_descriptions", (data["users"], data["computers"])),
                ("check_adminsdholder",         (data["acls"],)),
                ("check_stale_privileged",      (data["users"], data["groups"])),
                ("check_weak_password_policy",  (data["domains"],)),
                ("check_laps",                  (data["computers"],)),
            ]

            for fn_name, args in checks:
                fn = getattr(mod, fn_name, None)
                if fn:
                    try:
                        fn(*args, out_file, attack_path_id, run_id, workload_id)
                    except Exception as exc:
                        log.debug(f"bloodhound {fn_name}: {exc}")

        except Exception as exc:
            log.warning(f"BloodHound adapter error: {exc}")
            return []

        events = _read_ndjson(out_file)

    return events


# ---------------------------------------------------------------------------
# APRS — net_sandbox (egress + JNDI)
# ---------------------------------------------------------------------------

def run_web_fingerprint(
    collection: dict,
    workload_id: str,
    attack_path_id: str,
    run_id: str,
) -> list[dict]:
    """
    Route web collection data through the web fingerprint adapter.
    collection: dict from web_sensor.collect_target()
    Returns list of obs.attack.precondition events.
    """
    import tempfile
    mod = _adapter_module("skg-web-toolchain", "web_fingerprint")
    if mod is None:
        log.warning("web_fingerprint adapter not found")
        return []

    events: list[dict] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        out_file = tmp / "web_events.ndjson"

        run_checks = getattr(mod, "run_checks", None)
        if run_checks:
            try:
                run_checks(collection, out_file, attack_path_id, run_id, workload_id)
            except Exception as exc:
                log.error(f"web run_checks error: {exc}", exc_info=True)
                return []
        else:
            log.warning("web adapter missing run_checks")
            return []

        if out_file.exists():
            for line in out_file.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass

    log.info(f"[web] {workload_id}: {len(events)} events from web adapter")
    return events


def run_net_sandbox(
    collection: dict,
    workload_id: str,
    attack_path_id: str = "log4j_jndi_rce_v1",
    run_id: str | None = None,
) -> list[dict]:
    """
    Run the net_sandbox adapter against collected network data.
    collection keys: packages, network, log4j_jars, log4j_configs, java_homes, env_vars
    Returns list of envelope events.
    """
    run_id = run_id or str(uuid.uuid4())

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        out_file = tmp / "events.ndjson"

        # Write collection files as the adapter expects
        for key, filename in [
            ("packages",     "packages.txt"),
            ("network",      "network.txt"),
            ("log4j_jars",   "log4j_jars.txt"),
            ("env_vars",     "env_vars.txt"),
            ("java_homes",   "java_homes.txt"),
        ]:
            val = collection.get(key, "")
            if val:
                (tmp / filename).write_text(val if isinstance(val, str) else "\n".join(val))

        # docker_inspect if present
        if collection.get("docker_inspect"):
            (tmp / "docker_inspect.json").write_text(
                json.dumps(collection["docker_inspect"])
            )

        try:
            mod = _adapter_module("skg-aprs-toolchain", "net_sandbox")
            # net_sandbox adapter reads files from a directory
            # Call parse functions directly
            collection_dir = tmp

            # Build the analysis input the adapter expects
            for fn_name in ["analyze_packages", "analyze_network", "analyze_log4j",
                            "analyze_egress", "analyze_jndi_config"]:
                fn = getattr(mod, fn_name, None)
                if fn:
                    try:
                        fn(collection_dir, out_file, attack_path_id, run_id, workload_id)
                    except Exception as exc:
                        log.debug(f"net_sandbox {fn_name}: {exc}")

            # If adapter uses a single main parse function
            if hasattr(mod, "parse_collection"):
                try:
                    mod.parse_collection(
                        collection_dir, out_file, attack_path_id, run_id, workload_id
                    )
                except Exception as exc:
                    log.debug(f"net_sandbox parse_collection: {exc}")

        except Exception as exc:
            log.warning(f"net_sandbox adapter error: {exc}")

        events = _read_ndjson(out_file)

        # If adapter produced nothing, fall back to direct analysis
        if not events:
            events = _analyze_aprs_direct(collection, workload_id, attack_path_id, run_id)

        return events


def _analyze_aprs_direct(
    collection: dict,
    workload_id: str,
    attack_path_id: str,
    run_id: str,
) -> list[dict]:
    """
    Direct APRS wicket analysis when net_sandbox adapter interface doesn't match.
    Covers AP-L4 through AP-L19.
    """
    now = datetime.now(timezone.utc).isoformat()
    events = []

    def _ev(wicket_id, realized, rank, confidence, detail="", source_kind="ssh_collection"):
        status = "realized" if realized is True else ("blocked" if realized is False else "unknown")
        return {
            "id": str(uuid.uuid4()),
            "ts": now,
            "type": "obs.attack.precondition",
            "source": {"source_id": "adapter_runner.aprs_direct",
                       "toolchain": "skg-aprs-toolchain", "version": "0.0.0"},
            "payload": {
                "wicket_id": wicket_id, "status": status,
                "attack_path_id": attack_path_id, "run_id": run_id,
                "workload_id": workload_id, "detail": detail,
            },
            "provenance": {
                "evidence_rank": rank,
                "evidence": {"source_kind": source_kind, "pointer": wicket_id,
                             "collected_at": now, "confidence": confidence},
            },
        }

    packages   = (collection.get("packages") or "").lower()
    log4j_jars = (collection.get("log4j_jars") or "")
    network    = (collection.get("network") or "")
    env_vars   = (collection.get("env_vars") or "").upper()
    java_homes = (collection.get("java_homes") or "")

    # AP-L4: Java present
    java_present = bool(java_homes.strip()) or "java" in packages or "jdk" in packages
    events.append(_ev("AP-L4", java_present, 2, 0.90,
                       f"java_homes: {java_homes[:80]}"))

    # AP-L5: Log4j jar on classpath
    log4j_jar = bool(log4j_jars.strip())
    events.append(_ev("AP-L5", log4j_jar, 2, 0.95,
                       log4j_jars[:120] if log4j_jar else "no log4j jars found"))

    # AP-L6: Log4j config present
    log4j_config = collection.get("log4j_configs") or collection.get("log4j_config") or ""
    has_config = bool(log4j_config.strip()) if isinstance(log4j_config, str) else bool(log4j_config)
    # formatMsgNoLookups check
    lookups_disabled = "formatmsgnolookups=true" in log4j_config.lower() if isinstance(log4j_config, str) else False
    events.append(_ev("AP-L6", None if not has_config else True, 3, 0.80,
                       "log4j config found" if has_config else "no log4j config found"))
    if has_config:
        events.append(_ev("AP-L11", not lookups_disabled, 3, 0.85,
                           "lookups enabled in config" if not lookups_disabled else "lookups disabled"))

    # AP-L10: JNDI lookup capability — check env vars + jar presence
    jndi_env = "JNDI" in env_vars or "LOG4J" in env_vars
    jndi_capable = log4j_jar and (not lookups_disabled)
    events.append(_ev("AP-L10", jndi_capable or None, 2, 0.80,
                       "JNDI lookup capability inferred from jar + config"))

    # AP-L7/L12/L13/L14: Egress analysis
    net_lower = network.lower()
    # DNS
    dns_allowed = "53" in network and "drop" not in net_lower
    events.append(_ev("AP-L12", dns_allowed or None, 4, 0.70,
                       "DNS port 53 visible in network output" if dns_allowed else "DNS status unknown"))
    # LDAP/RMI
    ldap_rmi = ("389" in network or "1099" in network) and "drop" not in net_lower
    events.append(_ev("AP-L13", ldap_rmi or None, 4, 0.65,
                       "LDAP/RMI ports observed" if ldap_rmi else "LDAP/RMI status unknown"))
    # HTTP/HTTPS outbound
    http_out = ("80" in network or "443" in network or "8080" in network) and "output drop" not in net_lower
    events.append(_ev("AP-L14", http_out or None, 4, 0.70,
                       "HTTP/HTTPS outbound ports observed" if http_out else "unknown"))
    # General egress
    egress_blocked = "output drop" in net_lower or "output reject" in net_lower
    events.append(_ev("AP-L7", not egress_blocked if "output" in net_lower else None, 4, 0.75,
                       "iptables OUTPUT policy" if "output" in net_lower else "no iptables data"))

    # AP-L16: Process spawn — check if shell/interpreter is accessible
    procs = (collection.get("processes") or "").lower()
    spawn_capable = "bash" in procs or "sh" in procs or "python" in procs
    events.append(_ev("AP-L16", spawn_capable or None, 3, 0.65,
                       "shell process visible in ps output" if spawn_capable else "unknown"))


    # AP-L8: attacker-controlled input reaches log4j sink
    # Rank 1 — can only be confirmed via runtime observation (not static collection)
    # Mark as unknown from static collection; MSF/agent runtime will confirm
    events.append(_ev("AP-L8", None, 1, 0.30,
                       "Cannot confirm from static collection — requires runtime log observation"))

    # AP-L15: proxy-only outbound with allowlist
    proxy_env = "HTTP_PROXY" in env_vars or "HTTPS_PROXY" in env_vars or "http_proxy" in env_vars.lower()
    events.append(_ev("AP-L15", proxy_env or None, 4, 0.55,
                       f"proxy env vars present: {proxy_env}"))

    # AP-L17: relevant file write permitted
    # Infer from process running as root or writable paths in collection
    root_process = "root" in (collection.get("processes") or "").lower()
    events.append(_ev("AP-L17", root_process or None, 3, 0.50,
                       "root process present — file write likely" if root_process else "unknown"))

    return events


# ---------------------------------------------------------------------------
# Container escape — docker inspect
# ---------------------------------------------------------------------------

    return events


# ---------------------------------------------------------------------------
# Host toolchain — SSH collection
# ---------------------------------------------------------------------------

def run_ssh_host(
    client,          # paramiko SSHClient
    host: str,
    workload_id: str,
    attack_path_id: str = "host_ssh_initial_access_v1",
    run_id: str | None = None,
    out_file: Path | None = None,
    user: str = "root",
    auth_type: str = "key",
    port: int = 22,
) -> list[dict]:
    """
    Run the host toolchain ssh_collect adapter against a live paramiko client.
    Returns list of envelope events.
    """
    run_id = run_id or str(uuid.uuid4())

    with tempfile.TemporaryDirectory() as tmpdir:
        _out = out_file or (Path(tmpdir) / "events.ndjson")
        try:
            mod = _adapter_module("skg-host-toolchain", "ssh_collect")
            # Emit the initial-access wickets first so partial SSH runs still
            # preserve the fact that connectivity and authentication succeeded.
            fn = getattr(mod, "eval_ho01_reachability", None)
            if fn:
                try:
                    fn(host, _out, attack_path_id, run_id, workload_id)
                except Exception as exc:
                    log.debug(f"host eval_ho01_reachability: {exc}")
            fn = getattr(mod, "eval_ho02_ssh", None)
            if fn:
                try:
                    fn(host, port, _out, attack_path_id, run_id, workload_id)
                except Exception as exc:
                    log.debug(f"host eval_ho02_ssh: {exc}")
            fn = getattr(mod, "eval_ho03_credential", None)
            if fn:
                try:
                    fn(host, user, auth_type, _out, attack_path_id, run_id, workload_id)
                except Exception as exc:
                    log.debug(f"host eval_ho03_credential: {exc}")
            # Call all eval_ functions directly with the live client
            for fn_name in [
                "eval_ho10_root", "eval_ho06_sudo", "eval_ho07_suid",
                "eval_ho08_writable_cron", "eval_ho09_cred_in_env",
                "eval_ho11_vuln_packages", "eval_ho12_kernel", "eval_ho13_ssh_keys",
                "eval_ho15_docker", "eval_ho16_cloud_metadata",
                "eval_ho23_av_edr", "eval_ho24_domain_joined",
            ]:
                fn = getattr(mod, fn_name, None)
                if fn:
                    try:
                        fn(client, host, _out, attack_path_id, run_id, workload_id)
                    except Exception as exc:
                        log.debug(f"host {fn_name}: {exc}")

        except Exception as exc:
            log.warning(f"host ssh_collect adapter error: {exc}")
            return []

        events = _read_ndjson(_out)

    return events


# ---------------------------------------------------------------------------
# USB drop — route all present data through appropriate adapters
# ---------------------------------------------------------------------------

def run_usb_drop(
    drop_dir: Path,
    workload_id: str,
    attack_path_id: str | None = None,
    run_id: str | None = None,
) -> list[dict]:
    """
    Process a USB drop directory through all relevant adapters.
    
    Detects what data is present and routes each artifact:
      docker_inspect.json  → container_inspect adapter (CE wickets)
      bh_data/             → bloodhound adapter (AD wickets)  
      packages.txt +       → aprs direct analysis (AP wickets)
      log4j_jars.txt
    
    Returns all events from all adapters combined.
    """
    run_id = run_id or str(uuid.uuid4())
    all_events = []

    # Container inspection
    inspect_file = drop_dir / "docker_inspect.json"
    if inspect_file.exists():
        try:
            inspect_data = json.loads(inspect_file.read_text())
            path_id = attack_path_id or "container_escape_privileged_v1"
            events = run_container_inspect(inspect_data, workload_id, path_id, run_id)
            all_events.extend(events)
            log.info(f"[usb_drop] container_inspect: {len(events)} events")
        except Exception as exc:
            log.warning(f"[usb_drop] container_inspect failed: {exc}")

    # BloodHound
    bh_dir = drop_dir / "bh_data"
    if bh_dir.exists():
        try:
            path_id = attack_path_id or "ad_kerberoast_v1"
            events = run_bloodhound(bh_dir, workload_id, path_id, run_id)
            all_events.extend(events)
            log.info(f"[usb_drop] bloodhound: {len(events)} events")
        except Exception as exc:
            log.warning(f"[usb_drop] bloodhound failed: {exc}")

    # APRS / net_sandbox — build collection dict from drop files
    aprs_collection = {}
    for key, filename in [
        ("packages",     "packages.txt"),
        ("log4j_jars",   "log4j_jars.txt"),
        ("network",      "network.txt"),
        ("env_vars",     "env_vars.txt"),
        ("java_homes",   "java_homes.txt"),
        ("processes",    "processes.txt"),
        ("log4j_configs","log4j_configs.txt"),
    ]:
        f = drop_dir / filename
        if f.exists():
            aprs_collection[key] = f.read_text(errors="replace")

    if any(aprs_collection.values()):
        try:
            path_id = attack_path_id or "log4j_jndi_rce_v1"
            events = run_net_sandbox(aprs_collection, workload_id, path_id, run_id)
            all_events.extend(events)
            log.info(f"[usb_drop] net_sandbox/aprs: {len(events)} events")
        except Exception as exc:
            log.warning(f"[usb_drop] aprs failed: {exc}")

    return all_events


# ---------------------------------------------------------------------------
# Agent callback — full payload routing
# ---------------------------------------------------------------------------

def run_agent_callback(
    payload: dict,
    workload_id: str,
    run_id: str | None = None,
) -> list[dict]:
    """
    Route an agent callback payload through all relevant adapters.
    payload: {agent_id, hostname, platform, collection: {...}}
    """
    run_id = run_id or str(uuid.uuid4())
    all_events = []
    collection = payload.get("collection", {})
    platform = payload.get("platform", "linux").lower()

    # Container escape — if docker_inspect present
    if collection.get("docker_inspect"):
        try:
            events = run_container_inspect(
                collection["docker_inspect"], workload_id,
                "container_escape_privileged_v1", run_id
            )
            all_events.extend(events)
        except Exception as exc:
            log.debug(f"agent container_inspect: {exc}")

    # BloodHound — if bh_data present (written to temp dir)
    if collection.get("bh_data"):
        with tempfile.TemporaryDirectory() as tmpdir:
            bh_dir = Path(tmpdir) / "bh_data"
            bh_dir.mkdir()
            for fname, content in collection["bh_data"].items():
                (bh_dir / fname).write_text(
                    content if isinstance(content, str) else json.dumps(content)
                )
            try:
                events = run_bloodhound(bh_dir, workload_id, "ad_kerberoast_v1", run_id)
                all_events.extend(events)
            except Exception as exc:
                log.debug(f"agent bloodhound: {exc}")

    # APRS — from collection fields
    aprs_coll = {
        "packages":     collection.get("packages", ""),
        "log4j_jars":   collection.get("log4j_jars", ""),
        "network":      collection.get("network", ""),
        "env_vars":     collection.get("env_vars", ""),
        "java_homes":   collection.get("java_homes", ""),
        "processes":    collection.get("processes", ""),
        "docker_inspect": collection.get("docker_inspect"),
    }
    if any(v for v in aprs_coll.values() if v):
        try:
            events = run_net_sandbox(aprs_coll, workload_id, "log4j_jndi_rce_v1", run_id)
            all_events.extend(events)
        except Exception as exc:
            log.debug(f"agent aprs: {exc}")

    return all_events
