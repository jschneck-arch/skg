from __future__ import annotations

import glob
import socket
from pathlib import Path
from typing import Any, Iterable


SERVICE_PORT_DOMAINS: dict[int, list[str]] = {
    21: ["host"],
    22: ["host", "sysaudit"],
    23: ["host"],
    25: ["host"],
    53: ["host"],
    80: ["web"],
    88: ["ad_lateral"],
    135: ["host", "ad_lateral"],
    137: ["host", "ad_lateral"],
    138: ["host", "ad_lateral"],
    139: ["host", "ad_lateral"],
    389: ["ad_lateral"],
    443: ["web"],
    445: ["host", "ad_lateral"],
    464: ["ad_lateral"],
    593: ["host", "ad_lateral"],
    636: ["ad_lateral"],
    1433: ["data_pipeline"],
    1521: ["data_pipeline"],
    2375: ["container_escape"],
    2376: ["container_escape"],
    3268: ["ad_lateral"],
    3269: ["ad_lateral"],
    3306: ["host", "data_pipeline"],
    3389: ["host"],
    4000: ["ai_target"],
    5000: ["container_escape"],
    5001: ["ai_target"],
    5432: ["host", "data_pipeline"],
    5433: ["host", "data_pipeline"],
    5601: ["data_pipeline"],
    5985: ["host"],
    5986: ["host"],
    6006: ["ai_target"],
    6333: ["ai_target"],
    6379: ["data_pipeline"],
    6443: ["container_escape"],
    7860: ["ai_target"],
    8000: ["ai_target"],
    8001: ["ai_target"],
    8008: ["web"],
    8009: ["web"],
    8080: ["web"],
    8443: ["web"],
    8888: ["web", "ai_target"],
    9000: ["ai_target"],
    9200: ["data_pipeline"],
    9300: ["data_pipeline"],
    10250: ["container_escape"],
    10255: ["container_escape"],
    11211: ["data_pipeline"],
    11434: ["ai_target"],
    27017: ["data_pipeline"],
    27018: ["data_pipeline"],
}

AI_SPECULATIVE_PORTS = [11434, 6333, 8888, 7860, 5001, 4000, 6006]

GRAVITY_DOMAIN_ALIASES = {
    "binary": "binary_analysis",
    "data": "data_pipeline",
}


def _service_name_tokens(service: dict[str, Any]) -> str:
    return (service.get("name") or service.get("service") or "").lower()


def _gravity_domain(domain: str) -> str:
    raw = str(domain or "").strip()
    return GRAVITY_DOMAIN_ALIASES.get(raw, raw)


def summarize_view_nodes(view_nodes: Iterable[dict[str, Any]], *, identity_key: str) -> dict[str, Any]:
    summary = {
        "identity_key": identity_key,
        "view_count": 0,
        "measured_domains": [],
        "measured_unknowns": 0.0,
        "measured_realized": 0,
        "measured_blocked": 0,
        "memory_pearl_count": 0,
        "memory_reinforced_wickets": [],
        "observed_tools": {
            "tool_names": [],
            "observed_tools": [],
            "domain_hints": [],
            "instrument_hints": [],
            "scope": "node_local",
            "status": "unknown",
            "observed_at": "",
            "nse_available": False,
            "nse_script_count": 0,
        },
        "view_nodes": [],
    }
    if not identity_key:
        return summary

    domains: set[str] = set()
    reinforced: set[str] = set()
    memory_pearl_count = 0
    measured_unknowns = 0.0
    measured_realized = 0
    measured_blocked = 0
    matched: list[dict[str, Any]] = []
    tool_names: set[str] = set()
    tool_domain_hints: set[str] = set()
    tool_instrument_hints: set[str] = set()
    observed_tools: dict[str, dict[str, Any]] = {}
    observed_tool_status = "unknown"
    observed_tool_scope = "node_local"
    observed_tool_at = ""
    nse_available = False
    nse_script_count = 0

    for row in view_nodes or []:
        if str(row.get("identity_key") or "") != identity_key:
            continue
        matched.append(dict(row))
        summary["view_count"] += 1
        domain = _gravity_domain(str(row.get("domain") or ""))
        if domain:
            domains.add(domain)
        measured = dict(row.get("measured_now") or {})
        measured_unknowns += float(len(measured.get("unknown") or []))
        measured_realized += len(measured.get("realized") or [])
        measured_blocked += len(measured.get("blocked") or [])
        overlay = dict(row.get("memory_overlay") or {})
        memory_pearl_count += int(overlay.get("pearl_count", 0) or 0)
        reinforced.update(str(wid) for wid in (overlay.get("reinforced_wickets") or []) if wid)
        tool_overlay = dict(row.get("observed_tools") or measured.get("observed_tools") or {})
        for tool_name in tool_overlay.get("tool_names") or []:
            text = str(tool_name or "").strip()
            if text:
                tool_names.add(text)
        for domain_hint in tool_overlay.get("domain_hints") or []:
            text = _gravity_domain(str(domain_hint or "").strip())
            if text:
                tool_domain_hints.add(text)
        for inst_hint in tool_overlay.get("instrument_hints") or []:
            text = str(inst_hint or "").strip()
            if text:
                tool_instrument_hints.add(text)
        for tool in tool_overlay.get("observed_tools") or []:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or "").strip()
            if not name:
                continue
            current = dict(observed_tools.get(name) or {})
            merged = dict(tool)
            merged["name"] = name
            merged["instrument_names"] = sorted({
                str(item or "").strip()
                for item in (list(current.get("instrument_names") or []) + list(tool.get("instrument_names") or []))
                if str(item or "").strip()
            })
            merged["domain_hints"] = sorted({
                _gravity_domain(str(item or "").strip())
                for item in (list(current.get("domain_hints") or []) + list(tool.get("domain_hints") or []))
                if str(item or "").strip()
            })
            if bool(current.get("nse_available")) or bool(tool.get("nse_available")):
                merged["nse_available"] = True
            merged["nse_script_count"] = max(
                int(current.get("nse_script_count", 0) or 0),
                int(tool.get("nse_script_count", 0) or 0),
            )
            observed_tools[name] = merged
            if merged.get("nse_available"):
                nse_available = True
            nse_script_count = max(nse_script_count, int(merged.get("nse_script_count", 0) or 0))
        observed_at = str(tool_overlay.get("observed_at") or "").strip()
        if observed_at and observed_at > observed_tool_at:
            observed_tool_at = observed_at
        if tool_overlay.get("status") == "realized":
            observed_tool_status = "realized"
        elif observed_tool_status != "realized" and tool_overlay.get("status") == "blocked":
            observed_tool_status = "blocked"
        scope = str(tool_overlay.get("scope") or "").strip()
        if scope:
            observed_tool_scope = scope

    summary["measured_domains"] = sorted(domains)
    summary["measured_unknowns"] = round(measured_unknowns, 4)
    summary["measured_realized"] = measured_realized
    summary["measured_blocked"] = measured_blocked
    summary["memory_pearl_count"] = memory_pearl_count
    summary["memory_reinforced_wickets"] = sorted(reinforced)
    summary["observed_tools"] = {
        "tool_names": sorted(tool_names),
        "observed_tools": [observed_tools[name] for name in sorted(observed_tools)],
        "domain_hints": sorted(tool_domain_hints),
        "instrument_hints": sorted(tool_instrument_hints),
        "scope": observed_tool_scope,
        "status": observed_tool_status,
        "observed_at": observed_tool_at,
        "nse_available": nse_available,
        "nse_script_count": nse_script_count,
    }
    summary["view_nodes"] = matched
    return summary


def _probe_ai_ports(ip: str, ports: Iterable[int]) -> bool:
    for port in ports:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, int(port))) == 0:
                return True
        except Exception:
            continue
        finally:
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
    return False


def derive_effective_domains(
    target: dict[str, Any],
    *,
    ip: str,
    discovery_dir: Path | str,
    view_state: dict[str, Any] | None = None,
    probe_ai: bool = True,
    ai_port_probe=None,
) -> set[str]:
    view_state = dict(view_state or {})
    effective_domains = {
        _gravity_domain(domain)
        for domain in (view_state.get("measured_domains") or [])
        if str(domain or "").strip()
    }
    effective_domains.update(
        _gravity_domain(domain)
        for domain in (target.get("domains", []) or [])
        if str(domain or "").strip()
    )
    for service in target.get("services", []):
        port = service.get("port")
        service_name = _service_name_tokens(service)
        if port in SERVICE_PORT_DOMAINS:
            effective_domains.update(SERVICE_PORT_DOMAINS[int(port)])
        if any(token in service_name for token in ("ssh", "openssh")):
            effective_domains.update(["host", "sysaudit"])
        if any(token in service_name for token in ("ftp", "vsftpd", "proftpd", "telnet")):
            effective_domains.add("host")
        if any(token in service_name for token in ("smb", "netbios", "microsoft-ds", "cifs")):
            effective_domains.update(["host", "ad_lateral"])
        if any(token in service_name for token in ("ldap", "kerberos", "krb5")):
            effective_domains.add("ad_lateral")
        if any(token in service_name for token in ("rdp", "ms-wbt", "msrdp", "remote desktop")):
            effective_domains.add("host")
        if any(token in service_name for token in ("winrm", "wsman", "ms-wsman")):
            effective_domains.add("host")
        if any(token in service_name for token in ("mysql", "mariadb", "postgres", "mssql", "sqlserver", "oracle")):
            effective_domains.update(["host", "data_pipeline"])
        if any(token in service_name for token in ("redis", "memcached", "mongodb", "elasticsearch", "kibana")):
            effective_domains.add("data_pipeline")
        if any(token in service_name for token in ("docker", "kubernetes", "k8s", "kubectl")):
            effective_domains.add("container_escape")
        if any(token in service_name for token in ("http", "https", "nginx", "apache", "iis")):
            effective_domains.add("web")

    discovery_root = Path(discovery_dir)
    postexp_pattern = str(discovery_root / f"gravity_postexp_{ip.replace('.','_')}_*.ndjson")
    if list(glob.glob(postexp_pattern)):
        effective_domains.add("binary_analysis")
        effective_domains.add("container_escape")

    if probe_ai and "ai_target" not in effective_domains:
        probe = ai_port_probe or _probe_ai_ports
        if probe(ip, AI_SPECULATIVE_PORTS):
            effective_domains.add("ai_target")
    return effective_domains


def applicable_wickets_for_domains(domains: Iterable[str], domain_wickets: dict[str, set[str]]) -> set[str]:
    applicable: set[str] = set()
    for domain in domains:
        applicable.update(domain_wickets.get(domain, set()))
    return applicable


def apply_first_contact_floor(
    *,
    ip: str,
    entropy: float,
    applicable: set[str],
    domain_wickets: dict[str, set[str]],
    discovery_dir: Path | str,
    has_measured_view: bool = False,
) -> tuple[float, set[str], bool]:
    has_prior_nmap = bool(glob.glob(str(Path(discovery_dir) / f"gravity_nmap_{ip}_*.ndjson")))
    if has_prior_nmap or has_measured_view:
        return entropy, set(applicable), False

    adjusted_entropy = max(float(entropy or 0.0), 25.0)
    adjusted_applicable = set(applicable)
    if not adjusted_applicable:
        adjusted_applicable = (
            domain_wickets.get("host", set())
            | domain_wickets.get("web", set())
            | domain_wickets.get("sysaudit", set())
            | domain_wickets.get("ad_lateral", set())
        )
    return adjusted_entropy, adjusted_applicable, True


def summarize_applicable_states(states: dict[str, Any], applicable: set[str]) -> tuple[float, int, int]:
    unresolved = sum(
        max(
            float(states.get(wid, {}).get("phi_u", 0.0) or 0.0),
            float(states.get(wid, {}).get("local_energy", 0.0) or 0.0),
            1.0 if states.get(wid, {}).get("status", "unknown") == "unknown" else 0.0,
        ) + float(states.get(wid, {}).get("contradiction", 0.0) or 0.0)
        for wid in applicable
        if states.get(wid, {}).get("status", "unknown") == "unknown"
    )
    realized = sum(1 for wid in applicable if states.get(wid, {}).get("status") == "realized")
    blocked = sum(1 for wid in applicable if states.get(wid, {}).get("status") == "blocked")
    return round(unresolved, 4), realized, blocked
