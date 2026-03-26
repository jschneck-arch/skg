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


def _service_name_tokens(service: dict[str, Any]) -> str:
    return (service.get("name") or service.get("service") or "").lower()


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
    probe_ai: bool = True,
    ai_port_probe=None,
) -> set[str]:
    effective_domains = set(target.get("domains", []))
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
) -> tuple[float, set[str], bool]:
    has_prior_nmap = bool(glob.glob(str(Path(discovery_dir) / f"gravity_nmap_{ip}_*.ndjson")))
    if has_prior_nmap:
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
