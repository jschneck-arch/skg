from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_host.mappings import load_exploit_signatures, load_service_wickets
from skg_domain_host.ontology import load_wickets
from skg_domain_host.policies import load_nmap_adapter_policy


@dataclass(frozen=True, slots=True)
class NmapService:
    port: int
    proto: str
    service: str
    product: str = ""
    version: str = ""
    extra: str = ""
    scripts: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class NmapHostProfile:
    host: str
    host_up: bool
    hostname: str = ""
    os: str = ""
    open_ports: tuple[NmapService, ...] = ()


def _conf(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _wicket_label(wicket_id: str) -> str:
    wickets = load_wickets()
    row = wickets.get(wicket_id) if isinstance(wickets, dict) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _normalize_service(row: Mapping[str, Any]) -> NmapService:
    scripts = row.get("scripts")
    script_rows: dict[str, str] = {}
    if isinstance(scripts, Mapping):
        script_rows = {str(k): str(v) for k, v in scripts.items()}

    return NmapService(
        port=int(row.get("port") or 0),
        proto=str(row.get("proto") or "tcp"),
        service=str(row.get("service") or ""),
        product=str(row.get("product") or ""),
        version=str(row.get("version") or ""),
        extra=str(row.get("extra") or ""),
        scripts=script_rows,
    )


def _normalize_profiles(rows: Iterable[NmapHostProfile | Mapping[str, Any]]) -> list[NmapHostProfile]:
    profiles: list[NmapHostProfile] = []

    for row in rows:
        if isinstance(row, NmapHostProfile):
            profiles.append(row)
            continue

        if not isinstance(row, Mapping):
            continue

        services_raw = row.get("open_ports")
        services: list[NmapService] = []
        if isinstance(services_raw, list):
            for service_row in services_raw:
                if isinstance(service_row, Mapping):
                    services.append(_normalize_service(service_row))

        host = str(row.get("host") or row.get("ip") or "").strip()
        if not host:
            continue

        profiles.append(
            NmapHostProfile(
                host=host,
                host_up=bool(row.get("host_up", True)),
                hostname=str(row.get("hostname") or ""),
                os=str(row.get("os") or ""),
                open_ports=tuple(services),
            )
        )

    return profiles


def _service_hits(service: NmapService, service_map: Mapping[str, Any]) -> list[str]:
    rows = service_map.get("services") if isinstance(service_map, Mapping) else []
    if not isinstance(rows, list):
        return []

    service_name = service.service.lower()
    winners: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue

        wicket_id = str(row.get("wicket_id") or "").strip()
        keyword = str(row.get("match") or "").strip().lower()
        rule_port = int(row.get("port") or 0)

        if not wicket_id:
            continue

        keyword_hit = bool(keyword and keyword in service_name)
        port_hit = bool(rule_port and rule_port == service.port)

        if keyword_hit or port_hit:
            winners.append(wicket_id)

    return sorted(set(winners))


def _exploit_hits(service: NmapService, signatures: Mapping[str, Any]) -> list[str]:
    rows = signatures.get("signatures") if isinstance(signatures, Mapping) else []
    if not isinstance(rows, list):
        return []

    text = " ".join(
        [
            service.service,
            service.product,
            service.version,
            service.extra,
            " ".join(service.scripts.values()) if isinstance(service.scripts, Mapping) else "",
        ]
    ).lower()

    hits: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        keyword = str(row.get("keyword") or "").strip().lower()
        label = str(row.get("label") or keyword).strip()
        if keyword and keyword in text:
            hits.append(label)

    if "vulnerable" in text and "generic-script-vuln" not in hits:
        hits.append("generic-script-vuln")

    return sorted(set(hits))


def map_nmap_profiles_to_events(
    profiles: Iterable[NmapHostProfile | Mapping[str, Any]],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "adapter.host_nmap_profile",
    toolchain: str = "host",
) -> list[dict[str, Any]]:
    """Map host nmap-like profile rows into canonical precondition events."""

    normalized = _normalize_profiles(profiles)
    policy = load_nmap_adapter_policy()
    service_map = load_service_wickets()
    signatures = load_exploit_signatures()

    source_kind = str(policy.get("source_kind") or "nmap_scan")
    evidence_rank = int(policy.get("evidence_rank") or 4)
    pointer_prefix = str(policy.get("pointer_prefix") or "nmap://")
    default_conf = _conf(float(policy.get("default_confidence") or 0.85))
    exploit_conf = _conf(float(policy.get("exploit_confidence") or 0.75))
    unknown_exploit_conf = _conf(float(policy.get("unknown_exploit_confidence") or 0.4))
    reachable_wicket = str(policy.get("reachable_wicket_id") or "HO-01")
    exploit_wicket = str(policy.get("exploit_wicket_id") or "HO-25")
    emit_unknown_exploit = bool(policy.get("emit_unknown_exploit_when_no_hits", True))

    events: list[dict[str, Any]] = []

    for profile in normalized:
        this_workload_id = workload_id or f"host::{profile.host}"
        host_pointer = f"{pointer_prefix}{profile.host}"

        if profile.host_up:
            payload = build_precondition_payload(
                wicket_id=reachable_wicket,
                label=_wicket_label(reachable_wicket),
                domain="host",
                workload_id=this_workload_id,
                realized=True,
                status="realized",
                detail=f"Host {profile.host} responded to network scan.",
                attack_path_id=attack_path_id,
                target_ip=profile.host,
            )
            payload["run_id"] = run_id
            payload["attributes"] = {
                "host": profile.host,
                "hostname": profile.hostname,
                "os": profile.os,
            }
            events.append(
                build_event_envelope(
                    event_type="obs.attack.precondition",
                    source_id=source_id,
                    toolchain=toolchain,
                    payload=payload,
                    evidence_rank=evidence_rank,
                    source_kind=source_kind,
                    pointer=host_pointer,
                    confidence=default_conf,
                )
            )

        per_wicket_details: dict[str, list[str]] = {}
        per_wicket_pointer: dict[str, str] = {}
        exploit_details: list[str] = []

        for service in profile.open_ports:
            winners = _service_hits(service, service_map)
            for wicket_id in winners:
                per_wicket_details.setdefault(wicket_id, []).append(
                    f"{service.service or 'unknown'}:{service.port} {service.product} {service.version}".strip()
                )
                per_wicket_pointer.setdefault(
                    wicket_id,
                    f"{pointer_prefix}{profile.host}:{service.port}",
                )

            for exploit in _exploit_hits(service, signatures):
                exploit_details.append(
                    f"{service.service or 'unknown'}:{service.port} -> {exploit}"
                )

        for wicket_id in sorted(per_wicket_details):
            details = per_wicket_details[wicket_id]
            pointer = per_wicket_pointer.get(wicket_id, host_pointer)
            payload = build_precondition_payload(
                wicket_id=wicket_id,
                label=_wicket_label(wicket_id),
                domain="host",
                workload_id=this_workload_id,
                realized=True,
                status="realized",
                detail=f"Detected service exposure(s): {'; '.join(details[:3])}",
                attack_path_id=attack_path_id,
                target_ip=profile.host,
            )
            payload["run_id"] = run_id
            payload["attributes"] = {"service_matches": details}
            events.append(
                build_event_envelope(
                    event_type="obs.attack.precondition",
                    source_id=source_id,
                    toolchain=toolchain,
                    payload=payload,
                    evidence_rank=evidence_rank,
                    source_kind=source_kind,
                    pointer=pointer,
                    confidence=default_conf,
                )
            )

        if exploit_details:
            payload = build_precondition_payload(
                wicket_id=exploit_wicket,
                label=_wicket_label(exploit_wicket),
                domain="host",
                workload_id=this_workload_id,
                realized=True,
                status="realized",
                detail=f"Potential exploitable service signatures: {'; '.join(sorted(set(exploit_details))[:3])}",
                attack_path_id=attack_path_id,
                target_ip=profile.host,
            )
            payload["run_id"] = run_id
            payload["attributes"] = {"exploit_hits": sorted(set(exploit_details))}
            events.append(
                build_event_envelope(
                    event_type="obs.attack.precondition",
                    source_id=source_id,
                    toolchain=toolchain,
                    payload=payload,
                    evidence_rank=evidence_rank,
                    source_kind=source_kind,
                    pointer=host_pointer,
                    confidence=exploit_conf,
                )
            )
        elif emit_unknown_exploit:
            payload = build_precondition_payload(
                wicket_id=exploit_wicket,
                label=_wicket_label(exploit_wicket),
                domain="host",
                workload_id=this_workload_id,
                realized=None,
                status="unknown",
                detail="No exploitable version signature matched in scanned services.",
                attack_path_id=attack_path_id,
                target_ip=profile.host,
            )
            payload["run_id"] = run_id
            payload["attributes"] = {"open_port_count": len(profile.open_ports)}
            events.append(
                build_event_envelope(
                    event_type="obs.attack.precondition",
                    source_id=source_id,
                    toolchain=toolchain,
                    payload=payload,
                    evidence_rank=evidence_rank,
                    source_kind=source_kind,
                    pointer=host_pointer,
                    confidence=unknown_exploit_conf,
                )
            )

    return events
