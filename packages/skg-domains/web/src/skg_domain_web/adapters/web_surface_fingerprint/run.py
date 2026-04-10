from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_web.mappings import load_surface_fingerprint_rules
from skg_domain_web.ontology import load_wickets
from skg_domain_web.policies import load_surface_fingerprint_policy


def _conf(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _headers_lower(headers: Mapping[str, Any] | None) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        return {}
    lowered: dict[str, str] = {}
    for key, value in headers.items():
        lowered[str(key).strip().lower()] = str(value)
    return lowered


def _wicket_label(wicket_id: str) -> str:
    wickets = load_wickets()
    row = wickets.get(wicket_id) if isinstance(wickets, dict) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _emit(
    wicket_id: str,
    *,
    status: str,
    confidence: float,
    detail: str,
    pointer: str,
    source_id: str,
    source_kind: str,
    toolchain: str,
    attack_path_id: str,
    workload_id: str,
) -> dict[str, Any]:
    payload = build_precondition_payload(
        wicket_id=wicket_id,
        label=_wicket_label(wicket_id),
        domain="web",
        workload_id=workload_id,
        realized=status == "realized",
        status=status,
        detail=detail,
        attack_path_id=attack_path_id,
    )
    return build_event_envelope(
        event_type="obs.attack.precondition",
        source_id=source_id,
        toolchain=toolchain,
        payload=payload,
        evidence_rank=1,
        source_kind=source_kind,
        pointer=pointer,
        confidence=_conf(confidence),
    )


def map_surface_profile_to_events(
    profile: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "adapter.web_surface_fingerprint",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    """Map pre-collected surface fingerprint signals to canonical web events."""

    policy = load_surface_fingerprint_policy()
    rules = load_surface_fingerprint_rules()

    wickets = policy.get("wickets") if isinstance(policy, Mapping) else {}
    conf = policy.get("confidence") if isinstance(policy, Mapping) else {}
    if not isinstance(wickets, Mapping):
        wickets = {}
    if not isinstance(conf, Mapping):
        conf = {}

    parsed = urlparse(str(profile.get("base_url") or ""))
    scheme = str(profile.get("scheme") or parsed.scheme or "http").lower()
    host = str(profile.get("host") or parsed.hostname or "unknown")
    port = int(profile.get("port") or parsed.port or (443 if scheme == "https" else 80))
    source_kind = str(profile.get("source_kind") or "surface.profile")

    headers = _headers_lower(profile.get("response_headers"))
    version_headers = [str(v).lower() for v in (rules.get("version_headers") or [])]
    security_headers = [str(v).lower() for v in (rules.get("security_headers") or [])]
    weak_ciphers = [str(v).upper() for v in (rules.get("weak_ciphers") or [])]
    weak_protocols = {str(v) for v in (rules.get("weak_protocols") or [])}

    events: list[dict[str, Any]] = []

    reachable = bool(profile.get("reachable"))
    error = str(profile.get("error") or "").strip()
    wb01 = str(wickets.get("reachable") or "WB-01")
    if reachable:
        detail = str(profile.get("reachable_detail") or f"HTTP service reachable at {host}:{port}")
        events.append(
            _emit(
                wb01,
                status="realized",
                confidence=float(conf.get("reachable_realized", 1.0)),
                detail=detail,
                pointer=f"tcp://{host}:{port}",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )
    else:
        detail = error or f"Connection failed to {host}:{port}"
        events.append(
            _emit(
                wb01,
                status="blocked",
                confidence=float(conf.get("reachable_blocked", 0.95)),
                detail=detail,
                pointer=f"tcp://{host}:{port}",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )

    disclosed = {name: headers.get(name, "") for name in version_headers if headers.get(name)}
    wb02 = str(wickets.get("version_disclosure") or "WB-02")
    if disclosed:
        events.append(
            _emit(
                wb02,
                status="realized",
                confidence=float(conf.get("version_realized", 0.95)),
                detail=f"Version headers disclosed: {', '.join(sorted(disclosed))}",
                pointer=f"{str(profile.get('base_url') or f'{scheme}://{host}:{port}')} response headers",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )
    else:
        events.append(
            _emit(
                wb02,
                status="blocked",
                confidence=float(conf.get("version_blocked", 0.8)),
                detail="No version-disclosing headers found",
                pointer=f"{str(profile.get('base_url') or f'{scheme}://{host}:{port}')} response headers",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )

    provided_missing = profile.get("missing_security_headers")
    if isinstance(provided_missing, list):
        missing = [str(item) for item in provided_missing if str(item).strip()]
    else:
        missing = [header for header in security_headers if not headers.get(header)]

    wb19 = str(wickets.get("missing_security_headers") or "WB-19")
    if missing:
        events.append(
            _emit(
                wb19,
                status="realized",
                confidence=float(conf.get("missing_headers_realized", 0.9)),
                detail=f"Missing security headers: {', '.join(sorted(missing))}",
                pointer=f"{str(profile.get('base_url') or f'{scheme}://{host}:{port}')} response headers",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )
    else:
        events.append(
            _emit(
                wb19,
                status="blocked",
                confidence=float(conf.get("missing_headers_blocked", 0.85)),
                detail="All checked security headers present",
                pointer=f"{str(profile.get('base_url') or f'{scheme}://{host}:{port}')} response headers",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )

    cors = profile.get("cors") if isinstance(profile.get("cors"), Mapping) else {}
    acao = str(cors.get("acao") or headers.get("access-control-allow-origin") or "")
    acac = str(cors.get("acac") or headers.get("access-control-allow-credentials") or "")

    wb18 = str(wickets.get("cors_misconfigured") or "WB-18")
    if acao and (acao.strip() == "*" or "evil.example.com" in acao.lower()):
        cors_conf = float(conf.get("cors_realized", 0.9)) if acac.lower() == "true" else 0.7
        events.append(
            _emit(
                wb18,
                status="realized",
                confidence=cors_conf,
                detail=f"ACAO={acao}, ACAC={acac or 'absent'}",
                pointer=f"{str(profile.get('base_url') or f'{scheme}://{host}:{port}')} CORS probe",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )
    else:
        events.append(
            _emit(
                wb18,
                status="blocked",
                confidence=float(conf.get("cors_blocked", 0.75)),
                detail=f"ACAO={acao or 'absent'}",
                pointer=f"{str(profile.get('base_url') or f'{scheme}://{host}:{port}')} CORS probe",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )

    wb17 = str(wickets.get("tls_misconfigured") or "WB-17")
    if scheme != "https":
        events.append(
            _emit(
                wb17,
                status="realized",
                confidence=float(conf.get("tls_realized", 0.85)),
                detail="Service runs over plain HTTP, no TLS",
                pointer=f"http://{host}:{port}",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )
        return events

    tls = profile.get("tls") if isinstance(profile.get("tls"), Mapping) else {}
    if str(tls.get("error") or "").strip():
        events.append(
            _emit(
                wb17,
                status="unknown",
                confidence=float(conf.get("tls_unknown", 0.5)),
                detail=f"TLS probe error: {tls.get('error')}",
                pointer=f"tls://{host}:{port}",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )
        return events

    issues = [str(item) for item in (tls.get("issues") or []) if str(item).strip()]
    cipher_name = str(tls.get("cipher_name") or "")
    tls_version = str(tls.get("tls_version") or "")
    bits = int(tls.get("cipher_bits") or 0)

    if not issues and cipher_name:
        upper_cipher = cipher_name.upper()
        if any(token in upper_cipher for token in weak_ciphers):
            issues.append(f"weak cipher: {cipher_name}")
    if not issues and tls_version in weak_protocols:
        issues.append(f"weak protocol: {tls_version}")
    if not issues and bits and bits < 128:
        issues.append(f"low bit strength: {bits}")

    if bool(tls.get("certificate_expired")):
        issues.append("certificate expired")
    if bool(tls.get("self_signed")):
        issues.append("self-signed certificate")
    if str(tls.get("cn_mismatch") or "").strip():
        issues.append(f"CN mismatch: {tls.get('cn_mismatch')}")

    if issues:
        events.append(
            _emit(
                wb17,
                status="realized",
                confidence=float(conf.get("tls_realized", 0.85)),
                detail="; ".join(issues),
                pointer=f"tls://{host}:{port}",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )
    else:
        detail = f"{tls_version or 'unknown tls'}, {cipher_name or 'unknown cipher'}, {bits or 0}bit"
        events.append(
            _emit(
                wb17,
                status="blocked",
                confidence=float(conf.get("tls_blocked", 0.8)),
                detail=detail,
                pointer=f"tls://{host}:{port}",
                source_id=source_id,
                source_kind=source_kind,
                toolchain=toolchain,
                attack_path_id=attack_path_id,
                workload_id=workload_id,
            )
        )

    return events
