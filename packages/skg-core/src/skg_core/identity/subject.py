from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def _host_from_locator(locator: str) -> str:
    text = str(locator or "").strip()
    if not text:
        return ""

    if "://" in text:
        try:
            parsed = urlparse(text)
            return parsed.hostname or text
        except Exception:
            return text

    base = text.split("/", 1)[0]
    if "::" in base:
        base = base.split("::", 1)[0]
    if base.count(":") == 1 and "." in base:
        return base.split(":", 1)[0]
    return base


def _looks_like_ip_address(text: str) -> bool:
    candidate = str(text or "").strip()
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def parse_workload_ref(workload_id: str) -> dict[str, str]:
    """Parse workload IDs into stable identity/manifestation components."""

    raw = str(workload_id or "")
    if "::" in raw:
        domain, locator = raw.split("::", 1)
    else:
        domain, locator = "", raw

    host = _host_from_locator(locator)
    identity_key = host or locator or raw or "unknown"
    manifestation_key = raw or identity_key

    return {
        "workload_id": raw,
        "domain_hint": domain,
        "locator": locator or raw,
        "host": host,
        "identity_key": identity_key,
        "manifestation_key": manifestation_key,
    }


def canonical_observation_subject(
    payload: dict | None = None,
    *,
    workload_id: str = "",
    target_ip: str = "",
) -> dict[str, str]:
    """Resolve canonical identity and manifestation keys for observations."""

    payload = dict(payload or {})
    raw_workload = str(payload.get("workload_id") or workload_id or "").strip()
    parsed = parse_workload_ref(raw_workload)

    explicit_identity = str(payload.get("identity_key") or "").strip()
    explicit_manifestation = str(payload.get("manifestation_key") or "").strip()
    explicit_target_ip = str(payload.get("target_ip") or target_ip or "").strip()

    identity_key = (
        explicit_identity
        or explicit_target_ip
        or parsed.get("identity_key", "")
        or raw_workload
        or "unknown"
    )
    manifestation_key = (
        explicit_manifestation
        or raw_workload
        or parsed.get("manifestation_key", "")
        or identity_key
    )
    host = explicit_target_ip or str(parsed.get("host") or "").strip() or identity_key
    canonical_target_ip = explicit_target_ip
    if not canonical_target_ip and _looks_like_ip_address(host):
        canonical_target_ip = host

    return {
        "workload_id": raw_workload,
        "host": host,
        "target_ip": canonical_target_ip,
        "identity_key": identity_key,
        "manifestation_key": manifestation_key,
        "subject_key": identity_key,
    }
