from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse


TOOLCHAIN_ALIASES = {
    "aprs": "skg-aprs-toolchain",
    "container_escape": "skg-container-escape-toolchain",
    "ad_lateral": "skg-ad-lateral-toolchain",
    "host": "skg-host-toolchain",
    "web": "skg-web-toolchain",
    "data": "skg-data-toolchain",
}


def canonical_toolchain_name(toolchain: str) -> str:
    return TOOLCHAIN_ALIASES.get(toolchain, toolchain)


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


def _looks_like_ip(text: str) -> bool:
    candidate = str(text or "").strip()
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _subject_keys(workload_id: str, target_ip: str = "") -> dict[str, str]:
    raw_workload = str(workload_id or "").strip()

    if "::" in raw_workload:
        _, locator = raw_workload.split("::", 1)
    else:
        locator = raw_workload

    host = _host_from_locator(locator)
    identity_key = target_ip or host or locator or raw_workload or "unknown"
    manifestation_key = raw_workload or identity_key
    canonical_target_ip = str(target_ip or "").strip()
    if not canonical_target_ip and _looks_like_ip(host):
        canonical_target_ip = host

    return {
        "identity_key": identity_key,
        "manifestation_key": manifestation_key,
        "target_ip": canonical_target_ip,
    }


def build_event_envelope(
    event_type: str,
    source_id: str,
    toolchain: str,
    payload: dict,
    evidence_rank: int,
    source_kind: str,
    pointer: str,
    confidence: float = 1.0,
    version: str = "1.0.0",
    ts: str | None = None,
    confidence_vector: list[float] | None = None,
    local_energy: float | None = None,
    phase: float | None = None,
    is_latent: bool | None = None,
) -> dict:
    """Build canonical `skg.event.envelope.v1` records."""

    now = ts or datetime.now(timezone.utc).isoformat()

    evidence = {
        "source_kind": source_kind,
        "pointer": pointer,
        "collected_at": now,
        "confidence": confidence,
    }
    if confidence_vector is not None:
        evidence["confidence_vector"] = confidence_vector
    if local_energy is not None:
        evidence["local_energy"] = local_energy
    if phase is not None:
        evidence["phase"] = phase

    payload = dict(payload)
    if is_latent is not None and "is_latent" not in payload:
        payload["is_latent"] = bool(is_latent)

    return {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": event_type,
        "source": {
            "source_id": source_id,
            "toolchain": canonical_toolchain_name(toolchain),
            "version": version,
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": int(evidence_rank),
            "evidence": evidence,
        },
    }


def build_precondition_payload(
    wicket_id: str | None = None,
    label: str = "",
    domain: str = "",
    workload_id: str = "",
    realized: bool | None = None,
    status: str | None = None,
    detail: str = "",
    attack_path_id: str = "",
    node_id: str | None = None,
    target_ip: str = "",
) -> dict:
    """Build canonical payload for `obs.attack.precondition` events."""

    condition_id = node_id or wicket_id or ""
    keys = _subject_keys(workload_id=workload_id, target_ip=target_ip)

    if status is None:
        if realized is True:
            status = "realized"
        elif realized is False:
            status = "blocked"
        else:
            status = "unknown"

    payload = {
        "wicket_id": condition_id,
        "node_id": condition_id,
        "label": label,
        "domain": domain,
        "workload_id": workload_id,
        "realized": realized,
        "status": status,
        "detail": detail,
        "attack_path_id": attack_path_id,
    }

    if keys["identity_key"] and keys["identity_key"] != "unknown":
        payload["identity_key"] = keys["identity_key"]
    if keys["manifestation_key"] and keys["manifestation_key"] != "unknown":
        payload["manifestation_key"] = keys["manifestation_key"]
    if keys["target_ip"]:
        payload["target_ip"] = keys["target_ip"]

    return payload
