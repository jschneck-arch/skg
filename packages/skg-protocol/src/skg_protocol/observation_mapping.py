from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from skg_protocol.validation.assistant import classify_assistant_event

EPHEMERAL_INSTRUMENTS = {"pcap", "net_sensor", "tshark"}

INSTRUMENT_DECAY = {
    "bloodhound": "structural",
    "nvd_feed": "structural",
    "supply_chain": "structural",
    "nmap": "structural",
    "auth_scanner": "operational",
    "http_collector": "operational",
    "ssh_sensor": "operational",
    "sysaudit": "operational",
    "container_inspect": "operational",
    "msf_sensor": "operational",
    "pcap": "ephemeral",
}


@dataclass(frozen=True, slots=True)
class ObservationMapping:
    instrument: str
    targets: list[str]
    context: str
    payload: dict[str, Any]
    event_time: datetime
    decay_class: str
    support_mapping: dict[str, dict[str, float]]
    cycle_id: str = ""


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


def _subject_key(payload: dict[str, Any]) -> str:
    identity_key = str(payload.get("identity_key") or "").strip()
    if identity_key:
        return identity_key

    target_ip = str(payload.get("target_ip") or "").strip()
    if target_ip:
        return target_ip

    workload_id = str(payload.get("workload_id") or "").strip()
    if workload_id:
        locator = workload_id.split("::", 1)[1] if "::" in workload_id else workload_id
        host = _host_from_locator(locator)
        if host:
            return host
        if _looks_like_ip(locator):
            return locator

    return ""


def decay_class_for_event(instrument: str, evidence_rank: int) -> str:
    if instrument in EPHEMERAL_INSTRUMENTS:
        return "ephemeral"
    if evidence_rank == 2:
        return "structural"
    return INSTRUMENT_DECAY.get(instrument, "operational")


def phi_from_status(status: str, confidence: float) -> tuple[float, float, float]:
    normalized = str(status or "").strip().lower()
    if normalized == "realized":
        return (confidence, 0.0, 0.0)
    if normalized == "blocked":
        return (0.0, confidence, 0.0)
    return (0.0, 0.0, confidence)


def map_event_to_observation_mapping(event: dict, cycle_id: str = "") -> ObservationMapping | None:
    payload = dict(event.get("payload") or {})
    provenance = dict(event.get("provenance") or {})
    evidence = dict(provenance.get("evidence") or {})
    source = dict(event.get("source") or {})

    admissibility = classify_assistant_event(event)
    if not admissibility.get("observation_admissible", True):
        return None

    context = payload.get("wicket_id") or payload.get("node_id")
    status = payload.get("status")
    if not context or not status:
        return None

    subject = _subject_key(payload)
    if not subject:
        return None

    confidence = float(evidence.get("confidence") or payload.get("confidence") or 0.8)
    rank = int(provenance.get("evidence_rank") or evidence.get("rank") or 3)

    source_id = str(source.get("source_id") or "")
    instrument = source_id.split(".")[-1] if "." in source_id else source_id

    decay_class = decay_class_for_event(instrument, rank)
    phi_r, phi_b, phi_u = phi_from_status(str(status), confidence)

    ts_text = str(event.get("ts") or evidence.get("collected_at") or "")
    try:
        event_time = datetime.fromisoformat(ts_text)
    except (TypeError, ValueError):
        event_time = datetime.now(timezone.utc)
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    resolved_cycle_id = str(payload.get("gravity_cycle_id") or "").strip() or cycle_id

    return ObservationMapping(
        instrument=instrument,
        targets=[subject],
        context=str(context),
        payload=payload,
        event_time=event_time,
        decay_class=decay_class,
        support_mapping={subject: {"R": phi_r, "B": phi_b, "U": phi_u}},
        cycle_id=resolved_cycle_id,
    )
