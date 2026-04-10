"""
skg.sensors.event_builder
=========================
Canonical event builder for scanner/adapter use.

Thin wrapper over envelope() + precondition_payload() with
scanner-appropriate defaults.  Every adapter should call
make_precondition_event() instead of hand-rolling dicts.

This guarantees:
  - Correct source block (source_id, toolchain, version)
  - Correct provenance block (evidence_rank, evidence)
  - No missing keys that fail downstream validation
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from skg.sensors import envelope, precondition_payload


def _default_pointer(source_id: str, target: str) -> str:
    """Build a URI-style pointer from source and target."""
    safe = str(target or "").replace("://", "_")
    return f"{source_id}://{safe}"


def make_precondition_event(
    *,
    wicket_id: str,
    status: str,
    workload_id: str,
    source_id: str,
    toolchain: str,
    target_ip: str = "",
    domain: str = "",
    label: str = "",
    detail: str = "",
    attack_path_id: str = "",
    evidence_rank: int = 4,
    source_kind: str = "scanner",
    pointer: str = "",
    confidence: float = 0.85,
    version: str = "1.0.0",
    attributes: dict | None = None,
) -> dict:
    """
    Build a compliant obs.attack.precondition event.

    Parameters
    ----------
    wicket_id : str
        Wicket ID from the canonical catalog (e.g. "WB-08", "HO-02").
    status : str
        "realized" | "blocked" | "unknown"
    workload_id : str
        Canonical workload ID (use canonical_workload_id() from skg.identity.workload).
    source_id : str
        Adapter identifier, e.g. "sqlmap_adapter", "gobuster_adapter".
    toolchain : str
        Toolchain name, e.g. "skg-web-toolchain".
    target_ip : str
        Target IP or hostname (for provenance pointer).
    domain : str
        Domain hint for the payload (e.g. "web", "host").
    label : str
        Human-readable wicket label.
    detail : str
        Evidence detail string.
    attack_path_id : str
        Attack path this event is contributing to.
    evidence_rank : int
        1=runtime, 2=build, 3=config, 4=network, 5=static, 6=scanner.
    source_kind : str
        Short tag for the evidence source.
    pointer : str
        URI pointer to the raw evidence. Auto-generated if empty.
    confidence : float
        Confidence 0.0–1.0.
    version : str
        Adapter version string.
    attributes : dict | None
        Extra attributes merged into the payload.

    Returns
    -------
    dict
        Fully-formed skg.event.envelope.v1 dict with source + provenance.
    """
    # Realized/blocked/unknown → bool | None for precondition_payload
    realized: bool | None
    if status == "realized":
        realized = True
    elif status == "blocked":
        realized = False
    else:
        realized = None

    ptr = pointer or _default_pointer(source_id, target_ip or workload_id)

    payload = precondition_payload(
        wicket_id=wicket_id,
        label=label,
        domain=domain,
        workload_id=workload_id,
        realized=realized,
        detail=detail,
        attack_path_id=attack_path_id,
        target_ip=target_ip,
    )

    if attributes:
        payload.update(attributes)

    return envelope(
        event_type="obs.attack.precondition",
        source_id=source_id,
        toolchain=toolchain,
        payload=payload,
        evidence_rank=evidence_rank,
        source_kind=source_kind,
        pointer=ptr,
        confidence=confidence,
        version=version,
    )
