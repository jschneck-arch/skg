from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from skg_protocol.contracts import (
    AD_DELEGATION_INPUT_SCHEMA,
    validate_ad_delegation_input,
)
from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_delegation_posture_policy


def _conf(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _status_realized(status: str) -> bool | None:
    if status == "realized":
        return True
    if status == "blocked":
        return False
    return None


def _wicket_label(wicket_id: str) -> str:
    wickets = load_wickets()
    row = wickets.get(wicket_id) if isinstance(wickets, Mapping) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text:
            try:
                return int(float(text))
            except ValueError:
                return None
    return None


def _extract_summary(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    summary = payload.get("summary")
    if isinstance(summary, Mapping):
        return summary
    return {}


def _extract_rows(payload: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    rows = payload.get(key)
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, Mapping)]


def _emit(
    *,
    wicket_id: str,
    status: str,
    detail: str,
    run_id: str,
    workload_id: str,
    attack_path_id: str,
    source_id: str,
    toolchain: str,
    source_kind: str,
    pointer_prefix: str,
    evidence_rank: int,
    confidence: float,
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = build_precondition_payload(
        wicket_id=wicket_id,
        label=_wicket_label(wicket_id),
        domain="ad",
        workload_id=workload_id,
        realized=_status_realized(status),
        status=status,
        detail=detail,
        attack_path_id=attack_path_id,
    )
    payload["run_id"] = run_id
    if attributes:
        payload["attributes"] = dict(attributes)

    return build_event_envelope(
        event_type="obs.attack.precondition",
        source_id=source_id,
        toolchain=toolchain,
        payload=payload,
        evidence_rank=evidence_rank,
        source_kind=source_kind,
        pointer=f"{pointer_prefix}{workload_id}/{wicket_id.lower()}",
        confidence=_conf(confidence),
    )


def _derive_status(
    *,
    has_observation: bool,
    principal_count: int,
    posture_count: int,
) -> str:
    if not has_observation:
        return "unknown"
    if posture_count > 0:
        return "realized"
    if principal_count > 0:
        return "blocked"
    return "unknown"


def map_delegation_posture_to_events(
    delegation_input: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map canonical AD delegation sidecar input into AD-06/AD-08 posture-core events."""

    policy = load_delegation_posture_policy()
    source_kind = str(policy.get("source_kind") or "ad.delegation.snapshot")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.ad_delegation_posture")
    pointer_prefix = str(policy.get("pointer_prefix") or "ad://")
    required_schema = str(policy.get("schema") or AD_DELEGATION_INPUT_SCHEMA)
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}

    payload = delegation_input if isinstance(delegation_input, Mapping) else {}
    schema = str(payload.get("schema") or "")
    summary = _extract_summary(payload)
    principal_rows = _extract_rows(payload, "principal_rows")
    unconstrained_hosts = _extract_rows(payload, "unconstrained_non_dc_hosts")
    protocol_transition_principals = _extract_rows(payload, "protocol_transition_principals")
    delegation_spn_edges = _extract_rows(payload, "delegation_spn_edges")

    validation_errors = validate_ad_delegation_input(payload)
    schema_valid = bool(not validation_errors and schema == required_schema)
    has_observation = schema_valid and ("principal_rows" in payload)

    principal_count = _coerce_int(summary.get("principal_count"))
    if principal_count is None:
        principal_count = len(principal_rows)

    unconstrained_non_dc_count = _coerce_int(summary.get("unconstrained_non_dc_count"))
    if unconstrained_non_dc_count is None:
        unconstrained_non_dc_count = len(unconstrained_hosts)

    protocol_transition_count = _coerce_int(summary.get("protocol_transition_count"))
    if protocol_transition_count is None:
        protocol_transition_count = len(protocol_transition_principals)

    ad06_status = _derive_status(
        has_observation=has_observation,
        principal_count=principal_count,
        posture_count=unconstrained_non_dc_count,
    )
    ad08_status = _derive_status(
        has_observation=has_observation,
        principal_count=principal_count,
        posture_count=protocol_transition_count,
    )

    ad06_detail = (
        f"Delegation posture-core AD-06 status={ad06_status}; "
        f"unconstrained_non_dc={unconstrained_non_dc_count}; "
        f"observed_principals={principal_count}"
        if has_observation
        else "Canonical delegation sidecar missing or schema mismatch for AD-06 posture-core"
    )
    ad08_detail = (
        f"Delegation posture-core AD-08 status={ad08_status}; "
        f"protocol_transition={protocol_transition_count}; "
        f"observed_principals={principal_count}"
        if has_observation
        else "Canonical delegation sidecar missing or schema mismatch for AD-08 posture-core"
    )

    shared_attributes = {
        "schema": schema or "",
        "schema_valid": schema_valid,
        "validation_errors": validation_errors,
        "slice": str(payload.get("slice") or ""),
        "source_kind": str(payload.get("source_kind") or ""),
        "principal_count": principal_count,
        "delegation_spn_edge_count": len(delegation_spn_edges),
        "deferred_coupling": payload.get("deferred_coupling")
        if isinstance(payload.get("deferred_coupling"), Mapping)
        else {},
    }

    attributes = {
        "AD-06": {
            **shared_attributes,
            "unconstrained_non_dc_count": unconstrained_non_dc_count,
            "unconstrained_non_dc_hosts": unconstrained_hosts[:20],
        },
        "AD-08": {
            **shared_attributes,
            "protocol_transition_count": protocol_transition_count,
            "protocol_transition_principals": protocol_transition_principals[:20],
        },
    }

    statuses = {"AD-06": ad06_status, "AD-08": ad08_status}
    details = {"AD-06": ad06_detail, "AD-08": ad08_detail}

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-06", "AD-08"):
        wicket_cfg = wickets_policy.get(wicket_id) if isinstance(wickets_policy, Mapping) else {}
        if not isinstance(wicket_cfg, Mapping):
            wicket_cfg = {}

        events.append(
            _emit(
                wicket_id=wicket_id,
                status=statuses[wicket_id],
                detail=details[wicket_id],
                run_id=run_id,
                workload_id=workload_id,
                attack_path_id=attack_path_id,
                source_id=canonical_source_id,
                toolchain=toolchain,
                source_kind=source_kind,
                pointer_prefix=pointer_prefix,
                evidence_rank=int(wicket_cfg.get("evidence_rank") or 2),
                confidence=float(wicket_cfg.get("confidence") or 0.9),
                attributes=attributes[wicket_id],
            )
        )

    return events


def map_delegation_posture_file_to_events(
    input_path: str | Path,
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    path = Path(input_path)
    payload: Mapping[str, Any]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        payload = raw if isinstance(raw, Mapping) else {}
    except Exception:
        payload = {}

    return map_delegation_posture_to_events(
        payload,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        source_id=source_id,
        toolchain=toolchain,
    )


__all__ = [
    "map_delegation_posture_file_to_events",
    "map_delegation_posture_to_events",
]
