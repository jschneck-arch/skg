from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from skg_protocol.contracts import AD_TIERING_INPUT_SCHEMA, validate_ad_tiering_input
from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_tiering_posture_policy


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


def _normalize_status(value: Any) -> str:
    status = str(value or "").strip().lower()
    if status in {"realized", "blocked", "unknown"}:
        return status
    if status == "not_realized":
        return "blocked"
    return "unknown"


def _extract_summary(tiering_input: Mapping[str, Any]) -> Mapping[str, Any]:
    summary = tiering_input.get("summary")
    if isinstance(summary, Mapping):
        return summary
    return {}


def _extract_session_rows(tiering_input: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = tiering_input.get("session_rows")
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


def _derive_ad22_status(summary: Mapping[str, Any], session_rows: list[Mapping[str, Any]]) -> str:
    explicit = _normalize_status(summary.get("status"))
    if explicit != "unknown":
        return explicit

    non_tier0 = _coerce_int(summary.get("non_tier0_session_count"))
    observed = _coerce_int(summary.get("observed_session_count"))
    unknown_tier = _coerce_int(summary.get("unknown_tier_session_count"))

    if non_tier0 is not None and non_tier0 > 0:
        return "realized"

    if observed is None:
        observed = len(session_rows)

    if observed > 0 and unknown_tier == 0:
        return "blocked"
    return "unknown"


def map_tiering_posture_to_events(
    tiering_input: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map canonical AD-22 tiering sidecar input into AD domain precondition events."""

    policy = load_tiering_posture_policy()
    source_kind = str(policy.get("source_kind") or "ad.tiering.snapshot")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.ad_tiering_posture")
    pointer_prefix = str(policy.get("pointer_prefix") or "ad://")
    required_schema = str(policy.get("schema") or AD_TIERING_INPUT_SCHEMA)
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}

    payload = tiering_input if isinstance(tiering_input, Mapping) else {}
    schema = str(payload.get("schema") or "")
    summary = _extract_summary(payload)
    session_rows = _extract_session_rows(payload)

    validation_errors = validate_ad_tiering_input(payload)
    schema_valid = bool(not validation_errors and schema == required_schema)
    has_summary = bool(summary)
    has_observation = schema_valid and (has_summary or "session_rows" in payload)

    observed_count = _coerce_int(summary.get("observed_session_count"))
    if observed_count is None:
        observed_count = len(session_rows)

    ad22_status = _derive_ad22_status(summary, session_rows) if has_observation else "unknown"
    observation_status = "realized" if has_observation else "unknown"

    ad22_detail = (
        f"Privileged session tiering posture status={ad22_status}; "
        f"observed_sessions={observed_count}; "
        f"non_tier0={_coerce_int(summary.get('non_tier0_session_count')) or 0}; "
        f"unknown_tier={_coerce_int(summary.get('unknown_tier_session_count')) or 0}"
        if has_observation
        else "Canonical AD-22 tiering input not observed or schema mismatch"
    )
    observation_detail = (
        f"Canonical AD-22 tiering input observed via sidecar schema {schema or 'unknown'}"
        if has_observation
        else f"Canonical AD-22 sidecar schema missing or incompatible (expected {required_schema})"
    )

    attributes = {
        "AD-TI-01": {
            "schema": schema or "",
            "schema_valid": schema_valid,
            "validation_errors": validation_errors,
            "observed_session_count": observed_count,
            "computer_inventory_count": _coerce_int(payload.get("computer_inventory_count")) or 0,
            "source_kind": str(payload.get("source_kind") or ""),
        },
        "AD-22": {
            "legacy_wicket_alias": "AD-22",
            "status_summary": _normalize_status(summary.get("status")),
            "observed_session_count": observed_count,
            "non_tier0_session_count": _coerce_int(summary.get("non_tier0_session_count")) or 0,
            "tier0_session_count": _coerce_int(summary.get("tier0_session_count")) or 0,
            "unknown_tier_session_count": _coerce_int(summary.get("unknown_tier_session_count")) or 0,
            "non_tier0_sessions": summary.get("non_tier0_sessions") if isinstance(summary.get("non_tier0_sessions"), list) else [],
            "unknown_tier_sessions": summary.get("unknown_tier_sessions") if isinstance(summary.get("unknown_tier_sessions"), list) else [],
            "deferred_coupling": payload.get("deferred_coupling") if isinstance(payload.get("deferred_coupling"), Mapping) else {},
        },
    }

    statuses = {
        "AD-TI-01": observation_status,
        "AD-22": ad22_status,
    }
    details = {
        "AD-TI-01": observation_detail,
        "AD-22": ad22_detail,
    }

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-TI-01", "AD-22"):
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


def map_tiering_posture_file_to_events(
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

    return map_tiering_posture_to_events(
        payload,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        source_id=source_id,
        toolchain=toolchain,
    )
