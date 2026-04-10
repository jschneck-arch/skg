from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from skg_protocol.contracts import (
    AD_DELEGATION_CONTEXT_FILENAME,
    AD_DELEGATION_CONTEXT_SCHEMA,
    AD_DELEGATION_CONTEXT_WICKET_ID,
    AD_DELEGATION_INPUT_FILENAME,
    AD_DELEGATION_INPUT_SCHEMA,
    AD_TIERING_INPUT_FILENAME,
    AD_TIERING_INPUT_SCHEMA,
    validate_ad_delegation_context,
    validate_ad_delegation_input,
    validate_ad_tiering_input,
)


def canonical_ad_tiering_input_available() -> bool:
    try:
        from skg_domain_ad.adapters.common import summarize_privileged_tiering_exposure
    except Exception:
        return False
    return callable(summarize_privileged_tiering_exposure)


def _require_tiering_helpers():
    try:
        from skg_domain_ad.adapters.common import (
            normalize_privileged_session_rows,
            summarize_privileged_tiering_exposure,
        )
    except Exception as exc:
        raise RuntimeError(
            "Canonical AD domain tiering helpers unavailable: "
            "skg_domain_ad.adapters.common"
        ) from exc
    return normalize_privileged_session_rows, summarize_privileged_tiering_exposure


def _normalize_sessions_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, Mapping):
        sessions = payload.get("sessions")
        if isinstance(sessions, list):
            return [row for row in sessions if isinstance(row, Mapping)]
        return []
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, Mapping)]
    return []


def load_bloodhound_session_rows(bh_dir: Path) -> list[dict[str, Any]]:
    sessions_path = Path(bh_dir) / "sessions.json"
    if not sessions_path.exists():
        return []

    try:
        raw = json.loads(sessions_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    return _normalize_sessions_payload(raw)


def canonical_ad_delegation_input_available() -> bool:
    try:
        from skg_domain_ad.adapters.common import normalize_delegation_principals
    except Exception:
        return False
    return callable(normalize_delegation_principals)


def canonical_ad07_context_available() -> bool:
    try:
        from skg_services.gravity.delegation_context import classify_ad07_unconstrained_activity
    except Exception:
        return False
    return callable(classify_ad07_unconstrained_activity)


def _require_delegation_helpers():
    try:
        from skg_domain_ad.adapters.common import (
            extract_delegation_spn_edges,
            extract_protocol_transition_principals,
            extract_unconstrained_non_dc_hosts,
            normalize_delegation_principals,
        )
    except Exception as exc:
        raise RuntimeError(
            "Canonical AD domain delegation helpers unavailable: "
            "skg_domain_ad.adapters.common"
        ) from exc
    return (
        normalize_delegation_principals,
        extract_unconstrained_non_dc_hosts,
        extract_protocol_transition_principals,
        extract_delegation_spn_edges,
    )


def build_ad0608_delegation_input(
    *,
    principals: Any,
    workload_id: str,
    run_id: str,
    source_kind: str = "bloodhound.delegation",
) -> dict[str, Any]:
    (
        normalize_principals,
        extract_unconstrained_non_dc_hosts,
        extract_protocol_transition_principals,
        extract_delegation_spn_edges,
    ) = _require_delegation_helpers()

    principal_rows = normalize_principals(principals)
    unconstrained_hosts = extract_unconstrained_non_dc_hosts(principals)
    protocol_transition_principals = extract_protocol_transition_principals(principals)
    delegation_spn_edges = extract_delegation_spn_edges(principals)

    if unconstrained_hosts or protocol_transition_principals:
        status = "realized"
    elif principal_rows:
        status = "blocked"
    else:
        status = "unknown"

    return {
        "schema": AD_DELEGATION_INPUT_SCHEMA,
        "slice": "ad06_ad08_delegation_posture_core_input",
        "source_kind": str(source_kind or "bloodhound.delegation"),
        "workload_id": str(workload_id or ""),
        "run_id": str(run_id or ""),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "wicket_ids": ["AD-06", "AD-08"],
        "principal_rows": principal_rows,
        "unconstrained_non_dc_hosts": unconstrained_hosts,
        "protocol_transition_principals": protocol_transition_principals,
        "delegation_spn_edges": delegation_spn_edges,
        "summary": {
            "status": status,
            "principal_count": len(principal_rows),
            "unconstrained_non_dc_count": len(unconstrained_hosts),
            "protocol_transition_count": len(protocol_transition_principals),
            "delegation_spn_edge_count": len(delegation_spn_edges),
        },
        "deferred_coupling": {
            "ad07_context_deferred": True,
            "ad09_sensitive_target_deferred": True,
            "path_value_reasoning_deferred": True,
        },
    }


def route_bloodhound_delegation_evidence(
    *,
    bh_dir: Path,
    computers: Any,
    users: Any,
    workload_id: str,
    run_id: str,
    out_path: Path | None = None,
) -> dict[str, Any]:
    principals: list[Any] = []
    if isinstance(computers, list):
        principals.extend(computers)
    if isinstance(users, list):
        principals.extend(users)

    payload = build_ad0608_delegation_input(
        principals=principals,
        workload_id=workload_id,
        run_id=run_id,
        source_kind="bloodhound.delegation",
    )

    validation_errors = validate_ad_delegation_input(payload)
    if validation_errors:
        raise RuntimeError(
            "Invalid AD delegation sidecar payload generated: "
            + "; ".join(validation_errors)
        )

    destination = (
        Path(out_path)
        if out_path is not None
        else (Path(bh_dir) / AD_DELEGATION_INPUT_FILENAME)
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def build_ad07_delegation_context(
    *,
    computers: Any,
    workload_id: str,
    run_id: str,
    stale_days: int,
    unknown_last_logon_is_active: bool,
    source_kind: str = "bloodhound.delegation_context",
) -> dict[str, Any]:
    from skg_services.gravity.delegation_context import classify_ad07_unconstrained_activity

    classification = classify_ad07_unconstrained_activity(
        computers,
        stale_days=stale_days,
        unknown_last_logon_is_active=unknown_last_logon_is_active,
    )

    total_unconstrained = int(classification.get("total_unconstrained_non_dc") or 0)
    active_unconstrained = (
        classification.get("active_unconstrained")
        if isinstance(classification.get("active_unconstrained"), list)
        else []
    )
    stale_unconstrained = (
        classification.get("stale_unconstrained")
        if isinstance(classification.get("stale_unconstrained"), list)
        else []
    )
    unknown_last_logon = (
        classification.get("unknown_last_logon")
        if isinstance(classification.get("unknown_last_logon"), list)
        else []
    )

    if active_unconstrained:
        status = "realized"
    elif total_unconstrained > 0:
        status = "blocked"
    else:
        status = "unknown"

    return {
        "schema": AD_DELEGATION_CONTEXT_SCHEMA,
        "wicket_id": AD_DELEGATION_CONTEXT_WICKET_ID,
        "slice": "ad07_delegation_context_service_input",
        "source_kind": str(source_kind or "bloodhound.delegation_context"),
        "workload_id": str(workload_id or ""),
        "run_id": str(run_id or ""),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "recency_policy": {
            "stale_days": int(stale_days),
            "stale_threshold_seconds": int(classification.get("stale_threshold_seconds") or 0),
        },
        "unknown_handling_policy": {
            "unknown_last_logon_is_active": bool(unknown_last_logon_is_active),
        },
        "activity_classification": {
            "total_unconstrained_non_dc": total_unconstrained,
            "active_unconstrained": active_unconstrained,
            "stale_unconstrained": stale_unconstrained,
            "unknown_last_logon": unknown_last_logon,
        },
        "summary": {
            "status": status,
            "active_count": len(active_unconstrained),
            "stale_count": len(stale_unconstrained),
            "unknown_count": len(unknown_last_logon),
        },
    }


def route_bloodhound_ad07_context(
    *,
    bh_dir: Path,
    computers: Any,
    workload_id: str,
    run_id: str,
    stale_days: int,
    unknown_last_logon_is_active: bool,
    out_path: Path | None = None,
) -> dict[str, Any]:
    payload = build_ad07_delegation_context(
        computers=computers,
        workload_id=workload_id,
        run_id=run_id,
        stale_days=stale_days,
        unknown_last_logon_is_active=unknown_last_logon_is_active,
        source_kind="bloodhound.delegation_context",
    )

    validation_errors = validate_ad_delegation_context(payload)
    if validation_errors:
        raise RuntimeError(
            "Invalid AD-07 delegation context payload generated: "
            + "; ".join(validation_errors)
        )

    destination = (
        Path(out_path)
        if out_path is not None
        else (Path(bh_dir) / AD_DELEGATION_CONTEXT_FILENAME)
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def build_ad22_tiering_input(
    *,
    session_rows: Any,
    computers: Any,
    workload_id: str,
    run_id: str,
    source_kind: str = "bloodhound",
) -> dict[str, Any]:
    normalize_sessions, summarize = _require_tiering_helpers()

    normalized_sessions = normalize_sessions(session_rows)
    summary = summarize(session_rows, computers)

    return {
        "schema": AD_TIERING_INPUT_SCHEMA,
        "wicket_id": "AD-22",
        "slice": "ad22_baseline_tiering_core_input",
        "source_kind": str(source_kind or "bloodhound"),
        "workload_id": str(workload_id or ""),
        "run_id": str(run_id or ""),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "session_rows": normalized_sessions,
        "computer_inventory_count": len(computers) if isinstance(computers, list) else 0,
        "summary": summary if isinstance(summary, dict) else {},
        "deferred_coupling": {
            "path_value_reasoning": True,
            "runtime_orchestration": True,
        },
    }


def route_bloodhound_ad22_evidence(
    *,
    bh_dir: Path,
    computers: Any,
    workload_id: str,
    run_id: str,
    out_path: Path | None = None,
) -> dict[str, Any]:
    session_rows = load_bloodhound_session_rows(Path(bh_dir))
    payload = build_ad22_tiering_input(
        session_rows=session_rows,
        computers=computers,
        workload_id=workload_id,
        run_id=run_id,
        source_kind="bloodhound.sessions",
    )

    validation_errors = validate_ad_tiering_input(payload)
    if validation_errors:
        raise RuntimeError(
            "Invalid AD tiering sidecar payload generated: "
            + "; ".join(validation_errors)
        )

    destination = Path(out_path) if out_path is not None else (Path(bh_dir) / AD_TIERING_INPUT_FILENAME)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def map_ad0608_sidecar_to_events(
    *,
    sidecar_path: Path,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
) -> list[dict[str, Any]]:
    try:
        from skg_domain_ad.adapters.ad_delegation_posture.run import (
            map_delegation_posture_file_to_events,
        )
    except Exception as exc:
        raise RuntimeError(
            "Canonical AD delegation posture adapter unavailable: "
            "skg_domain_ad.adapters.ad_delegation_posture.run"
        ) from exc

    sidecar = Path(sidecar_path)
    if not sidecar.exists():
        return []

    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to parse AD delegation sidecar: {sidecar}") from exc

    validation_errors = validate_ad_delegation_input(payload)
    if validation_errors:
        raise RuntimeError(
            "Invalid AD delegation sidecar payload: "
            + "; ".join(validation_errors)
        )

    return map_delegation_posture_file_to_events(
        sidecar,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
    )


def map_ad22_sidecar_to_events(
    *,
    sidecar_path: Path,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
) -> list[dict[str, Any]]:
    try:
        from skg_domain_ad.adapters.ad_tiering_posture.run import map_tiering_posture_file_to_events
    except Exception as exc:
        raise RuntimeError(
            "Canonical AD tiering adapter unavailable: "
            "skg_domain_ad.adapters.ad_tiering_posture.run"
        ) from exc

    sidecar = Path(sidecar_path)
    if not sidecar.exists():
        return []

    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to parse AD tiering sidecar: {sidecar}") from exc

    validation_errors = validate_ad_tiering_input(payload)
    if validation_errors:
        raise RuntimeError(
            "Invalid AD tiering sidecar payload: "
            + "; ".join(validation_errors)
        )

    return map_tiering_posture_file_to_events(
        sidecar,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
    )


__all__ = [
    "build_ad07_delegation_context",
    "build_ad0608_delegation_input",
    "build_ad22_tiering_input",
    "canonical_ad07_context_available",
    "canonical_ad_delegation_input_available",
    "canonical_ad_tiering_input_available",
    "load_bloodhound_session_rows",
    "map_ad0608_sidecar_to_events",
    "map_ad22_sidecar_to_events",
    "route_bloodhound_ad07_context",
    "route_bloodhound_delegation_evidence",
    "route_bloodhound_ad22_evidence",
]
