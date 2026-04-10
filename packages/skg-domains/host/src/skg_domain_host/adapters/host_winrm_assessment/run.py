from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_host.ontology import load_wickets
from skg_domain_host.policies import load_winrm_adapter_policy


@dataclass(frozen=True, slots=True)
class WinrmAssessment:
    host: str
    port: int = 5985
    username: str = ""
    winrm_exposed: bool | None = None
    credential_valid: bool | None = None
    is_admin: bool | None = None
    credential_in_env: bool | None = None
    env_text: str = ""
    whoami_groups: str = ""


def _conf(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _status(value: bool | None) -> str:
    if value is True:
        return "realized"
    if value is False:
        return "blocked"
    return "unknown"


def _wicket_label(wicket_id: str) -> str:
    wickets = load_wickets()
    row = wickets.get(wicket_id) if isinstance(wickets, dict) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "realized"}:
        return True
    if text in {"0", "false", "no", "n", "blocked"}:
        return False
    return None


def _normalize_assessments(rows: Iterable[WinrmAssessment | Mapping[str, Any]]) -> list[WinrmAssessment]:
    assessments: list[WinrmAssessment] = []

    for row in rows:
        if isinstance(row, WinrmAssessment):
            assessments.append(row)
            continue

        if not isinstance(row, Mapping):
            continue

        host = str(row.get("host") or row.get("target_ip") or "").strip()
        if not host:
            continue

        assessments.append(
            WinrmAssessment(
                host=host,
                port=int(row.get("port") or 5985),
                username=str(row.get("username") or row.get("user") or ""),
                winrm_exposed=_as_bool(row.get("winrm_exposed")),
                credential_valid=_as_bool(row.get("credential_valid")),
                is_admin=_as_bool(row.get("is_admin")),
                credential_in_env=_as_bool(row.get("credential_in_env")),
                env_text=str(row.get("env_text") or ""),
                whoami_groups=str(row.get("whoami_groups") or ""),
            )
        )

    return assessments


def _credential_indicator_from_text(env_text: str, patterns: list[str]) -> bool | None:
    text = str(env_text or "").strip()
    if not text:
        return None
    for pattern in patterns:
        try:
            if re.search(pattern, text):
                return True
        except re.error:
            continue
    return False


def _emit(
    *,
    wicket_id: str,
    status: str,
    detail: str,
    host: str,
    port: int,
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
        domain="host",
        workload_id=workload_id,
        realized=True if status == "realized" else (False if status == "blocked" else None),
        status=status,
        detail=detail,
        attack_path_id=attack_path_id,
        target_ip=host,
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
        pointer=f"{pointer_prefix}{host}:{port}/{wicket_id.lower()}",
        confidence=_conf(confidence),
    )


def map_winrm_assessments_to_events(
    assessments: Iterable[WinrmAssessment | Mapping[str, Any]],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "host",
) -> list[dict[str, Any]]:
    """Map WinRM runtime assessment rows into canonical host precondition events."""

    rows = _normalize_assessments(assessments)
    policy = load_winrm_adapter_policy()

    source_kind = str(policy.get("source_kind") or "winrm_runtime")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.host_winrm_assessment")
    pointer_prefix = str(policy.get("pointer_prefix") or "winrm://")
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}
    cred_patterns = [
        str(pattern)
        for pattern in (policy.get("credential_patterns") or [])
        if str(pattern).strip()
    ]

    events: list[dict[str, Any]] = []

    for row in rows:
        this_workload_id = workload_id or f"winrm::{row.host}"

        credential_env_state = (
            row.credential_in_env
            if row.credential_in_env is not None
            else _credential_indicator_from_text(row.env_text, cred_patterns)
        )

        wicket_states = {
            "HO-04": _status(row.winrm_exposed),
            "HO-05": _status(row.credential_valid),
            "HO-10": _status(row.is_admin),
            "HO-09": _status(credential_env_state),
        }

        wicket_details = {
            "HO-04": f"WinRM service exposure assessment for {row.host}:{row.port}",
            "HO-05": f"WinRM credential assessment for user '{row.username or 'unknown'}'",
            "HO-10": "Administrative group check from WinRM whoami/groups output",
            "HO-09": "Credential indicator check from WinRM environment snapshot",
        }

        wicket_attributes: dict[str, dict[str, Any]] = {
            "HO-05": {
                "username": row.username,
            },
            "HO-10": {
                "whoami_groups": row.whoami_groups[:240],
            },
            "HO-09": {
                "env_snippet": row.env_text[:240],
            },
        }

        for wicket_id in ("HO-04", "HO-05", "HO-10", "HO-09"):
            wicket_cfg = wickets_policy.get(wicket_id) if isinstance(wickets_policy, Mapping) else {}
            if not isinstance(wicket_cfg, Mapping):
                wicket_cfg = {}

            events.append(
                _emit(
                    wicket_id=wicket_id,
                    status=wicket_states[wicket_id],
                    detail=wicket_details[wicket_id],
                    host=row.host,
                    port=row.port,
                    run_id=run_id,
                    workload_id=this_workload_id,
                    attack_path_id=attack_path_id,
                    source_id=canonical_source_id,
                    toolchain=toolchain,
                    source_kind=source_kind,
                    pointer_prefix=pointer_prefix,
                    evidence_rank=int(wicket_cfg.get("evidence_rank") or 1),
                    confidence=float(wicket_cfg.get("confidence") or 0.7),
                    attributes=wicket_attributes.get(wicket_id),
                )
            )

    return events
