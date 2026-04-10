from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_web.ontology import load_wickets
from skg_domain_web.policies import load_auth_assessment_policy


@dataclass(frozen=True, slots=True)
class AuthAssessment:
    auth_attempted: bool
    authenticated: bool
    username: str = ""
    method: str = "none"
    used_default_credential: bool = False
    status_code: int = 0
    detail: str = ""


def _conf(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _wicket_label(wicket_id: str) -> str:
    wickets = load_wickets()
    row = wickets.get(wicket_id) if isinstance(wickets, dict) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _normalize_assessment(value: AuthAssessment | Mapping[str, Any]) -> AuthAssessment:
    if isinstance(value, AuthAssessment):
        return value
    if not isinstance(value, Mapping):
        return AuthAssessment(auth_attempted=False, authenticated=False)
    return AuthAssessment(
        auth_attempted=bool(value.get("auth_attempted")),
        authenticated=bool(value.get("authenticated")),
        username=str(value.get("username") or ""),
        method=str(value.get("method") or "none"),
        used_default_credential=bool(value.get("used_default_credential")),
        status_code=int(value.get("status_code") or 0),
        detail=str(value.get("detail") or ""),
    )


def map_auth_assessment_to_events(
    assessment: AuthAssessment | Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "adapter.web_auth_assessment",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    """Map runtime auth outcome into canonical domain auth events."""

    policy = load_auth_assessment_policy()
    conf = policy.get("confidence") if isinstance(policy, Mapping) else {}
    wickets = policy.get("wickets") if isinstance(policy, Mapping) else {}
    if not isinstance(conf, Mapping):
        conf = {}
    if not isinstance(wickets, Mapping):
        wickets = {}

    record = _normalize_assessment(assessment)

    wicket_id = str(wickets.get("default_credentials") or "WB-10")
    source_kind = str(policy.get("source_kind") or "auth.runtime")
    evidence_rank = int(policy.get("evidence_rank") or 3)
    pointer_prefix = str(policy.get("pointer_prefix") or "web-auth://")
    pointer = f"{pointer_prefix}{workload_id}"

    if not record.auth_attempted:
        status = "unknown"
        confidence = _conf(float(conf.get("auth_unknown", 0.50)))
        detail = record.detail or "No auth attempt executed"
        realized = None
    elif record.authenticated and record.used_default_credential:
        status = "realized"
        confidence = _conf(float(conf.get("default_credential_realized", 0.90)))
        who = record.username or "(unknown user)"
        detail = record.detail or f"Default credential accepted for {who}"
        realized = True
    else:
        status = "blocked"
        confidence = _conf(float(conf.get("default_credential_blocked", 0.82)))
        if record.authenticated:
            detail = record.detail or "Authentication succeeded with non-default credentials"
        else:
            detail = record.detail or "Default credentials not accepted"
        realized = False

    payload = build_precondition_payload(
        wicket_id=wicket_id,
        label=_wicket_label(wicket_id),
        domain="web",
        workload_id=workload_id,
        realized=realized,
        status=status,
        detail=detail,
        attack_path_id=attack_path_id,
    )

    event = build_event_envelope(
        event_type="obs.attack.precondition",
        source_id=source_id,
        toolchain=toolchain,
        payload=payload,
        evidence_rank=evidence_rank,
        source_kind=source_kind,
        pointer=pointer,
        confidence=confidence,
    )
    return [event]
