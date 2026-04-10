from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_host.ontology import load_wickets
from skg_domain_host.policies import load_ssh_adapter_policy


@dataclass(frozen=True, slots=True)
class SshAssessment:
    host: str
    port: int = 22
    username: str = ""
    auth_type: str = ""
    reachable: bool | None = None
    ssh_exposed: bool | None = None
    credential_valid: bool | None = None
    is_admin: bool | None = None
    sudo_nopasswd: bool | None = None
    kernel_release: str = ""
    id_output: str = ""
    sudo_output: str = ""


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


def _normalize_assessments(rows: Iterable[SshAssessment | Mapping[str, Any]]) -> list[SshAssessment]:
    assessments: list[SshAssessment] = []

    for row in rows:
        if isinstance(row, SshAssessment):
            assessments.append(row)
            continue

        if not isinstance(row, Mapping):
            continue

        host = str(row.get("host") or row.get("target_ip") or "").strip()
        if not host:
            continue

        assessments.append(
            SshAssessment(
                host=host,
                port=int(row.get("port") or 22),
                username=str(row.get("username") or row.get("user") or ""),
                auth_type=str(row.get("auth_type") or ""),
                reachable=_as_bool(row.get("reachable")),
                ssh_exposed=_as_bool(row.get("ssh_exposed")),
                credential_valid=_as_bool(row.get("credential_valid")),
                is_admin=_as_bool(row.get("is_admin")),
                sudo_nopasswd=_as_bool(row.get("sudo_nopasswd")),
                kernel_release=str(row.get("kernel_release") or "").strip(),
                id_output=str(row.get("id_output") or ""),
                sudo_output=str(row.get("sudo_output") or ""),
            )
        )

    return assessments


def _kernel_is_vulnerable(kernel_release: str, patterns: list[str]) -> bool | None:
    value = str(kernel_release or "").strip()
    if not value:
        return None
    for pattern in patterns:
        try:
            if re.match(pattern, value):
                return True
        except re.error:
            continue
    return None


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


def map_ssh_assessments_to_events(
    assessments: Iterable[SshAssessment | Mapping[str, Any]],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "host",
) -> list[dict[str, Any]]:
    """Map SSH runtime assessment rows into canonical host precondition events."""

    rows = _normalize_assessments(assessments)
    policy = load_ssh_adapter_policy()

    source_kind = str(policy.get("source_kind") or "ssh_runtime")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.host_ssh_assessment")
    pointer_prefix = str(policy.get("pointer_prefix") or "ssh://")
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}
    vulnerable_patterns = [
        str(pattern)
        for pattern in (policy.get("kernel_vulnerable_patterns") or [])
        if str(pattern).strip()
    ]

    events: list[dict[str, Any]] = []

    for row in rows:
        this_workload_id = workload_id or f"ssh::{row.host}"

        wicket_states = {
            "HO-01": _status(row.reachable),
            "HO-02": _status(row.ssh_exposed if row.ssh_exposed is not None else row.reachable),
            "HO-03": _status(row.credential_valid),
            "HO-10": _status(row.is_admin),
            "HO-06": _status(row.sudo_nopasswd),
            "HO-12": _status(_kernel_is_vulnerable(row.kernel_release, vulnerable_patterns)),
        }

        wicket_details = {
            "HO-01": f"SSH reachability probe for {row.host}:{row.port}",
            "HO-02": f"SSH service exposure assessment for {row.host}:{row.port}",
            "HO-03": f"SSH credential assessment for user '{row.username or 'unknown'}' via {row.auth_type or 'unknown'}",
            "HO-10": "Administrative privilege check from 'id' output",
            "HO-06": "sudo policy check from 'sudo -l -n' output",
            "HO-12": f"Kernel release assessed as '{row.kernel_release or 'unknown'}'",
        }

        wicket_attributes: dict[str, dict[str, Any]] = {
            "HO-03": {
                "username": row.username,
                "auth_type": row.auth_type,
            },
            "HO-10": {
                "id_output": row.id_output[:200],
            },
            "HO-06": {
                "sudo_output": row.sudo_output[:200],
            },
            "HO-12": {
                "kernel_release": row.kernel_release,
            },
        }

        for wicket_id in ("HO-01", "HO-02", "HO-03", "HO-10", "HO-06", "HO-12"):
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
