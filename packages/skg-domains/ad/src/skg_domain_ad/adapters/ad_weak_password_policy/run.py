from __future__ import annotations

from typing import Any, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.adapters.common import coerce_int_scalar
from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_weak_password_policy_policy


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
    row = wickets.get(wicket_id) if isinstance(wickets, dict) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _extract_properties(row: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("Properties", "properties", "attributes"):
        value = row.get(key)
        if isinstance(value, Mapping):
            return value
    return row


def _as_text(value: Any) -> str:
    if isinstance(value, list):
        if not value:
            return ""
        value = value[0]
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    return coerce_int_scalar(value)


def _extract_policy_rows(inventory: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []

    domains = inventory.get("domains")
    if isinstance(domains, list):
        rows.extend(row for row in domains if isinstance(row, Mapping))
    elif isinstance(domains, Mapping):
        rows.append(domains)

    for key in ("domain_policy", "policy"):
        value = inventory.get(key)
        if isinstance(value, Mapping):
            rows.append(value)
    return rows


def _extract_domain_name(props: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    for key in ("name", "domain", "dnsroot"):
        text = _as_text(props.get(key))
        if text:
            return text
    for key in ("name", "domain", "dnsroot"):
        text = _as_text(row.get(key))
        if text:
            return text
    return "unknown-domain"


def _extract_min_password_length(props: Mapping[str, Any], row: Mapping[str, Any]) -> int | None:
    keys = (
        "minPwdLength",
        "minpwdlength",
        "minimum_password_length",
    )
    for key in keys:
        value = _as_int(props.get(key))
        if value is not None:
            return value
    for key in keys:
        value = _as_int(row.get(key))
        if value is not None:
            return value
    return None


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


def map_weak_password_policy_to_events(
    inventory: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map AD password policy snapshots into canonical weak-policy events."""

    policy_cfg = load_weak_password_policy_policy()
    threshold = int(policy_cfg.get("min_password_length_threshold") or 12)
    source_kind = str(policy_cfg.get("source_kind") or "ad.policy.snapshot")
    canonical_source_id = str(source_id or policy_cfg.get("source_id") or "adapter.ad_weak_password_policy")
    pointer_prefix = str(policy_cfg.get("pointer_prefix") or "ad://")
    wickets_policy = policy_cfg.get("wickets") if isinstance(policy_cfg.get("wickets"), Mapping) else {}

    rows = _extract_policy_rows(inventory if isinstance(inventory, Mapping) else {})
    observed_rows: list[dict[str, Any]] = []
    weak_rows: list[dict[str, Any]] = []
    strong_rows: list[dict[str, Any]] = []

    for row in rows:
        props = _extract_properties(row)
        domain_name = _extract_domain_name(props, row)
        min_len = _extract_min_password_length(props, row)

        observed = {
            "domain": domain_name,
            "min_password_length": min_len,
        }
        observed_rows.append(observed)

        if min_len is None:
            continue
        if min_len < threshold:
            weak_rows.append(observed)
        else:
            strong_rows.append(observed)

    has_observed = bool(observed_rows)
    has_weak_policy = bool(weak_rows)

    statuses = {
        "AD-WP-01": "realized" if has_observed else "unknown",
        "AD-WP-02": (
            "realized"
            if has_weak_policy
            else ("blocked" if has_observed else "unknown")
        ),
    }

    details = {
        "AD-WP-01": (
            f"Password policy snapshots observed for domains: {', '.join(row['domain'] for row in observed_rows[:5])}"
            if has_observed
            else "No password policy snapshot provided"
        ),
        "AD-WP-02": (
            f"Weak minimum password length (<{threshold}) detected for domains: {', '.join(row['domain'] for row in weak_rows[:5])}"
            if has_weak_policy
            else (
                f"Observed password policies meet minimum length threshold (>= {threshold})"
                if has_observed
                else "Cannot assess weak password policy without policy observation"
            )
        ),
    }

    attributes = {
        "AD-WP-01": {
            "policy_observation_count": len(observed_rows),
            "observed_policies": observed_rows[:20],
        },
        "AD-WP-02": {
            "min_password_length_threshold": threshold,
            "weak_policy_count": len(weak_rows),
            "weak_policies": weak_rows[:20],
            "strong_policy_sample": strong_rows[:20],
        },
    }

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-WP-01", "AD-WP-02"):
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
                evidence_rank=int(wicket_cfg.get("evidence_rank") or 3),
                confidence=float(wicket_cfg.get("confidence") or 0.85),
                attributes=attributes[wicket_id],
            )
        )
    return events
