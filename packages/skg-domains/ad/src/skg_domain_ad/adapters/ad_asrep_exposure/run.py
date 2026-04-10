from __future__ import annotations

from typing import Any, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.adapters.common import (
    has_dont_require_preauth,
    is_account_enabled,
    is_machine_account_principal,
)
from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_asrep_exposure_policy


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


def _extract_name(props: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    keys = (
        "name",
        "samaccountname",
        "sAMAccountName",
        "displayname",
        "cn",
    )
    for key in keys:
        text = _as_text(props.get(key))
        if text:
            return text
    for key in keys:
        text = _as_text(row.get(key))
        if text:
            return text
    return "unknown-user"


def _extract_enabled(props: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    explicit_enabled = props.get("enabled")
    if explicit_enabled is None:
        explicit_enabled = row.get("enabled")

    uac = props.get("userAccountControl", props.get("useraccountcontrol"))
    if uac is None:
        uac = row.get("userAccountControl", row.get("useraccountcontrol"))

    return is_account_enabled(
        explicit_enabled=explicit_enabled,
        user_account_control=uac,
    )


def _extract_dontreqpreauth(props: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    explicit_flag = props.get("dontreqpreauth")
    if explicit_flag is None:
        explicit_flag = row.get("dontreqpreauth")

    uac = props.get("userAccountControl", props.get("useraccountcontrol"))
    if uac is None:
        uac = row.get("userAccountControl", row.get("useraccountcontrol"))

    return has_dont_require_preauth(
        explicit_flag=explicit_flag,
        user_account_control=uac,
    )


def _extract_users(inventory: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    users = inventory.get("users")
    if not isinstance(users, list):
        return []
    return [row for row in users if isinstance(row, Mapping)]


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


def map_asrep_exposure_to_events(
    inventory: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map AD user inventory to AS-REP baseline exposure events (AD-04 core only)."""

    policy = load_asrep_exposure_policy()
    exclude_machine_accounts = bool(policy.get("exclude_machine_accounts", False))
    source_kind = str(policy.get("source_kind") or "ad.inventory.snapshot")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.ad_asrep_exposure")
    pointer_prefix = str(policy.get("pointer_prefix") or "ad://")
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}

    users = _extract_users(inventory if isinstance(inventory, Mapping) else {})

    observed_users: list[dict[str, Any]] = []
    asrep_exposed_users: list[dict[str, Any]] = []

    for row in users:
        props = _extract_properties(row)
        name = _extract_name(props, row)
        enabled = _extract_enabled(props, row)
        dontreqpreauth = _extract_dontreqpreauth(props, row)
        is_machine = is_machine_account_principal(name)

        account = {
            "name": name,
            "enabled": enabled,
            "dontreqpreauth": dontreqpreauth,
            "is_machine": is_machine,
        }
        observed_users.append(account)

        if exclude_machine_accounts and is_machine:
            continue
        if enabled and dontreqpreauth:
            asrep_exposed_users.append(account)

    has_observed_users = bool(observed_users)
    has_asrep_exposure = bool(asrep_exposed_users)

    statuses = {
        "AD-AS-01": "realized" if has_observed_users else "unknown",
        "AD-AS-02": (
            "realized"
            if has_asrep_exposure
            else ("blocked" if has_observed_users else "unknown")
        ),
    }

    details = {
        "AD-AS-01": (
            f"AD user pre-auth state observed for {len(observed_users)} account(s)"
            if has_observed_users
            else "No AD user inventory observed for AS-REP baseline assessment"
        ),
        "AD-AS-02": (
            f"AS-REP roastable accounts observed: {', '.join(account['name'] for account in asrep_exposed_users[:5])}"
            if has_asrep_exposure
            else (
                "Observed AD user inventory contains no enabled account with pre-auth disabled"
                if has_observed_users
                else "Cannot assess AS-REP exposure without user inventory observation"
            )
        ),
    }

    attributes = {
        "AD-AS-01": {
            "observed_user_count": len(observed_users),
            "observed_users": observed_users[:20],
        },
        "AD-AS-02": {
            "asrep_exposed_user_count": len(asrep_exposed_users),
            "asrep_exposed_users": asrep_exposed_users[:20],
            "exclude_machine_accounts": exclude_machine_accounts,
        },
    }

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-AS-01", "AD-AS-02"):
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
                confidence=float(wicket_cfg.get("confidence") or 0.9),
                attributes=attributes[wicket_id],
            )
        )
    return events
