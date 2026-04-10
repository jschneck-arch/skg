from __future__ import annotations

from typing import Any, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.adapters.common import (
    encryption_allows_rc4,
    is_account_enabled,
    is_machine_account_principal,
)
from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_kerberoast_exposure_policy


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


def _extract_users(inventory: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    users = inventory.get("users")
    if not isinstance(users, list):
        return []
    return [row for row in users if isinstance(row, Mapping)]


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


def _extract_has_spn(props: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    has_spn = props.get("hasspn")
    if has_spn is None:
        has_spn = row.get("hasspn")
    if isinstance(has_spn, bool):
        return has_spn
    if isinstance(has_spn, str):
        normalized = has_spn.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False

    for key in (
        "servicePrincipalName",
        "serviceprincipalname",
        "spns",
    ):
        value = props.get(key)
        if value is None:
            value = row.get(key)
        if isinstance(value, list):
            if any(_as_text(item) for item in value):
                return True
        elif _as_text(value):
            return True
    return False


def _extract_encryption_types(props: Mapping[str, Any], row: Mapping[str, Any]) -> Any:
    keys = (
        "supportedencryptiontypes",
        "msDS-SupportedEncryptionTypes",
        "msds-supportedencryptiontypes",
    )
    for key in keys:
        value = props.get(key)
        if value is not None:
            return value
    for key in keys:
        value = row.get(key)
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


def map_kerberoast_exposure_to_events(
    inventory: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map AD user inventory to Kerberoast baseline exposure events (AD-01/AD-02 core)."""

    policy = load_kerberoast_exposure_policy()
    exclude_machine_accounts = bool(policy.get("exclude_machine_accounts", True))
    source_kind = str(policy.get("source_kind") or "ad.inventory.snapshot")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.ad_kerberoast_exposure")
    pointer_prefix = str(policy.get("pointer_prefix") or "ad://")
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}

    users = _extract_users(inventory if isinstance(inventory, Mapping) else {})

    kerberoastable_accounts: list[dict[str, Any]] = []
    rc4_accounts: list[dict[str, Any]] = []

    for row in users:
        props = _extract_properties(row)
        name = _extract_name(props, row)
        enabled = _extract_enabled(props, row)
        is_machine = is_machine_account_principal(name)
        has_spn = _extract_has_spn(props, row)
        enc_types = _extract_encryption_types(props, row)

        if not enabled or not has_spn:
            continue
        if exclude_machine_accounts and is_machine:
            continue

        account = {
            "name": name,
            "is_machine": is_machine,
            "supported_encryption_types": enc_types,
        }
        kerberoastable_accounts.append(account)

        if encryption_allows_rc4(enc_types):
            rc4_accounts.append(account)

    has_observed_users = bool(users)
    has_kerberoastable = bool(kerberoastable_accounts)
    has_rc4_accounts = bool(rc4_accounts)

    statuses = {
        "AD-KR-01": (
            "realized"
            if has_kerberoastable
            else ("blocked" if has_observed_users else "unknown")
        ),
        "AD-KR-02": (
            "realized"
            if has_rc4_accounts
            else ("blocked" if has_kerberoastable else "unknown")
        ),
    }

    details = {
        "AD-KR-01": (
            f"Kerberoastable SPN-linked accounts observed: {', '.join(account['name'] for account in kerberoastable_accounts[:5])}"
            if has_kerberoastable
            else (
                "Observed AD user inventory contains no enabled SPN-linked account"
                if has_observed_users
                else "No AD user inventory observed for Kerberoast baseline assessment"
            )
        ),
        "AD-KR-02": (
            f"Kerberoastable accounts permitting RC4 observed: {', '.join(account['name'] for account in rc4_accounts[:5])}"
            if has_rc4_accounts
            else (
                "Kerberoastable accounts observed but none indicate RC4-permitted encryption"
                if has_kerberoastable
                else "Cannot assess RC4 Kerberoast exposure without Kerberoastable account observation"
            )
        ),
    }

    attributes = {
        "AD-KR-01": {
            "kerberoastable_account_count": len(kerberoastable_accounts),
            "kerberoastable_accounts": kerberoastable_accounts[:20],
            "exclude_machine_accounts": exclude_machine_accounts,
        },
        "AD-KR-02": {
            "rc4_allowed_account_count": len(rc4_accounts),
            "rc4_allowed_accounts": rc4_accounts[:20],
        },
    }

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-KR-01", "AD-KR-02"):
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
