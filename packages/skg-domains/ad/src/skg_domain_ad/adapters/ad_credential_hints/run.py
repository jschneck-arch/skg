from __future__ import annotations

from typing import Any, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.adapters.common import (
    description_has_password_hint,
    is_account_enabled,
    is_machine_account_principal,
)
from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_credential_hint_policy


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


def _extract_name(props: Mapping[str, Any], row: Mapping[str, Any], account_kind: str) -> str:
    keys = (
        "name",
        "samaccountname",
        "sAMAccountName",
        "displayname",
        "dNSHostName",
        "dnshostname",
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
    if account_kind == "computer":
        return "unknown-computer"
    return "unknown-user"


def _extract_description(props: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    for key in ("description", "Description"):
        text = _as_text(props.get(key))
        if text:
            return text
    for key in ("description", "Description"):
        text = _as_text(row.get(key))
        if text:
            return text
    return ""


def _extract_enabled(props: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    for key in ("enabled", "Enabled"):
        value = props.get(key)
        if value is None:
            value = row.get(key)
        if value is not None:
            return is_account_enabled(explicit_enabled=value)

    uac = props.get("userAccountControl", props.get("useraccountcontrol"))
    if uac is None:
        uac = row.get("userAccountControl", row.get("useraccountcontrol"))
    return is_account_enabled(user_account_control=uac)


def _normalize_inventory(inventory: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    users_raw = inventory.get("users") if isinstance(inventory, Mapping) else []
    computers_raw = inventory.get("computers") if isinstance(inventory, Mapping) else []

    users = [row for row in users_raw if isinstance(row, Mapping)] if isinstance(users_raw, list) else []
    computers = [row for row in computers_raw if isinstance(row, Mapping)] if isinstance(computers_raw, list) else []
    return users, computers


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


def map_credential_hints_to_events(
    inventory: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map AD account description credential hints into canonical AD events."""

    users, computers = _normalize_inventory(inventory)
    policy = load_credential_hint_policy()

    source_kind = str(policy.get("source_kind") or "ad.inventory.snapshot")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.ad_credential_hints")
    pointer_prefix = str(policy.get("pointer_prefix") or "ad://")
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}

    findings: list[dict[str, Any]] = []
    enabled_non_machine_findings: list[dict[str, Any]] = []

    for account_kind, rows in (("user", users), ("computer", computers)):
        for row in rows:
            props = _extract_properties(row)
            name = _extract_name(props, row, account_kind)
            description = _extract_description(props, row)
            enabled = _extract_enabled(props, row)
            is_machine = is_machine_account_principal(name)

            if not description_has_password_hint(description):
                continue

            finding = {
                "account_kind": account_kind,
                "name": name,
                "enabled": enabled,
                "is_machine": is_machine,
                "description_excerpt": description[:120],
            }
            findings.append(finding)

            if enabled and not is_machine:
                enabled_non_machine_findings.append(finding)

    has_hints = bool(findings)
    has_enabled_non_machine_hints = bool(enabled_non_machine_findings)

    statuses = {
        "AD-CH-01": "realized" if has_hints else "blocked",
        "AD-CH-02": (
            "realized"
            if has_enabled_non_machine_hints
            else ("blocked" if has_hints else "unknown")
        ),
    }

    details = {
        "AD-CH-01": (
            f"Credential hints detected in account descriptions: {', '.join(f['name'] for f in findings[:5])}"
            if has_hints
            else "No credential-hint keywords detected in account descriptions"
        ),
        "AD-CH-02": (
            f"Enabled non-machine accounts with credential hints: {', '.join(f['name'] for f in enabled_non_machine_findings[:5])}"
            if has_enabled_non_machine_hints
            else "No enabled non-machine account contains credential-hint description text"
        ),
    }

    attributes = {
        "AD-CH-01": {
            "credential_hint_count": len(findings),
            "credential_hints": findings[:20],
        },
        "AD-CH-02": {
            "enabled_non_machine_hint_count": len(enabled_non_machine_findings),
            "enabled_non_machine_hints": enabled_non_machine_findings[:20],
        },
    }

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-CH-01", "AD-CH-02"):
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
                confidence=float(wicket_cfg.get("confidence") or 0.8),
                attributes=attributes[wicket_id],
            )
        )

    return events
