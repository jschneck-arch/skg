from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.adapters.common import is_machine_account_principal
from skg_domain_ad.mappings import load_privileged_group_aliases
from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_privileged_membership_policy


@dataclass(frozen=True, slots=True)
class DirectoryInventory:
    users: tuple[Mapping[str, Any], ...]
    groups: tuple[Mapping[str, Any], ...]


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
    for key in ("Properties", "properties"):
        value = row.get(key)
        if isinstance(value, Mapping):
            return value
    return row


def _extract_id(row: Mapping[str, Any]) -> str:
    for key in ("ObjectIdentifier", "objectidentifier", "objectid", "ObjectId", "id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    props = _extract_properties(row)
    for key in ("ObjectIdentifier", "objectidentifier", "objectid", "id"):
        value = props.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _normalize_name(value: str) -> str:
    text = str(value or "").strip().lower()
    if "@" in text:
        text = text.split("@", 1)[0]
    return " ".join(token for token in text.replace("_", " ").split() if token)


def _coerce_rows(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        data_rows = value.get("data")
        if isinstance(data_rows, list):
            return [row for row in data_rows if isinstance(row, Mapping)]
        return [value]
    if isinstance(value, list):
        return [row for row in value if isinstance(row, Mapping)]
    return []


def _normalize_inventory(value: DirectoryInventory | Mapping[str, Any]) -> DirectoryInventory:
    if isinstance(value, DirectoryInventory):
        return value

    if not isinstance(value, Mapping):
        return DirectoryInventory(users=(), groups=())

    users = tuple(_coerce_rows(value.get("users") or []))
    groups = tuple(_coerce_rows(value.get("groups") or []))
    return DirectoryInventory(users=users, groups=groups)


def _build_user_index(users: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in users:
        props = _extract_properties(row)
        object_id = _extract_id(row).lower()
        name = str(
            props.get("name")
            or props.get("samaccountname")
            or props.get("sAMAccountName")
            or object_id
            or ""
        )
        enabled = bool(props.get("enabled", True))

        entry = {
            "id": object_id,
            "name": name,
            "enabled": enabled,
        }

        if object_id:
            index[object_id] = entry
        normalized_name = _normalize_name(name)
        if normalized_name:
            index[f"name::{normalized_name}"] = entry
    return index


def _is_privileged_group(name: str, aliases: list[str]) -> bool:
    normalized = _normalize_name(name)
    if not normalized:
        return False
    return any(alias in normalized for alias in aliases)


def _extract_members(group_row: Mapping[str, Any]) -> list[Mapping[str, Any] | str]:
    for key in ("Members", "members"):
        value = group_row.get(key)
        if isinstance(value, list):
            return list(value)

    props = _extract_properties(group_row)
    value = props.get("members")
    if isinstance(value, list):
        return list(value)

    return []


def _member_id_and_name(member: Mapping[str, Any] | str) -> tuple[str, str]:
    if isinstance(member, str):
        text = member.strip()
        return text, text

    if not isinstance(member, Mapping):
        return "", ""

    member_id = ""
    for key in ("ObjectIdentifier", "objectidentifier", "objectid", "MemberId", "member_id", "id"):
        value = member.get(key)
        if isinstance(value, str) and value.strip():
            member_id = value.strip()
            break

    member_name = ""
    for key in ("name", "Name", "samaccountname", "sAMAccountName"):
        value = member.get(key)
        if isinstance(value, str) and value.strip():
            member_name = value.strip()
            break

    return member_id, member_name


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


def map_privileged_memberships_to_events(
    inventory: DirectoryInventory | Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map AD privileged-group membership inventory into canonical AD events."""

    normalized = _normalize_inventory(inventory)
    policy = load_privileged_membership_policy()
    aliases = load_privileged_group_aliases()

    source_kind = str(policy.get("source_kind") or "ad.inventory.snapshot")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.ad_privileged_membership")
    pointer_prefix = str(policy.get("pointer_prefix") or "ad://")
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}

    user_index = _build_user_index(normalized.users)

    privileged_groups: list[dict[str, Any]] = []
    privileged_memberships: list[dict[str, Any]] = []
    human_enabled_members: list[dict[str, Any]] = []

    for group in normalized.groups:
        props = _extract_properties(group)
        group_name = str(
            props.get("name")
            or props.get("cn")
            or props.get("samaccountname")
            or ""
        )
        if not _is_privileged_group(group_name, aliases):
            continue

        group_id = _extract_id(group)
        members = _extract_members(group)
        privileged_groups.append(
            {
                "group_name": group_name,
                "group_id": group_id,
                "member_count": len(members),
            }
        )

        for member in members:
            member_id, member_name = _member_id_and_name(member)
            member_key = member_id.lower()
            resolved = user_index.get(member_key)
            if resolved is None and member_name:
                resolved = user_index.get(f"name::{_normalize_name(member_name)}")

            resolved_name = (
                str(resolved.get("name")) if isinstance(resolved, Mapping) and resolved.get("name") else member_name or member_id
            )
            enabled = bool(resolved.get("enabled", True)) if isinstance(resolved, Mapping) else True
            is_machine = is_machine_account_principal(resolved_name)

            edge = {
                "group_name": group_name,
                "group_id": group_id,
                "member_id": member_id,
                "member_name": resolved_name,
                "enabled": enabled,
                "is_machine": is_machine,
            }
            privileged_memberships.append(edge)

            if enabled and not is_machine:
                human_enabled_members.append(edge)

    has_privileged_groups = bool(privileged_groups)
    has_memberships = bool(privileged_memberships)
    has_human_enabled_members = bool(human_enabled_members)

    status_groups = "realized" if has_privileged_groups else "blocked"
    if has_privileged_groups:
        status_memberships = "realized" if has_memberships else "blocked"
        status_human = "realized" if has_human_enabled_members else ("blocked" if has_memberships else "unknown")
    else:
        status_memberships = "unknown"
        status_human = "unknown"

    details = {
        "AD-PR-01": (
            f"Privileged groups detected: {', '.join(group['group_name'] for group in privileged_groups[:5])}"
            if has_privileged_groups
            else "No privileged group aliases detected in snapshot"
        ),
        "AD-PR-02": (
            f"Privileged membership edges observed: {len(privileged_memberships)}"
            if has_memberships
            else "No membership edges observed for privileged groups"
        ),
        "AD-PR-03": (
            f"Enabled non-machine privileged members: {', '.join(edge['member_name'] for edge in human_enabled_members[:5])}"
            if has_human_enabled_members
            else "No enabled non-machine user principal mapped to privileged groups"
        ),
    }

    attributes = {
        "AD-PR-01": {
            "privileged_group_count": len(privileged_groups),
            "privileged_groups": privileged_groups[:10],
        },
        "AD-PR-02": {
            "membership_edge_count": len(privileged_memberships),
            "membership_edges": privileged_memberships[:20],
        },
        "AD-PR-03": {
            "enabled_human_member_count": len(human_enabled_members),
            "enabled_human_members": human_enabled_members[:20],
        },
    }

    statuses = {
        "AD-PR-01": status_groups,
        "AD-PR-02": status_memberships,
        "AD-PR-03": status_human,
    }

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-PR-01", "AD-PR-02", "AD-PR-03"):
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
                confidence=float(wicket_cfg.get("confidence") or 0.7),
                attributes=attributes[wicket_id],
            )
        )

    return events
