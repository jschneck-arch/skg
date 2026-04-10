from __future__ import annotations

from typing import Any, Mapping


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


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]

    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return None


def _first_text(props: Mapping[str, Any], row: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        text = _as_text(props.get(key))
        if text:
            return text
    for key in keys:
        text = _as_text(row.get(key))
        if text:
            return text
    return ""


def _first_value(props: Mapping[str, Any], row: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in props:
            return props.get(key)
    for key in keys:
        if key in row:
            return row.get(key)
    return None


def _normalize_computer_key(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "@" in text:
        text = text.split("@", 1)[0]
    if text.endswith("$"):
        text = text[:-1]
    return text


def normalize_privileged_session_rows(rows: Any) -> list[dict[str, str]]:
    if not isinstance(rows, list):
        return []

    normalized: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue

        props = _extract_properties(row)

        computer = _first_text(
            props,
            row,
            ("computer", "computer_name", "host", "target", "dNSHostName", "dnshostname"),
        )
        user = _first_text(
            props,
            row,
            ("user", "username", "samaccountname", "sAMAccountName"),
        )
        computer_id = _first_text(
            props,
            row,
            ("computer_id", "computerid", "computer_objectid", "ObjectIdentifier", "objectidentifier", "objectid"),
        )
        user_id = _first_text(
            props,
            row,
            ("user_id", "userid", "user_objectid", "ObjectIdentifier", "objectidentifier", "objectid"),
        )

        if not computer and not computer_id:
            continue

        normalized.append(
            {
                "computer": computer,
                "user": user,
                "computer_id": computer_id,
                "user_id": user_id,
            }
        )

    return normalized


def build_computer_tier_index(computers: Any) -> dict[str, str]:
    if not isinstance(computers, list):
        return {}

    index: dict[str, str] = {}
    for row in computers:
        if not isinstance(row, Mapping):
            continue

        props = _extract_properties(row)
        is_dc_value = _first_value(
            props,
            row,
            ("isdc", "isDomainController", "is_domain_controller"),
        )
        is_dc = _coerce_bool(is_dc_value)
        if is_dc is True:
            tier = "tier0"
        elif is_dc is False:
            tier = "non_tier0"
        else:
            tier = "unknown"

        computer_name = _first_text(
            props,
            row,
            ("name", "dNSHostName", "dnshostname", "samaccountname", "sAMAccountName"),
        )
        computer_id = _first_text(
            props,
            row,
            ("ObjectIdentifier", "objectidentifier", "objectid", "id"),
        )

        for key in (_normalize_computer_key(computer_name), _normalize_computer_key(computer_id)):
            if key:
                index[key] = tier

    return index


def summarize_privileged_tiering_exposure(
    session_rows: Any,
    computers: Any,
) -> dict[str, Any]:
    sessions = normalize_privileged_session_rows(session_rows)
    computer_tiers = build_computer_tier_index(computers)

    non_tier0_sessions: list[dict[str, str]] = []
    tier0_sessions: list[dict[str, str]] = []
    unknown_tier_sessions: list[dict[str, str]] = []

    for session in sessions:
        keys = (
            _normalize_computer_key(session.get("computer", "")),
            _normalize_computer_key(session.get("computer_id", "")),
        )
        tier = ""
        for key in keys:
            if key and key in computer_tiers:
                tier = computer_tiers[key]
                break
        tier = tier or "unknown"

        if tier == "non_tier0":
            non_tier0_sessions.append(session)
        elif tier == "tier0":
            tier0_sessions.append(session)
        else:
            unknown_tier_sessions.append(session)

    has_observed_sessions = bool(sessions)
    has_non_tier0 = bool(non_tier0_sessions)
    all_tiers_known = has_observed_sessions and not unknown_tier_sessions

    if has_non_tier0:
        status = "realized"
    elif all_tiers_known:
        status = "blocked"
    else:
        status = "unknown"

    return {
        "status": status,
        "observed_session_count": len(sessions),
        "non_tier0_session_count": len(non_tier0_sessions),
        "tier0_session_count": len(tier0_sessions),
        "unknown_tier_session_count": len(unknown_tier_sessions),
        "non_tier0_sessions": non_tier0_sessions[:20],
        "tier0_sessions": tier0_sessions[:20],
        "unknown_tier_sessions": unknown_tier_sessions[:20],
    }
