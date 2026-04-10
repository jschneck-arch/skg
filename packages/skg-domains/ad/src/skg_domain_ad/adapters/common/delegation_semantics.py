from __future__ import annotations

from typing import Any, Mapping

from skg_domain_ad.adapters.common.account_semantics import is_account_enabled


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


def _coerce_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        text = _as_text(item)
        if text:
            normalized.append(text)
    return normalized


def _parse_spn(spn: str) -> tuple[str, str]:
    text = str(spn or "").strip()
    if not text:
        return "", ""
    if "/" not in text:
        return text.lower(), ""
    service, target = text.split("/", 1)
    return service.strip().lower(), target.strip().lower()


def normalize_delegation_principals(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        return []

    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        props = _extract_properties(row)
        name = _first_text(
            props,
            row,
            ("name", "samaccountname", "sAMAccountName", "dNSHostName", "dnshostname"),
        )
        object_id = _first_text(
            props,
            row,
            ("ObjectIdentifier", "objectidentifier", "objectsid", "objectid", "id"),
        )
        enabled = is_account_enabled(
            explicit_enabled=_first_value(props, row, ("enabled", "isenabled")),
            user_account_control=_first_value(
                props,
                row,
                ("useraccountcontrol", "userAccountControl"),
            ),
        )
        is_domain_controller = _coerce_bool(
            _first_value(props, row, ("isdc", "isDomainController", "is_domain_controller"))
        )
        unconstrained_delegation = _coerce_bool(
            _first_value(
                props,
                row,
                ("unconstraineddelegation", "unconstrained_delegation"),
            )
        )
        trusted_to_auth_for_delegation = _coerce_bool(
            _first_value(
                props,
                row,
                ("trustedtoauthfordelegation", "trusted_to_auth_for_delegation"),
            )
        )
        allowed_to_delegate = _coerce_string_list(
            _first_value(props, row, ("allowedtodelegate", "allowed_to_delegate"))
        )

        if not name and not object_id:
            continue

        normalized.append(
            {
                "name": name,
                "object_id": object_id,
                "enabled": enabled,
                "is_domain_controller": is_domain_controller,
                "unconstrained_delegation": unconstrained_delegation,
                "trusted_to_auth_for_delegation": trusted_to_auth_for_delegation,
                "allowed_to_delegate": allowed_to_delegate,
            }
        )
    return normalized


def extract_unconstrained_non_dc_hosts(rows: Any) -> list[dict[str, str]]:
    principals = normalize_delegation_principals(rows)
    hosts: list[dict[str, str]] = []
    for principal in principals:
        if principal.get("enabled") is not True:
            continue
        if principal.get("unconstrained_delegation") is not True:
            continue
        if principal.get("is_domain_controller") is True:
            continue
        hosts.append(
            {
                "name": str(principal.get("name") or ""),
                "object_id": str(principal.get("object_id") or ""),
            }
        )
    return hosts


def extract_protocol_transition_principals(rows: Any) -> list[dict[str, Any]]:
    principals = normalize_delegation_principals(rows)
    resolved: list[dict[str, Any]] = []
    for principal in principals:
        if principal.get("enabled") is not True:
            continue
        allowed = principal.get("allowed_to_delegate")
        if not isinstance(allowed, list) or not allowed:
            continue
        if principal.get("trusted_to_auth_for_delegation") is not True:
            continue
        resolved.append(
            {
                "name": str(principal.get("name") or ""),
                "object_id": str(principal.get("object_id") or ""),
                "allowed_to_delegate": [str(spn) for spn in allowed],
            }
        )
    return resolved


def extract_delegation_spn_edges(rows: Any) -> list[dict[str, str]]:
    principals = normalize_delegation_principals(rows)
    edges: list[dict[str, str]] = []
    for principal in principals:
        account = str(principal.get("name") or "")
        object_id = str(principal.get("object_id") or "")
        allowed = principal.get("allowed_to_delegate")
        if not isinstance(allowed, list):
            continue
        for spn in allowed:
            spn_text = str(spn).strip()
            if not spn_text:
                continue
            service, target = _parse_spn(spn_text)
            edges.append(
                {
                    "account": account,
                    "object_id": object_id,
                    "spn": spn_text,
                    "service": service,
                    "target": target,
                }
            )
    return edges


__all__ = [
    "extract_delegation_spn_edges",
    "extract_protocol_transition_principals",
    "extract_unconstrained_non_dc_hosts",
    "normalize_delegation_principals",
]
