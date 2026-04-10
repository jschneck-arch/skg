from __future__ import annotations

from datetime import datetime, timezone
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


def _first_value(props: Mapping[str, Any], row: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in props:
            return props.get(key)
    for key in keys:
        if key in row:
            return row.get(key)
    return None


def _coerce_epoch_seconds(value: Any) -> float | None:
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        cast = float(value)
        if cast > 0:
            return cast
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            cast = float(text)
        except ValueError:
            return None
        if cast > 0:
            return cast
    return None


def classify_ad07_unconstrained_activity(
    computers: Any,
    *,
    stale_days: int,
    now_ts: float | None = None,
    unknown_last_logon_is_active: bool,
) -> dict[str, Any]:
    """
    Service-owned AD-07 context classifier.

    This helper intentionally stays out of domain semantics and isolates the
    runtime freshness assumption currently used by legacy delegation logic.
    """

    if not isinstance(stale_days, int) or stale_days <= 0:
        raise ValueError("stale_days must be a positive integer")
    if not isinstance(unknown_last_logon_is_active, bool):
        raise ValueError("unknown_last_logon_is_active must be a bool")

    rows = computers if isinstance(computers, list) else []
    current_ts = float(now_ts) if isinstance(now_ts, (int, float)) else datetime.now(
        timezone.utc
    ).timestamp()
    stale_threshold_seconds = max(1, int(stale_days)) * 86400

    unconstrained_non_dc: list[dict[str, Any]] = []
    active_unconstrained: list[dict[str, Any]] = []
    stale_unconstrained: list[dict[str, Any]] = []
    unknown_last_logon: list[dict[str, Any]] = []

    for row in rows:
        if not isinstance(row, Mapping):
            continue

        props = _extract_properties(row)
        name = _as_text(
            _first_value(
                props,
                row,
                ("name", "samaccountname", "sAMAccountName", "dNSHostName", "dnshostname"),
            )
        ) or "unknown-computer"

        enabled_value = _coerce_bool(_first_value(props, row, ("enabled", "Enabled", "isenabled")))
        is_enabled = True if enabled_value is None else enabled_value
        if not is_enabled:
            continue

        is_dc = _coerce_bool(
            _first_value(props, row, ("isdc", "isDomainController", "is_domain_controller"))
        )
        if is_dc is True:
            continue

        unconstrained = _coerce_bool(
            _first_value(props, row, ("unconstraineddelegation", "unconstrained_delegation"))
        )
        if unconstrained is not True:
            continue

        raw_last_logon = _first_value(
            props,
            row,
            ("lastlogontimestamp", "last_logon_timestamp", "lastLogonTimestamp"),
        )
        last_logon_epoch = _coerce_epoch_seconds(raw_last_logon)

        record = {
            "name": name,
            "last_logon_epoch": last_logon_epoch,
            "age_seconds": None,
        }
        unconstrained_non_dc.append(record)

        if last_logon_epoch is None:
            unknown_last_logon.append({**record, "activity_state": "unknown"})
            if unknown_last_logon_is_active:
                active_unconstrained.append({**record, "activity_state": "unknown_assumed_active"})
            continue

        age_seconds = max(0.0, current_ts - last_logon_epoch)
        record["age_seconds"] = age_seconds
        if age_seconds < stale_threshold_seconds:
            active_unconstrained.append({**record, "activity_state": "recent"})
        else:
            stale_unconstrained.append({**record, "activity_state": "stale"})

    return {
        "stale_days": int(stale_days),
        "stale_threshold_seconds": stale_threshold_seconds,
        "total_unconstrained_non_dc": len(unconstrained_non_dc),
        "active_unconstrained": active_unconstrained,
        "stale_unconstrained": stale_unconstrained,
        "unknown_last_logon": unknown_last_logon,
        "unknown_last_logon_is_active": bool(unknown_last_logon_is_active),
    }


__all__ = ["classify_ad07_unconstrained_activity"]
