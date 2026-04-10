from __future__ import annotations

from collections.abc import Mapping
from typing import Any


LAPS_PASSWORD_ATTRIBUTE_KEYS = (
    "ms-Mcs-AdmPwd",
    "ms-mcs-admpwd",
    "msLAPS-Password",
)


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


def is_non_dc_computer_candidate(
    *,
    enabled: Any = True,
    is_domain_controller: Any = False,
) -> bool:
    enabled_value = _coerce_bool(enabled)
    dc_value = _coerce_bool(is_domain_controller)

    effective_enabled = True if enabled_value is None else enabled_value
    effective_is_dc = False if dc_value is None else dc_value
    return effective_enabled and not effective_is_dc


def laps_password_attribute_present(value: Any) -> bool:
    # Legacy adapters treated any non-None LAPS attribute value as present.
    return value is not None


def resolve_laps_presence(
    *,
    explicit_has_laps: Any = None,
    attributes: Mapping[str, Any] | None = None,
    attribute_keys: tuple[str, ...] | None = None,
) -> bool | None:
    explicit_value = _coerce_bool(explicit_has_laps)
    if explicit_value is not None:
        return explicit_value

    if not isinstance(attributes, Mapping):
        return None

    keys = attribute_keys or LAPS_PASSWORD_ATTRIBUTE_KEYS
    for key in keys:
        if key in attributes:
            return laps_password_attribute_present(attributes.get(key))
    return None
