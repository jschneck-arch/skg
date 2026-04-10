from __future__ import annotations

from typing import Any


ACCOUNT_DISABLE_BIT = 0x2
DONT_REQUIRE_PREAUTH_BIT = 0x400000
RC4_BIT = 0x04
AES256_BIT = 0x10


def coerce_int_scalar(value: Any) -> int | None:
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_account_enabled(
    *,
    explicit_enabled: Any = None,
    user_account_control: Any = None,
    default: bool = True,
) -> bool:
    if isinstance(explicit_enabled, bool):
        return explicit_enabled
    if isinstance(explicit_enabled, str):
        normalized = explicit_enabled.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False

    uac_value = coerce_int_scalar(user_account_control)
    if uac_value is None:
        return default
    return not bool(uac_value & ACCOUNT_DISABLE_BIT)


def has_dont_require_preauth(
    *,
    explicit_flag: Any = None,
    user_account_control: Any = None,
) -> bool:
    if isinstance(explicit_flag, bool):
        return explicit_flag
    if isinstance(explicit_flag, str):
        normalized = explicit_flag.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False

    uac_value = coerce_int_scalar(user_account_control)
    if uac_value is None:
        return False
    return bool(uac_value & DONT_REQUIRE_PREAUTH_BIT)


def encryption_is_aes_only(supported_encryption_types: Any) -> bool:
    value = coerce_int_scalar(supported_encryption_types)
    if value is None:
        return False
    return bool(value & AES256_BIT) and not bool(value & RC4_BIT)


def encryption_allows_rc4(supported_encryption_types: Any) -> bool:
    return not encryption_is_aes_only(supported_encryption_types)
