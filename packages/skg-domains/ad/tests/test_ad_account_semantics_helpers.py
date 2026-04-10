from __future__ import annotations

from skg_domain_ad.adapters.common import (
    coerce_int_scalar,
    encryption_allows_rc4,
    encryption_is_aes_only,
    has_dont_require_preauth,
    is_account_enabled,
)


def test_coerce_int_scalar_handles_list_and_invalid_values() -> None:
    assert coerce_int_scalar(["12"]) == 12
    assert coerce_int_scalar("8") == 8
    assert coerce_int_scalar(None) is None
    assert coerce_int_scalar("not-int") is None


def test_is_account_enabled_prefers_explicit_then_uac() -> None:
    assert is_account_enabled(explicit_enabled=True)
    assert not is_account_enabled(explicit_enabled="false")
    assert is_account_enabled(user_account_control=512)
    assert not is_account_enabled(user_account_control=514)


def test_has_dont_require_preauth_supports_explicit_and_uac_bit() -> None:
    assert has_dont_require_preauth(explicit_flag=True)
    assert has_dont_require_preauth(user_account_control=0x400000)
    assert not has_dont_require_preauth(user_account_control=512)


def test_encryption_flag_helpers_match_legacy_rc4_logic() -> None:
    assert encryption_is_aes_only(0x10)
    assert not encryption_is_aes_only(0x14)  # AES + RC4
    assert encryption_allows_rc4(0x14)
    assert encryption_allows_rc4(0)  # unknown/missing treated as not AES-only in legacy flow
