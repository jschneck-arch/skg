from __future__ import annotations

from skg_domain_ad.adapters.common import (
    description_has_password_hint,
    is_machine_account_principal,
)
from skg_domain_ad.mappings import load_password_description_keywords


def test_is_machine_account_principal_handles_realm_suffix() -> None:
    assert is_machine_account_principal("WS01$@CONTOSO.LOCAL")
    assert is_machine_account_principal("SQL01$")
    assert not is_machine_account_principal("alice@CONTOSO.LOCAL")
    assert not is_machine_account_principal("")


def test_description_has_password_hint_uses_domain_keyword_mapping() -> None:
    keywords = load_password_description_keywords()
    assert "password" in keywords
    assert description_has_password_hint("Temporary password set to Welcome2026!")
    assert not description_has_password_hint("No account notes present.")
