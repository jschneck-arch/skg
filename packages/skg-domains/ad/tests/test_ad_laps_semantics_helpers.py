from __future__ import annotations

from skg_domain_ad.adapters.common import (
    is_non_dc_computer_candidate,
    laps_password_attribute_present,
    resolve_laps_presence,
)


def test_is_non_dc_computer_candidate_uses_enabled_and_dc_flags() -> None:
    assert is_non_dc_computer_candidate(enabled=True, is_domain_controller=False)
    assert is_non_dc_computer_candidate(enabled="true", is_domain_controller="no")
    assert not is_non_dc_computer_candidate(enabled=False, is_domain_controller=False)
    assert not is_non_dc_computer_candidate(enabled=True, is_domain_controller=True)


def test_laps_password_attribute_present_matches_legacy_non_none_signal() -> None:
    assert not laps_password_attribute_present(None)
    assert laps_password_attribute_present("")
    assert laps_password_attribute_present("redacted")
    assert laps_password_attribute_present([])


def test_resolve_laps_presence_prefers_explicit_signal() -> None:
    attrs = {"ms-Mcs-AdmPwd": None}
    assert resolve_laps_presence(explicit_has_laps=True, attributes=attrs) is True
    assert resolve_laps_presence(explicit_has_laps=False, attributes=attrs) is False


def test_resolve_laps_presence_uses_attribute_signal_when_explicit_absent() -> None:
    assert resolve_laps_presence(attributes={"ms-Mcs-AdmPwd": "secret"}) is True
    assert resolve_laps_presence(attributes={"msLAPS-Password": ""}) is True
    assert resolve_laps_presence(attributes={"ms-mcs-admpwd": None}) is False
    assert resolve_laps_presence(attributes={"unrelated": "value"}) is None
