from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest import mock


def _load_module(module_name: str, path: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_gravity_field():
    return _load_module(
        "skg_gravity_field_phase7s",
        "/opt/skg/skg-gravity/gravity_field.py",
    )


def test_bloodhound_wavelength_deauthorizes_ad07_ad09_from_canonical_coverage() -> None:
    with mock.patch.dict(
        os.environ,
        {"BH_PASSWORD": "", "NEO4J_PASSWORD": ""},
        clear=False,
    ):
        gravity_field = _load_gravity_field()
        instruments = gravity_field.detect_instruments()

    bloodhound = instruments["bloodhound"]
    assert "AD-06" in bloodhound.wavelength
    assert "AD-08" in bloodhound.wavelength
    assert "AD-07" not in bloodhound.wavelength
    assert "AD-09" not in bloodhound.wavelength


def test_legacy_ad06_collision_wavelengths_retired_from_inventory() -> None:
    with mock.patch.dict(
        os.environ,
        {"BH_PASSWORD": "", "NEO4J_PASSWORD": ""},
        clear=False,
    ):
        gravity_field = _load_gravity_field()
        instruments = gravity_field.detect_instruments()

    ldap_wavelength = instruments["ldap_enum"].wavelength
    impacket_wavelength = instruments["impacket_post"].wavelength

    assert "AD-06-LDAP-LEGACY" not in ldap_wavelength
    assert "AD-06-IMPACKET-LEGACY" not in impacket_wavelength
    assert "AD-06" not in ldap_wavelength
    assert "AD-06" not in impacket_wavelength


def test_legacy_ad06_collision_symbols_retired_but_ad22_quarantine_remains() -> None:
    ldap_enum = _load_module(
        "skg_gravity_ldap_enum_phase7s",
        "/opt/skg/skg-gravity/adapters/ldap_enum.py",
    )
    impacket_post = _load_module(
        "skg_gravity_impacket_post_phase7s",
        "/opt/skg/skg-gravity/adapters/impacket_post.py",
    )

    assert not hasattr(ldap_enum, "QUARANTINED_AD06_WICKET")
    assert not hasattr(impacket_post, "QUARANTINED_AD06_WICKET")
    assert getattr(ldap_enum, "QUARANTINED_AD22_WICKET", "") == "AD-22-LDAP-LEGACY"


def test_retired_collision_ids_are_not_referenced_by_runtime_authority_paths() -> None:
    gravity_field_path = "/opt/skg/skg-gravity/gravity_field.py"
    adapter_runner_path = "/opt/skg/skg/sensors/adapter_runner.py"

    gravity_text = Path(gravity_field_path).read_text(encoding="utf-8")
    runner_text = Path(adapter_runner_path).read_text(encoding="utf-8")

    for retired_id in ("AD-06-LDAP-LEGACY", "AD-06-IMPACKET-LEGACY"):
        assert retired_id not in gravity_text
        assert retired_id not in runner_text


def test_legacy_delegation_paths_are_explicit_and_compat_gated() -> None:
    adapter_runner = _load_module(
        "skg_adapter_runner_phase7u",
        "/opt/skg/skg/sensors/adapter_runner.py",
    )
    assert adapter_runner.LEGACY_DELEGATION_ATTACK_PATH_IDS == {
        "ad_unconstrained_delegation_v1",
        "ad_constrained_delegation_s4u_v1",
    }
    assert adapter_runner._legacy_delegation_enabled_for_path(  # noqa: SLF001
        "ad_constrained_delegation_s4u_v1"
    ) is False
