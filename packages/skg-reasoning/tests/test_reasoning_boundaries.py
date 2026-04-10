from __future__ import annotations

import inspect

import skg_reasoning.delegation_engine as delegation_engine


def test_reasoning_engine_has_no_domain_or_service_imports() -> None:
    source = inspect.getsource(delegation_engine)

    assert "skg_domain_" not in source
    assert "skg_services" not in source
    assert "skg.sensors" not in source
    assert "skg-gravity" not in source


def test_reasoning_engine_emits_derived_output_not_raw_observations() -> None:
    source = inspect.getsource(delegation_engine)

    assert "build_event_envelope" not in source
    assert "build_precondition_payload" not in source
