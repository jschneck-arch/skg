from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_POLICIES_ROOT = Path(__file__).resolve().parent


def _load_yaml(name: str) -> dict[str, Any]:
    payload = yaml.safe_load((_POLICIES_ROOT / name).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {}


def load_privileged_membership_policy() -> dict[str, Any]:
    return _load_yaml("privileged_membership_policy.yaml")


def load_credential_hint_policy() -> dict[str, Any]:
    return _load_yaml("credential_hint_policy.yaml")


def load_asrep_exposure_policy() -> dict[str, Any]:
    return _load_yaml("asrep_exposure_policy.yaml")


def load_kerberoast_exposure_policy() -> dict[str, Any]:
    return _load_yaml("kerberoast_exposure_policy.yaml")


def load_laps_coverage_policy() -> dict[str, Any]:
    return _load_yaml("laps_coverage_policy.yaml")


def load_weak_password_policy_policy() -> dict[str, Any]:
    return _load_yaml("weak_password_policy.yaml")


def load_tiering_posture_policy() -> dict[str, Any]:
    return _load_yaml("tiering_posture_policy.yaml")


def load_delegation_posture_policy() -> dict[str, Any]:
    return _load_yaml("delegation_posture_policy.yaml")


def load_projection_policy() -> dict[str, Any]:
    return _load_yaml("projection_policy.yaml")
