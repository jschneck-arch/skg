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


def load_adapter_policy() -> dict[str, Any]:
    return _load_yaml("adapter_policy.yaml")


def load_projection_policy() -> dict[str, Any]:
    return _load_yaml("projection_policy.yaml")


def load_surface_fingerprint_policy() -> dict[str, Any]:
    return _load_yaml("surface_fingerprint_policy.yaml")


def load_nikto_adapter_policy() -> dict[str, Any]:
    return _load_yaml("nikto_adapter_policy.yaml")


def load_auth_assessment_policy() -> dict[str, Any]:
    return _load_yaml("auth_assessment_policy.yaml")


def load_auth_runtime_policy() -> dict[str, Any]:
    return _load_yaml("auth_runtime_policy.yaml")
