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


def load_nmap_adapter_policy() -> dict[str, Any]:
    return _load_yaml("nmap_adapter_policy.yaml")


def load_ssh_adapter_policy() -> dict[str, Any]:
    return _load_yaml("ssh_adapter_policy.yaml")


def load_winrm_adapter_policy() -> dict[str, Any]:
    return _load_yaml("winrm_adapter_policy.yaml")


def load_projection_policy() -> dict[str, Any]:
    return _load_yaml("projection_policy.yaml")
