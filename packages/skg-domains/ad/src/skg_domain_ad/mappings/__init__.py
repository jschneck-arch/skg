from __future__ import annotations

from pathlib import Path

import yaml

_MAPPINGS_ROOT = Path(__file__).resolve().parent


def _load_yaml(name: str) -> dict:
    payload = yaml.safe_load((_MAPPINGS_ROOT / name).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {}


def load_privileged_group_aliases() -> list[str]:
    payload = _load_yaml("privileged_group_aliases.yaml")
    values = payload.get("privileged_group_aliases")
    if isinstance(values, list):
        return [str(value).strip().lower() for value in values if str(value).strip()]
    return []


def load_password_description_keywords() -> list[str]:
    payload = _load_yaml("password_description_keywords.yaml")
    values = payload.get("password_description_keywords")
    if isinstance(values, list):
        return [str(value).strip().lower() for value in values if str(value).strip()]
    return []


def load_laps_semantics_mapping() -> dict:
    return _load_yaml("laps_semantics.yaml")
