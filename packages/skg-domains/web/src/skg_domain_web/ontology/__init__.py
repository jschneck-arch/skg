from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

_ONT_ROOT = Path(__file__).resolve().parent


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {}


def load_wickets() -> dict[str, dict[str, Any]]:
    payload = _load_yaml(_ONT_ROOT / "wickets.yaml")
    wickets = payload.get("wickets")
    if isinstance(wickets, dict):
        return {str(k): dict(v) for k, v in wickets.items() if isinstance(v, dict)}
    return {}


def load_attack_paths() -> dict[str, dict[str, Any]]:
    payload = _load_yaml(_ONT_ROOT / "attack_paths.yaml")
    attack_paths = payload.get("attack_paths")
    if isinstance(attack_paths, dict):
        return {str(k): dict(v) for k, v in attack_paths.items() if isinstance(v, dict)}
    return {}


def load_catalog() -> dict[str, Any]:
    catalog_path = _ONT_ROOT / "catalogs" / "attack_preconditions_catalog.web.v1.json"
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {}
