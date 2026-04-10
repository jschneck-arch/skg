from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_MAPPINGS_ROOT = Path(__file__).resolve().parent


def _load_yaml(name: str, default: dict[str, Any]) -> dict[str, Any]:
    payload = yaml.safe_load((_MAPPINGS_ROOT / name).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return default


def load_service_wickets() -> dict[str, Any]:
    return _load_yaml("service_wickets.yaml", {"services": []})


def load_exploit_signatures() -> dict[str, Any]:
    return _load_yaml("exploit_signatures.yaml", {"signatures": []})
