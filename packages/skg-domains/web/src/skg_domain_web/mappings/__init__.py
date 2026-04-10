from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_MAPPINGS_ROOT = Path(__file__).resolve().parent


def load_path_signatures() -> dict[str, Any]:
    payload = yaml.safe_load((_MAPPINGS_ROOT / "path_signatures.yaml").read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {"wickets": {}}


def load_surface_fingerprint_rules() -> dict[str, Any]:
    payload = yaml.safe_load((_MAPPINGS_ROOT / "surface_fingerprint_rules.yaml").read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {}


def load_nikto_patterns() -> dict[str, Any]:
    payload = yaml.safe_load((_MAPPINGS_ROOT / "nikto_patterns.yaml").read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {"patterns": []}
