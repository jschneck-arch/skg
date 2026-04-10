from __future__ import annotations

import json
from pathlib import Path

_INTERP_ENVELOPE_KEYS = {"id", "ts", "type", "source", "provenance", "payload"}

_CLASSIFICATION_ALIASES = {
    "fully_realized": "realized",
    "blocked": "not_realized",
    "partial": "indeterminate",
    "indeterminate_h1": "indeterminate",
}


def normalize_interp_classification(classification: str) -> str:
    classification = str(classification or "").strip()
    if classification in {"realized", "not_realized", "indeterminate", "unknown"}:
        return classification
    return _CLASSIFICATION_ALIASES.get(classification, classification or "unknown")


def canonical_interp_payload(interp: dict) -> dict:
    """
    Flatten wrapped interp envelopes into one canonical payload dict.

    Existing projectors emit a mix of bare payloads and interp.* envelopes.
    Core SKG should consume one shape regardless of how a toolchain serialized it.
    """
    if not isinstance(interp, dict):
        return {}

    payload = interp.get("payload")
    if isinstance(payload, dict):
        normalized = {
            key: value
            for key, value in interp.items()
            if key not in _INTERP_ENVELOPE_KEYS
        }
        normalized.update(payload)
    else:
        normalized = dict(interp)
        normalized.pop("payload", None)

    if "computed_at" not in normalized and interp.get("ts"):
        normalized["computed_at"] = interp["ts"]

    normalized["classification"] = normalize_interp_classification(
        normalized.get("classification", "unknown")
    )
    return normalized


def read_interp_payload(path: Path) -> dict | None:
    """
    Read an interp artifact and return the canonical flattened payload.

    Supports both JSON payload files and legacy NDJSON interp envelopes.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return None

    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        if path.suffix != ".ndjson":
            return None
        raw = None
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            break
        if raw is None:
            return None

    if not isinstance(raw, dict):
        return None
    return canonical_interp_payload(raw)
