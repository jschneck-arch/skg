from __future__ import annotations


def _major(version: str) -> int | None:
    text = str(version or "").strip()
    if not text:
        return None
    try:
        return int(text.split(".", 1)[0])
    except ValueError:
        return None


def is_protocol_compatible(
    manifest_protocol_version: str,
    required_protocol_version: str,
) -> bool:
    """
    Compatibility policy for canonical extraction pass.

    Current rule: major versions must match.
    """

    producer = _major(manifest_protocol_version)
    consumer = _major(required_protocol_version)
    if producer is None or consumer is None:
        return False
    return producer == consumer
