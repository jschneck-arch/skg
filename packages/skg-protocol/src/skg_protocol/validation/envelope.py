from __future__ import annotations


def validate_event_envelope(event: dict) -> list[str]:
    """Validate minimal canonical event envelope shape."""

    errors: list[str] = []
    if not isinstance(event, dict):
        return ["envelope must be a dict"]

    for field in ("id", "ts", "type", "source", "payload", "provenance"):
        if field not in event:
            errors.append(f"missing field: {field}")

    source = event.get("source")
    if source is not None and not isinstance(source, dict):
        errors.append("source must be a dict")
    elif isinstance(source, dict):
        for field in ("source_id", "toolchain", "version"):
            if field not in source:
                errors.append(f"source missing field: {field}")

    provenance = event.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        errors.append("provenance must be a dict")
    elif isinstance(provenance, dict):
        if "evidence_rank" not in provenance:
            errors.append("provenance missing field: evidence_rank")
        evidence = provenance.get("evidence")
        if evidence is None:
            errors.append("provenance missing field: evidence")
        elif not isinstance(evidence, dict):
            errors.append("provenance.evidence must be a dict")
        else:
            for field in ("source_kind", "pointer", "collected_at", "confidence"):
                if field not in evidence:
                    errors.append(f"provenance.evidence missing field: {field}")

    payload = event.get("payload")
    if payload is not None and not isinstance(payload, dict):
        errors.append("payload must be a dict")

    return errors
