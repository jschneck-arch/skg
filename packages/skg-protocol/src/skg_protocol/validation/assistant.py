from __future__ import annotations

import hashlib
import json
from typing import Any


OBSERVED_EVIDENCE = "observed_evidence"
DERIVED_ADVICE = "derived_advice"
MUTATION_ARTIFACT = "mutation_artifact"
RECONCILIATION_CLAIM = "reconciliation_claim"

ASSISTANT_SOURCE_KINDS = {
    "assistant",
    "ai_assistant",
    "ollama_assistant",
    "llm_assistant",
    "assistant_claim",
}

ASSISTANT_SOURCE_PREFIXES = (
    "assistant",
    "assistant.",
    "assistant/",
    "ollama",
    "ollama.",
    "llm",
    "llm.",
)


def artifact_hash(content: Any) -> str:
    if isinstance(content, (bytes, bytearray)):
        payload = bytes(content)
    elif isinstance(content, str):
        payload = content.encode("utf-8", errors="replace")
    else:
        payload = json.dumps(
            content,
            sort_keys=True,
            default=str,
            ensure_ascii=True,
        ).encode("utf-8", errors="replace")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def custody_chain_complete(custody_chain: Any) -> bool:
    if not isinstance(custody_chain, dict):
        return False
    has_artifact = bool(custody_chain.get("artifact_path") or custody_chain.get("artifact_ref"))
    has_hash = bool(custody_chain.get("artifact_hash"))
    has_source = bool(
        custody_chain.get("source_uri")
        or custody_chain.get("source_pointer")
        or custody_chain.get("source_command")
    )
    has_collected_at = bool(custody_chain.get("collected_at") or custody_chain.get("observed_at"))
    return has_artifact and has_hash and has_source and has_collected_at


def assistant_output_metadata(
    output_class: str,
    *,
    task: str = "",
    contract_name: str = "",
    demand: dict[str, Any] | None = None,
    model: str | None = None,
    custody_chain: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_class = str(output_class or "").strip() or DERIVED_ADVICE
    demand = dict(demand or {})
    custody_chain = dict(custody_chain or {})

    return {
        "assistant_output_class": normalized_class,
        "task": task,
        "contract_name": contract_name,
        "model": model,
        "state_authority": (
            "custody_relay_only" if normalized_class == OBSERVED_EVIDENCE else "advisory_only"
        ),
        "observation_admissible": (
            normalized_class == OBSERVED_EVIDENCE and custody_chain_complete(custody_chain)
        ),
        "requires_reobservation": normalized_class != OBSERVED_EVIDENCE,
        "admissible_effects": list(demand.get("admissible_effects") or []),
        "forbidden_effects": list(demand.get("forbidden_effects") or []),
        "custody_chain": custody_chain,
    }


def classify_assistant_event(event: dict[str, Any]) -> dict[str, Any]:
    payload = dict(event.get("payload") or {})
    provenance = dict(event.get("provenance") or {})
    evidence = dict(provenance.get("evidence") or {})
    source = dict(event.get("source") or {})

    source_id = str(source.get("source_id") or "").strip().lower()
    source_kind = str(evidence.get("source_kind") or "").strip().lower()
    explicit_class = str(
        payload.get("assistant_output_class")
        or evidence.get("assistant_output_class")
        or evidence.get("evidence_class")
        or payload.get("evidence_class")
        or ""
    ).strip()
    custody_chain = evidence.get("custody_chain") or payload.get("custody_chain") or {}

    is_assistant = bool(explicit_class) or source_kind in ASSISTANT_SOURCE_KINDS or any(
        source_id == prefix or source_id.startswith(prefix)
        for prefix in ASSISTANT_SOURCE_PREFIXES
    )

    effective_class = explicit_class or (DERIVED_ADVICE if is_assistant else OBSERVED_EVIDENCE)

    admissible = True
    reason = ""
    if effective_class != OBSERVED_EVIDENCE:
        admissible = False
        reason = "non-observation assistant output cannot enter the observation plane"
    elif is_assistant and not custody_chain_complete(custody_chain):
        admissible = False
        reason = "assistant-relayed evidence is missing a complete custody chain"

    return {
        "is_assistant": is_assistant,
        "assistant_output_class": effective_class,
        "custody_chain": custody_chain if isinstance(custody_chain, dict) else {},
        "observation_admissible": admissible,
        "reason": reason,
    }


def observation_event_admissible(event: dict[str, Any]) -> bool:
    return bool(classify_assistant_event(event).get("observation_admissible", True))
