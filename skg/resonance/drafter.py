"""
skg.resonance.drafter
=====================
Given a natural language description of a new attack domain,
proposes a structured wicket catalog by reasoning over existing
memory patterns.

The drafter does NOT write code. It produces a catalog JSON
(wickets + attack paths) for human review. Once approved, a human
writes the adapter, or the drafter is extended to generate it.

Drafting strategy:
1. Query resonance memory for similar wickets across all domains
2. Query for similar adapters (what evidence sources might apply)
3. Build a structural template from the most similar existing domain
4. Use the Anthropic API to generate wicket definitions grounded in
   the existing memory patterns
5. Validate the output against the catalog schema
6. Save as a draft for human review

The Anthropic API call is the only non-deterministic step.
Everything else is deterministic — same memory, same query → same context.
"""

from __future__ import annotations
import json, logging, re
from pathlib import Path
from datetime import datetime, timezone

from skg.resonance.engine import ResonanceEngine

log = logging.getLogger("skg.resonance.drafter")

# Minimum structural requirements for a valid draft catalog
REQUIRED_CATALOG_KEYS = {"version", "description", "wickets", "attack_paths"}
MIN_WICKETS = 3
MIN_PATHS   = 1


def _build_system_prompt() -> str:
    return """You are the SKG resonance engine drafter. Your job is to propose
a wicket catalog for a new attack domain, following the exact structure
of existing SKG catalogs.

A wicket is an atomic, evidence-checkable precondition required for an
attack path to succeed. Each wicket must be:
- Independently verifiable from a specific evidence source
- Binary in nature (the condition either holds or it doesn't)
- Described with a concrete evidence_hint explaining how to check it

The output must be valid JSON only — no markdown, no explanation, no preamble.
Follow the schema exactly."""


def _build_user_prompt(domain_name: str, description: str,
                       context: dict) -> str:
    # Format similar wickets from memory
    similar_wickets = []
    for rec, score in context.get("wickets", []):
        similar_wickets.append(
            f"  [{rec['domain']}::{rec['wicket_id']}] {rec['label']}\n"
            f"    {rec['description']}\n"
            f"    Evidence: {rec['evidence_hint']}"
        )

    similar_adapters = []
    for rec, score in context.get("adapters", []):
        sources = "; ".join(rec.get("evidence_sources", []))
        similar_adapters.append(
            f"  [{rec['domain']}::{rec['adapter_name']}] {sources}"
        )

    similar_domains = []
    for rec, score in context.get("domains", []):
        similar_domains.append(
            f"  {rec['domain']}: {rec['description']} "
            f"({rec['wicket_count']} wickets, paths: {', '.join(rec['attack_paths'][:3])})"
        )

    wicket_context = "\n".join(similar_wickets) if similar_wickets else "  (none)"
    adapter_context = "\n".join(similar_adapters) if similar_adapters else "  (none)"
    domain_context = "\n".join(similar_domains) if similar_domains else "  (none)"

    return f"""Propose a SKG wicket catalog for this attack domain:

Domain name: {domain_name}
Description: {description}

Similar wickets from existing domains (for pattern reference):
{wicket_context}

Similar adapters and their evidence sources:
{adapter_context}

Similar existing domains:
{domain_context}

Produce a JSON catalog with this exact structure:
{{
  "version": "1.0.0",
  "description": "<one sentence describing this domain>",
  "wickets": {{
    "<DOMAIN_PREFIX>-01": {{
      "id": "<DOMAIN_PREFIX>-01",
      "label": "<snake_case_label>",
      "description": "<what condition this checks>",
      "evidence_hint": "<what to look at and how to check it>"
    }}
    ... (8-15 wickets minimum)
  }},
  "attack_paths": {{
    "<domain_name>_<path_name>_v1": {{
      "id": "<domain_name>_<path_name>_v1",
      "description": "<what this attack achieves>",
      "required_wickets": ["<DOMAIN_PREFIX>-01", ...],
      "references": ["https://attack.mitre.org/techniques/..."]
    }}
    ... (3+ attack paths)
  }}
}}

Use a 2-3 letter uppercase prefix for wicket IDs that abbreviates the domain.
Ensure every wicket referenced in attack_paths exists in the wickets dict.
Output JSON only."""


def _validate_draft(catalog: dict) -> list[str]:
    """Return list of validation errors. Empty list = valid."""
    errors = []
    for key in REQUIRED_CATALOG_KEYS:
        if key not in catalog:
            errors.append(f"Missing required key: {key}")

    wickets    = catalog.get("wickets", {})
    paths      = catalog.get("attack_paths", {})

    if len(wickets) < MIN_WICKETS:
        errors.append(f"Too few wickets: {len(wickets)} (min {MIN_WICKETS})")
    if len(paths) < MIN_PATHS:
        errors.append(f"Too few attack paths: {len(paths)} (min {MIN_PATHS})")

    # Check all referenced wickets exist
    for path_id, path_def in paths.items():
        for wid in path_def.get("required_wickets", []):
            if wid not in wickets:
                errors.append(f"Path {path_id} references unknown wicket {wid}")

    # Check wicket structure
    for wid, wdef in wickets.items():
        for field in ("id", "label", "description", "evidence_hint"):
            if field not in wdef:
                errors.append(f"Wicket {wid} missing field: {field}")

    return errors


def draft_catalog(engine: ResonanceEngine,
                  domain_name: str,
                  description: str,
                  api_key: str | None = None) -> dict:
    """
    Generate a draft catalog for a new domain.

    Returns:
        {
            "domain": domain_name,
            "catalog": {...},        # proposed catalog
            "validation_errors": [], # empty if valid
            "draft_path": "...",     # path where draft was saved
            "context_used": {...},   # memory that informed the draft
        }
    """
    log.info(f"Drafting catalog for domain: {domain_name}")

    # Step 1: surface relevant memory
    query = f"{domain_name}: {description}"
    context = engine.surface(query, k_each=4)
    log.info(f"  Context: {len(context['wickets'])} wickets, "
             f"{len(context['adapters'])} adapters, "
             f"{len(context['domains'])} domains surfaced")

    # Step 2: call Anthropic API
    import urllib.request, os
    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError(
            "ANTHROPIC_API_KEY not set. Pass api_key= or set the environment variable.")

    system = _build_system_prompt()
    user   = _build_user_prompt(domain_name, description, context)

    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    log.info("  Calling Anthropic API...")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            response = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"Anthropic API call failed: {e}") from e

    # Extract text content
    content_blocks = response.get("content", [])
    raw_text = "".join(
        block.get("text", "")
        for block in content_blocks
        if block.get("type") == "text"
    ).strip()

    # Step 3: parse JSON — strip markdown fences if present
    raw_text = re.sub(r"^```json\s*", "", raw_text)
    raw_text = re.sub(r"^```\s*", "", raw_text)
    raw_text = re.sub(r"\s*```$", "", raw_text).strip()

    try:
        catalog = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"API returned invalid JSON: {e}\nRaw: {raw_text[:500]}") from e

    # Step 4: validate
    errors = _validate_draft(catalog)
    if errors:
        log.warning(f"  Draft has {len(errors)} validation issues: {errors}")
    else:
        log.info("  Draft passed validation")

    # Step 5: save draft
    draft_path = engine.save_draft(domain_name, catalog)

    return {
        "domain":            domain_name,
        "catalog":           catalog,
        "validation_errors": errors,
        "draft_path":        str(draft_path),
        "context_used": {
            "wickets_surfaced":  len(context["wickets"]),
            "adapters_surfaced": len(context["adapters"]),
            "domains_surfaced":  len(context["domains"]),
        },
    }
