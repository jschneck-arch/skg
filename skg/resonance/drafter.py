"""
skg.resonance.drafter
=====================
Given a natural language description of a new attack domain,
proposes a structured wicket catalog by reasoning over existing
memory patterns.

Two modes:
  1. prompt  — builds grounded context from memory, writes a prompt file
               for the user to paste into claude.ai, saves a pending draft
  2. accept  — validates and promotes a JSON response into a proper draft

The prompt mode is the default when no API key is available.
An API key mode (direct Anthropic call) is preserved for future use.
"""

from __future__ import annotations
import json, logging, re
from pathlib import Path
from datetime import datetime, timezone

from skg.resonance.engine import ResonanceEngine

log = logging.getLogger("skg.resonance.drafter")

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

    wicket_context  = "\n".join(similar_wickets)  if similar_wickets  else "  (none)"
    adapter_context = "\n".join(similar_adapters) if similar_adapters else "  (none)"
    domain_context  = "\n".join(similar_domains)  if similar_domains  else "  (none)"

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
    errors = []
    for key in REQUIRED_CATALOG_KEYS:
        if key not in catalog:
            errors.append(f"Missing required key: {key}")

    wickets = catalog.get("wickets", {})
    paths   = catalog.get("attack_paths", {})

    if len(wickets) < MIN_WICKETS:
        errors.append(f"Too few wickets: {len(wickets)} (min {MIN_WICKETS})")
    if len(paths) < MIN_PATHS:
        errors.append(f"Too few attack paths: {len(paths)} (min {MIN_PATHS})")

    for path_id, path_def in paths.items():
        for wid in path_def.get("required_wickets", []):
            if wid not in wickets:
                errors.append(f"Path {path_id} references unknown wicket {wid}")

    for wid, wdef in wickets.items():
        for field in ("id", "label", "description", "evidence_hint"):
            if field not in wdef:
                errors.append(f"Wicket {wid} missing field: {field}")

    return errors


def draft_prompt(engine: ResonanceEngine,
                 domain_name: str,
                 description: str) -> dict:
    """
    Build a grounded prompt from memory and write it to a file.
    The user pastes the prompt into claude.ai and feeds the response
    back via draft_accept().

    Returns:
        {
            "domain":       domain_name,
            "prompt_path":  path to the .txt prompt file,
            "pending_path": path to the pending draft marker,
            "context_used": {...},
            "prompt":       the full prompt text,
        }
    """
    log.info(f"Building draft prompt for domain: {domain_name}")

    query   = f"{domain_name}: {description}"
    context = engine.surface(query, k_each=4)

    system = _build_system_prompt()
    user   = _build_user_prompt(domain_name, description, context)

    # Full prompt formatted for pasting into claude.ai
    full_prompt = f"""SYSTEM:
{system}

---

{user}"""

    ts           = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    drafts_dir   = engine._drafts_dir
    prompt_path  = drafts_dir / f"prompt_{domain_name}_{ts}.txt"
    pending_path = drafts_dir / f"pending_{domain_name}_{ts}.json"

    prompt_path.write_text(full_prompt, encoding="utf-8")

    # Write a pending marker so draft_accept knows the metadata
    pending = {
        "domain":      domain_name,
        "description": description,
        "drafted_at":  ts,
        "status":      "awaiting_response",
        "prompt_path": str(prompt_path),
        "context_used": {
            "wickets_surfaced":  len(context["wickets"]),
            "adapters_surfaced": len(context["adapters"]),
            "domains_surfaced":  len(context["domains"]),
        },
    }
    pending_path.write_text(json.dumps(pending, indent=2), encoding="utf-8")

    return {
        "domain":       domain_name,
        "prompt_path":  str(prompt_path),
        "pending_path": str(pending_path),
        "context_used": pending["context_used"],
        "prompt":       full_prompt,
    }


def draft_accept(engine: ResonanceEngine,
                 domain_name: str,
                 response_json: str | dict) -> dict:
    """
    Accept a JSON catalog response (from claude.ai or elsewhere),
    validate it, and save it as a proper draft.

    Args:
        engine:        the resonance engine
        domain_name:   domain this catalog is for
        response_json: either a JSON string, a path to a JSON file,
                       or an already-parsed dict

    Returns:
        {
            "domain":            domain_name,
            "catalog":           {...},
            "validation_errors": [...],
            "draft_path":        "...",
        }
    """
    # Parse input — string path, JSON string, or dict
    if isinstance(response_json, dict):
        catalog = response_json
    elif isinstance(response_json, str):
        p = Path(response_json)
        if p.exists():
            raw = p.read_text(encoding="utf-8")
        else:
            raw = response_json
        # Strip markdown fences if present
        raw = re.sub(r"^```json\s*", "", raw.strip())
        raw = re.sub(r"^```\s*",     "", raw)
        raw = re.sub(r"\s*```$",     "", raw).strip()
        try:
            catalog = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e
    else:
        raise TypeError(f"Unexpected type for response_json: {type(response_json)}")

    errors     = _validate_draft(catalog)
    draft_path = engine.save_draft(domain_name, catalog)

    # Mark any pending draft for this domain as accepted
    for pending in engine._drafts_dir.glob(f"pending_{domain_name}_*.json"):
        try:
            data = json.loads(pending.read_text(encoding="utf-8"))
            data["status"] = "accepted"
            data["draft_path"] = str(draft_path)
            pending.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    return {
        "domain":            domain_name,
        "catalog":           catalog,
        "validation_errors": errors,
        "draft_path":        str(draft_path),
    }


def draft_catalog(engine: ResonanceEngine,
                  domain_name: str,
                  description: str,
                  api_key: str | None = None) -> dict:
    """
    Legacy entry point. If api_key is provided, calls Anthropic directly.
    Otherwise falls back to prompt mode.
    """
    if not api_key:
        import os
        api_key = os.getenv("ANTHROPIC_API_KEY")

    if api_key:
        # Direct API call path (future: also support ollama here)
        log.info(f"Drafting catalog for domain: {domain_name} (API mode)")
        query   = f"{domain_name}: {description}"
        context = engine.surface(query, k_each=4)
        system  = _build_system_prompt()
        user    = _build_user_prompt(domain_name, description, context)

        import urllib.request
        payload = json.dumps({
            "model": "claude-sonnet-4-6",
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":    "application/json",
                "x-api-key":       api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                response = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"Anthropic API call failed: {e}") from e

        content_blocks = response.get("content", [])
        raw_text = "".join(
            b.get("text", "") for b in content_blocks if b.get("type") == "text"
        ).strip()
        raw_text = re.sub(r"^```json\s*", "", raw_text)
        raw_text = re.sub(r"^```\s*",     "", raw_text)
        raw_text = re.sub(r"\s*```$",     "", raw_text).strip()

        try:
            catalog = json.loads(raw_text)
        except json.JSONDecodeError as e:
            raise ValueError(f"API returned invalid JSON: {e}") from e

        errors     = _validate_draft(catalog)
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
    else:
        # Try local ollama backend
        try:
            from skg.resonance.ollama_backend import OllamaBackend
            backend = OllamaBackend()
            if backend.available():
                log.info(f"No API key — using local ollama backend")
                query   = f"{domain_name}: {description}"
                context = engine.surface(query, k_each=4)
                catalog, errors = backend.draft_catalog(domain_name, description, context)
                draft_path = engine.save_draft(domain_name, catalog)
                return {
                    "domain":            domain_name,
                    "catalog":           catalog,
                    "validation_errors": errors,
                    "draft_path":        str(draft_path),
                    "backend":           "ollama",
                    "model":             backend.model(),
                    "context_used": {
                        "wickets_surfaced":  len(context["wickets"]),
                        "adapters_surfaced": len(context["adapters"]),
                        "domains_surfaced":  len(context["domains"]),
                    },
                }
        except Exception as exc:
            log.warning(f"Ollama backend failed: {exc}")

        # Final fallback: prompt mode — build context, write prompt file
        raise ValueError(
            "No API key and Ollama unavailable. Options:\n"
            "  1. Start ollama: ollama serve && ollama pull llama3.2:3b\n"
            "  2. Use prompt mode: skg resonance draft-prompt\n"
            "     then paste into claude.ai and: skg resonance draft-accept"
        )


def record_draft_accept(domain: str, description: str,
                        prompt: str, catalog: dict):
    """Record an accepted draft as a positive training example."""
    try:
        from skg.training.corpus import on_draft_accept
        on_draft_accept(domain, description, prompt, catalog)
    except Exception:
        pass
