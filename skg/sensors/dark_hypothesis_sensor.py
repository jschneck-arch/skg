"""
skg.sensors.dark_hypothesis_sensor
=====================================
Cognitive planner sensor: maps dark hypotheses to actionable field probes.

Role in the autonomous loop:
  - Gravity cycle identifies high-torque wickets with no instrument (dark hypotheses)
  - Forge creates *new* toolchains for unknown domains
  - This sensor handles the complementary case: the domain *has* instruments but
    no instrument is currently aimed at the dark wicket on a specific target.

    dark_hypothesis → LLM reasoning → cognitive_action proposal
                                              ↓
                               engine dispatches existing instrument
                                              ↓
                               observation realized → dark → observable

Prompt strategy:
  The LLM receives the wicket definition, the target's current observed state,
  and the set of available instruments.  It returns a JSON object naming which
  instrument to run, the target host, and the specific collection command to use.

Output:
  Proposals written to PROPOSALS_DIR with proposal_kind = "cognitive_action".
  These are operator-reviewable by default; engine can auto-dispatch after a
  configurable confidence threshold.

Configuration (skg_config.yaml under dark_hypothesis_sensor:):
  enabled:          true
  min_torque:       1.5        # only reason about hypotheses above this torque
  max_proposals:    6          # per gravity cycle
  auto_dispatch:    false      # if true, accepted proposals run immediately
  ollama_model:     null       # override model (null = use OllamaBackend default)
  temperature:      0.2
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("skg.sensors.dark_hypothesis")
from skg_registry import DomainRegistry as _CanonicalDomainRegistry

# ── proposal storage ───────────────────────────────────────────────────────────
try:
    from skg_core.config.paths import SKG_STATE_DIR
    _PROPOSALS_DIR: Path = SKG_STATE_DIR / "proposals"
except Exception:
    _PROPOSALS_DIR = Path("/tmp/skg/proposals")


def _write_proposal(proposal: dict) -> Path:
    _PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    p = _PROPOSALS_DIR / f"{proposal['id']}.json"
    p.write_text(json.dumps(proposal, indent=2))
    return p


# ── LLM back-end (Ollama; falls back gracefully) ──────────────────────────────

def _call_llm(prompt: str, model: str | None = None, temperature: float = 0.2) -> str | None:
    """Try Ollama first, then check for API keys.  Returns raw text or None."""
    try:
        from skg.resonance.ollama_backend import OllamaBackend
        ob = OllamaBackend(model=model) if model else OllamaBackend()
        if ob.available():
            return ob.generate(prompt, temperature=temperature, num_predict=512)
    except Exception as exc:
        log.debug("[dark_hyp_sensor] Ollama unavailable: %s", exc)

    # Anthropic API fallback
    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        try:
            import urllib.request
            payload = {
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 512,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
            req = urllib.request.Request(
                url="https://api.anthropic.com/v1/messages",
                data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            return data["content"][0]["text"]
        except Exception as exc:
            log.debug("[dark_hyp_sensor] Anthropic API fallback failed: %s", exc)

    return None


# ── instrument discovery ───────────────────────────────────────────────────────

def _available_instruments() -> list[dict]:
    """Return a list of installed toolchain descriptors.

    Sources checked in priority order:
    1. Checked-in toolchains via the domain registry (skg-*-toolchain/ dirs)
    2. State-installed toolchains under SKG_STATE_DIR/toolchains/
    """
    instruments: list[dict] = []
    seen_domains: set[str] = set()

    # 1. Check-in toolchains from domain registry
    try:
        rows = []
        for record in _CanonicalDomainRegistry.discover().list_domains():
            metadata = dict(record.manifest.metadata or {})
            rows.append(
                {
                    "name": record.name,
                    "toolchain": record.root_dir.name,
                    "dir": record.root_dir,
                    "catalog_count": len(list(record.catalogs_dir.glob("*.json"))) if record.catalogs_dir.exists() else 0,
                    "runtime": record.manifest.runtime,
                    "description": str(metadata.get("description") or ""),
                }
            )

        for row in rows:
            domain = row.get("name", "unknown")
            seen_domains.add(domain)
            instruments.append({
                "name":         row.get("toolchain", domain),
                "domain":       domain,
                "path":         str(row.get("dir", "")),
                "wicket_count": row.get("catalog_count", 0),
            })
    except Exception as exc:
        log.debug("[dark_hyp_sensor] domain registry scan failed: %s", exc)

    # 2. State-installed toolchains (generated by forge)
    try:
        from skg_core.config.paths import SKG_STATE_DIR
        toolchains_dir = SKG_STATE_DIR / "toolchains"
        if toolchains_dir.exists():
            for meta_f in toolchains_dir.glob("*/forge_meta.json"):
                try:
                    meta = json.loads(meta_f.read_text())
                    domain = meta.get("domain", "unknown")
                    if domain in seen_domains:
                        continue  # already covered by registry
                    seen_domains.add(domain)
                    instruments.append({
                        "name":         meta.get("tc_name", meta_f.parent.name),
                        "domain":       domain,
                        "path":         str(meta_f.parent),
                        "wicket_count": meta.get("wicket_count", 0),
                    })
                except Exception:
                    pass
    except Exception as exc:
        log.debug("[dark_hyp_sensor] state toolchain scan failed: %s", exc)

    return instruments


# ── prompt builder ─────────────────────────────────────────────────────────────

_SYSTEM_CONTEXT = """\
You are a field-intelligence planner for a knowledge graph inference engine.
The engine collects observations from live systems.  Some high-confidence
predictions in the graph have no corresponding instrument coverage — these are
called "dark hypotheses".

Your task: given a dark hypothesis and the available instruments, recommend
the single most informative collection action that would confirm or deny the
hypothesis.

Respond ONLY with a JSON object (no markdown, no explanation) using this schema:
{
  "instrument": "<toolchain name>",
  "target":     "<host IP or hostname>",
  "command":    "<specific shell command to run via SSH or equivalent>",
  "wicket_id":  "<wicket ID this resolves>",
  "rationale":  "<one sentence>"
}
If no existing instrument can probe this hypothesis, respond with:
{"instrument": null, "reason": "<why none apply>"}
"""


def _build_prompt(hypothesis: dict, target: str, instruments: list[dict],
                  observed_state: dict) -> str:
    instr_lines = "\n".join(
        f"  - {i['name']} (domain={i['domain']}, wickets={i['wicket_count']})"
        for i in instruments[:12]
    ) or "  (none installed)"

    state_summary = json.dumps(
        {k: v for k, v in observed_state.items() if k not in ("raw",)},
        indent=2
    )[:800]

    return (
        f"{_SYSTEM_CONTEXT}\n\n"
        f"## Dark hypothesis\n"
        f"Wicket ID  : {hypothesis.get('wicket_id', '?')}\n"
        f"Domain     : {hypothesis.get('domain', '?')}\n"
        f"Label      : {hypothesis.get('label', '?')}\n"
        f"Torque     : {hypothesis.get('torque', 0):.3f}\n"
        f"Description: {hypothesis.get('description', '?')}\n\n"
        f"## Target\n{target}\n\n"
        f"## Current observed state (summary)\n{state_summary}\n\n"
        f"## Available instruments\n{instr_lines}\n\n"
        "Respond with JSON only."
    )


# ── main API ───────────────────────────────────────────────────────────────────

def plan_dark_hypotheses(
    landscape: list[dict],
    *,
    min_torque: float = 1.5,
    max_proposals: int = 6,
    llm_model: str | None = None,
    temperature: float = 0.2,
) -> list[dict]:
    """
    For each dark hypothesis above `min_torque`, ask the LLM which existing
    instrument can probe it.  Returns list of created proposal dicts.

    Called from gravity_field.py at the end of each compute cycle.
    """
    instruments = _available_instruments()
    proposals: list[dict] = []

    # Flatten dark hypotheses across all targets, sorted by torque descending
    candidates: list[tuple[float, str, dict]] = []   # (torque, target, hyp)
    for target_entry in landscape:
        target_ip = target_entry.get("host") or target_entry.get("target", "?")
        observed  = target_entry.get("observations", {})
        for hyp in target_entry.get("wgraph_dark", []):
            t = float(hyp.get("torque", 0))
            if t >= min_torque:
                candidates.append((t, target_ip, hyp, observed))

    candidates.sort(key=lambda x: x[0], reverse=True)

    for torque, target, hyp, observed in candidates[:max_proposals]:
        try:
            prompt = _build_prompt(hyp, target, instruments, observed)
            raw = _call_llm(prompt, model=llm_model, temperature=temperature)
            if not raw:
                log.debug("[dark_hyp_sensor] LLM returned nothing for %s/%s",
                          target, hyp.get("wicket_id"))
                continue

            # strip markdown fences if present
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[-1]
                raw = raw.rsplit("```", 1)[0].strip()

            plan = json.loads(raw)
        except json.JSONDecodeError:
            log.debug("[dark_hyp_sensor] LLM output not valid JSON for %s/%s: %s",
                      target, hyp.get("wicket_id"), raw[:120] if raw else "(none)")
            continue
        except Exception as exc:
            log.warning("[dark_hyp_sensor] planning error for %s: %s", target, exc)
            continue

        if not plan.get("instrument"):
            log.debug("[dark_hyp_sensor] LLM reports no instrument for %s/%s: %s",
                      target, hyp.get("wicket_id"), plan.get("reason", ""))
            continue

        proposal_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()

        proposal: dict[str, Any] = {
            "id":              proposal_id,
            # Emitted as field_action so the shared proposal trigger path can
            # execute it without special-casing.  The cognitive_action source is
            # preserved in the "source" field for auditability.
            "proposal_kind":   "field_action",
            "source":          "cognitive_action",
            "domain":          hyp.get("domain", "unknown"),
            "wicket_id":       hyp.get("wicket_id", "?"),
            "target":          target,
            "torque":          round(torque, 4),
            "instrument":      plan["instrument"],
            "command":         plan.get("command", ""),
            "rationale":       plan.get("rationale", ""),
            "llm_plan":        plan,
            "hypothesis":      hyp,
            "status":          "pending",
            "generated_at":    now,
            "maturity":        {"level": "candidate", "reason": "llm_planner"},
        }

        try:
            p = _write_proposal(proposal)
            log.info("[dark_hyp_sensor] cognitive_action proposal: %s → %s cmd=%s  (%s)",
                     proposal_id, target, plan.get("command", "")[:60], p)
        except Exception as exc:
            log.warning("[dark_hyp_sensor] failed to write proposal: %s", exc)
            continue

        proposals.append(proposal)

    return proposals
