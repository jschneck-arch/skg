"""
skg.resonance.ollama_backend
=============================
Ollama local model backend for catalog drafting.

The drafter's job is translation, not creativity:
  resonance context (existing wickets, adapters, domains)
  + domain description
  → valid catalog JSON

This is a structured format conversion task. A lightweight model
(llama3.2:3b, mistral:7b, gemma2:2b) handles it well.

The system prompt is tight and prescriptive. The model is told exactly
what JSON schema to produce and given examples from the resonance engine.
It does not need to understand offensive security — it needs to output
valid JSON that matches the catalog schema.

Ollama API: POST http://localhost:11434/api/generate
  {model, prompt, stream: false, options: {temperature: 0.1}}

Model selection (in order of preference for this task):
  1. Whatever is configured in sensors.yaml
  2. llama3.2:3b — fast, fits in 4GB VRAM, adequate for structured output
  3. mistral:7b  — better reasoning, needs 8GB VRAM
  4. Any available model from /api/tags

Usage:
  from skg.resonance.ollama_backend import OllamaBackend
  backend = OllamaBackend()
  catalog = backend.draft_catalog(domain_name, description, context)
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
import urllib.error
from typing import Any

log = logging.getLogger("skg.resonance.ollama")

DEFAULT_URL   = "http://localhost:11434"
DEFAULT_TEMPERATURE = 0.1
MODEL_PREFS   = ["tinyllama:latest", "tinyllama", "tinydolphin:latest", "tinydolphin",
                 "phi3:mini", "phi3", "llama3.2:3b", "llama3.2", "mistral:7b", "mistral"]

SCHEMA_EXAMPLE = """{
  "domain": "example_domain",
  "version": "1.0.0",
  "description": "One sentence describing the attack domain.",
  "wickets": {
    "EX-01": {
      "label": "short_snake_case_label",
      "description": "One sentence describing the attack precondition.",
      "evidence_hint": "How to detect this: what file/API/command to check.",
      "default_rank": 2
    }
  },
  "attack_paths": {
    "example_path_v1": {
      "label": "Human readable path name",
      "description": "What this path achieves.",
      "required_wickets": ["EX-01"],
      "ordered": false
    }
  }
}"""


def _build_prompt(domain_name: str, description: str, context: dict) -> str:
    """
    Build a tight, example-grounded prompt for catalog generation.
    The model only needs to translate — not reason about offensive security.
    """
    # Format context from resonance engine
    context_parts = []

    wickets = context.get("wickets", [])[:6]
    if wickets:
        context_parts.append("SIMILAR WICKETS FROM EXISTING CATALOGS:")
        for w in wickets:
            context_parts.append(
                f"  {w.get('id','')}: {w.get('label','')} — {w.get('description','')[:80]}"
            )

    adapters = context.get("adapters", [])[:3]
    if adapters:
        context_parts.append("RELEVANT ADAPTERS:")
        for a in adapters:
            context_parts.append(f"  {a.get('name','')}: {a.get('description','')[:80]}")

    domains = context.get("domains", [])[:3]
    if domains:
        context_parts.append("SIMILAR EXISTING DOMAINS:")
        for d in domains:
            context_parts.append(f"  {d.get('name','')}: {d.get('description','')[:80]}")

    context_str = "\n".join(context_parts) if context_parts else "No similar context found."

    # Derive wicket prefix from domain name
    prefix = "".join(w[0].upper() for w in domain_name.split("_")[:3])[:3]
    if not prefix:
        prefix = domain_name[:3].upper()

    prompt = f"""You are a JSON generator. Produce a valid SKG attack precondition catalog.

TASK: Generate a catalog JSON for the domain: {domain_name}
DESCRIPTION: {description}

OUTPUT FORMAT (produce ONLY this JSON, no other text, no markdown):
{SCHEMA_EXAMPLE}

RULES:
- Wicket IDs use prefix "{prefix}-" followed by two digits: {prefix}-01, {prefix}-02, etc.
- Labels are short snake_case strings
- Each wicket is one specific attack precondition (not a step)
- evidence_hint describes exactly what artifact to check (file path, API field, command output)
- default_rank: 1=runtime observation, 2=live command output, 3=config file, 4=network probe, 5=static analysis
- Include 4-12 wickets and 1-3 attack paths
- required_wickets must reference only wicket IDs defined in this catalog

CONTEXT FROM EXISTING CATALOGS:
{context_str}

Generate the catalog JSON now:"""

    return prompt


class OllamaBackend:
    """Local Ollama model backend for catalog drafting."""

    def __init__(self, url: str = DEFAULT_URL, model: str | None = None,
                 temperature: float = DEFAULT_TEMPERATURE):
        cfg = OllamaBackend.load_config()
        cfg_url = cfg.get("url") or url
        cfg_model = cfg.get("model")
        cfg_temp = cfg.get("temperature", temperature)

        env_url = os.getenv("SKG_OLLAMA_URL")
        env_model = os.getenv("SKG_OLLAMA_MODEL")
        env_temp = os.getenv("SKG_OLLAMA_TEMPERATURE")

        self.url = (env_url or cfg_url or DEFAULT_URL).rstrip("/")
        self._model = (
            model
            or OllamaBackend.load_model_override()
            or env_model
            or cfg_model
        )
        self.temperature = float(env_temp) if env_temp else float(cfg_temp)
        # generation_timeout_s: how long to wait for a full generation response.
        # Default 900s (15 min) — CPU-only inference for catalog/adapter JSON is slow.
        # Set resonance.ollama.generation_timeout_s in skg_config.yaml to override.
        self.generation_timeout_s = int(cfg.get("generation_timeout_s") or 900)

    @staticmethod
    def load_config() -> dict[str, Any]:
        """Load resonance.ollama config from SKG config if available."""
        try:
            import yaml
            from skg_core.config.paths import SKG_CONFIG_DIR, SKG_HOME

            candidates = [
                SKG_CONFIG_DIR / "skg_config.yaml",
                SKG_HOME / "config" / "skg_config.yaml",
            ]
            for cfg_path in candidates:
                if not cfg_path.exists():
                    continue
                data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                resonance = data.get("resonance", {}) or {}
                ollama = resonance.get("ollama", {}) or {}
                if isinstance(ollama, dict):
                    return ollama
            return {}
        except ImportError:
            log.warning("PyYAML is not installed; Ollama config file loading is unavailable")
            return {}
        except Exception:
            return {}

    def available(self) -> bool:
        """Check if Ollama is running."""
        try:
            req = urllib.request.Request(f"{self.url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3):
                return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return list of available model names."""
        try:
            req = urllib.request.Request(f"{self.url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    def model(self) -> str | None:
        """Select best available model."""
        if self._model:
            return self._model
        available = self.list_models()
        if not available:
            return None
        available_lower = [m.lower() for m in available]
        for pref in MODEL_PREFS:
            for i, m in enumerate(available_lower):
                if pref in m:
                    self._model = available[i]
                    return self._model
        # Use whatever's there
        self._model = available[0]
        return self._model

    def generate(self,
                 prompt: str,
                 model: str | None = None,
                 num_predict: int = 2048) -> str:
        """Send a generation request to Ollama. Returns raw text response."""
        m = model or self.model()
        if not m:
            raise RuntimeError("No Ollama models available. Run: ollama pull llama3.2:3b")

        payload = json.dumps({
            "model":  m,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": int(num_predict),
                "stop": ["```\n", "\n\nHuman:", "\n\nUser:"],
            },
        }).encode()

        req = urllib.request.Request(
            f"{self.url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.generation_timeout_s) as r:
                data = json.loads(r.read())
            return data.get("response", "").strip()
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

    def draft_catalog(self, domain_name: str, description: str,
                      context: dict) -> dict:
        """
        Generate a catalog for domain_name using local model.
        Returns parsed catalog dict.
        Raises ValueError if output is not valid JSON or fails schema check.
        """
        m = self.model()
        if not m:
            raise RuntimeError(
                "Ollama not available. Start ollama and pull a model:\n"
                "  ollama serve\n"
                "  ollama pull llama3.2:3b"
            )

        log.info(f"[ollama] drafting catalog for '{domain_name}' using {m}")
        prompt = _build_prompt(domain_name, description, context)

        # Catalogs are compact JSON — 512 tokens is sufficient and reduces
        # inference time significantly on CPU-only hardware.
        raw = self.generate(prompt, m, num_predict=512)

        # Strip markdown fences if present
        raw = re.sub(r"^```json\s*", "", raw)
        raw = re.sub(r"^```\s*",     "", raw)
        raw = re.sub(r"\s*```$",     "", raw).strip()

        # Extract first JSON object if model added commentary
        brace = raw.find("{")
        if brace > 0:
            raw = raw[brace:]
        last_brace = raw.rfind("}")
        if last_brace >= 0:
            raw = raw[:last_brace + 1]

        try:
            catalog = json.loads(raw)
        except json.JSONDecodeError as exc:
            # Retry once with stricter instruction
            log.warning(f"[ollama] first attempt invalid JSON ({exc}), retrying")
            retry_prompt = prompt + "\n\nCRITICAL: Output ONLY the JSON object. No text before or after."
            raw2 = self.generate(retry_prompt, m, num_predict=512)
            raw2 = re.sub(r"```[^\n]*\n?", "", raw2).strip()
            brace2 = raw2.find("{")
            if brace2 >= 0:
                raw2 = raw2[brace2:]
            try:
                catalog = json.loads(raw2)
            except json.JSONDecodeError as exc2:
                raise ValueError(
                    f"Ollama output is not valid JSON after retry: {exc2}\n"
                    f"Raw output (first 500 chars): {raw2[:500]}"
                ) from exc2

        # Basic schema validation
        errors = []
        if "wickets" not in catalog:
            errors.append("missing 'wickets' key")
        if "attack_paths" not in catalog:
            errors.append("missing 'attack_paths' key")
        if "domain" not in catalog:
            catalog["domain"] = domain_name

        log.info(f"[ollama] catalog generated: {len(catalog.get('wickets',{}))} wickets, "
                 f"{len(catalog.get('attack_paths',{}))} paths")

        return catalog, errors

    def set_model(self, model_tag: str):
        """
        Override the active model. Persists to SKG state so the
        training system can swap in a fine-tuned model after a run.
        """
        from skg_core.config.paths import SKG_STATE_DIR
        self._model = model_tag
        model_override_file = SKG_STATE_DIR / "training" / "active_model.txt"
        model_override_file.parent.mkdir(parents=True, exist_ok=True)
        model_override_file.write_text(model_tag)

    @staticmethod
    def load_model_override() -> str | None:
        """Load trainer model override if present."""
        try:
            from skg_core.config.paths import SKG_STATE_DIR
            f = SKG_STATE_DIR / "training" / "active_model.txt"
            if f.exists():
                tag = f.read_text().strip()
                return tag if tag else None
        except Exception:
            pass
        return None

    def status(self) -> dict:
        """Return current backend status."""
        running = self.available()
        models  = self.list_models() if running else []
        selected = self.model() if running else None
        return {
            "available":      running,
            "url":            self.url,
            "models":         models,
            "selected_model": selected,
            "temperature":    self.temperature,
            "configured_model": self._model,
        }
