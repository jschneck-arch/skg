"""
skg.resonance.llm_pool
======================
Multi-backend LLM pool with fiber-style concurrent dispatch.

Each backend is a lightweight worker fiber running inside a shared
ThreadPoolExecutor. Requests are dispatched to one or more backends
concurrently; the caller receives either the first valid response (race),
a merged result (ensemble), or a balanced load across backends (round_robin).

Supported backend types:
  ollama    — local Ollama server (any model/URL combination)
  anthropic — Anthropic API (claude-haiku-4-5-20251001, etc.)

Config (skg_config.yaml):
  resonance:
    llm_pool:
      enabled: true
      strategy: race          # race | round_robin | ensemble
      max_workers: 4          # total fiber threads in the pool
      backends:
        - type: ollama
          url: http://localhost:11434
          model: tinyllama:latest
          temperature: 0.1
          generation_timeout_s: 900
        - type: ollama
          url: http://localhost:11434
          model: llama3.2:3b
          temperature: 0.1
          generation_timeout_s: 900
        - type: anthropic
          model: claude-haiku-4-5-20251001
          max_tokens: 1024

If llm_pool is not configured or disabled, a single-backend pool is
constructed from the existing resonance.ollama config (backward compatible).
"""
from __future__ import annotations

import concurrent.futures
import logging
import os
import threading
from abc import ABC, abstractmethod
from typing import Any

log = logging.getLogger("skg.resonance.llm_pool")


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------

class LLMBackend(ABC):
    """Abstract base for a single LLM backend fiber."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def generate(self, prompt: str, num_predict: int = 512, **kwargs) -> str: ...


# ---------------------------------------------------------------------------
# Ollama backend
# ---------------------------------------------------------------------------

class OllamaLLMBackend(LLMBackend):
    """Pool-compatible wrapper around OllamaBackend."""

    def __init__(self, url: str = "http://localhost:11434",
                 model: str | None = None,
                 temperature: float = 0.1,
                 generation_timeout_s: int = 900):
        from skg.resonance.ollama_backend import OllamaBackend
        self._inner = OllamaBackend(url=url, model=model, temperature=temperature)
        self._inner.generation_timeout_s = generation_timeout_s
        self._url = url
        self._model_tag = model or ""

    @property
    def name(self) -> str:
        model = self._inner._model or self._model_tag or "auto"
        return f"ollama:{model}"

    def available(self) -> bool:
        return self._inner.available()

    def generate(self, prompt: str, num_predict: int = 512, **kwargs) -> str:
        return self._inner.generate(prompt, num_predict=num_predict)

    def draft_catalog(self, domain_name: str, description: str,
                      context: dict) -> tuple[dict, list[str]]:
        return self._inner.draft_catalog(domain_name, description, context)

    def model(self) -> str | None:
        return self._inner.model()


# ---------------------------------------------------------------------------
# Anthropic backend
# ---------------------------------------------------------------------------

class AnthropicLLMBackend(LLMBackend):
    """Anthropic API backend fiber."""

    def __init__(self, model: str = "claude-haiku-4-5-20251001",
                 api_key: str | None = None,
                 max_tokens: int = 1024):
        self._model = model
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return f"anthropic:{self._model}"

    def available(self) -> bool:
        return bool(self._api_key)

    def generate(self, prompt: str, num_predict: int = 512, **kwargs) -> str:
        import json
        import urllib.request

        system = kwargs.get("system", "")
        messages = [{"role": "user", "content": prompt}]
        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": min(num_predict, self._max_tokens),
            "messages": messages,
        }
        if system:
            payload["system"] = system

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())

        blocks = data.get("content", [])
        return "".join(
            b.get("text", "") for b in blocks if b.get("type") == "text"
        ).strip()


# ---------------------------------------------------------------------------
# HuggingFace Inference API backend
# ---------------------------------------------------------------------------

class HuggingFaceAPIBackend(LLMBackend):
    """
    HuggingFace Inference API backend fiber.

    Uses the HF serverless inference endpoint for text generation.
    Requires HF_API_KEY (or HUGGINGFACE_API_KEY) environment variable,
    or a token set via huggingface-cli login.

    Good open models for structured output on free tier:
      mistralai/Mistral-7B-Instruct-v0.3
      microsoft/Phi-3-mini-4k-instruct
      HuggingFaceH4/zephyr-7b-beta
      tiiuae/falcon-7b-instruct  (smaller, faster)

    Config (skg_config.yaml):
      - type: huggingface
        model: "mistralai/Mistral-7B-Instruct-v0.3"
        max_new_tokens: 512
        temperature: 0.1
    """

    HF_API_BASE = "https://api-inference.huggingface.co/models"

    def __init__(self, model: str = "mistralai/Mistral-7B-Instruct-v0.3",
                 api_key: str | None = None,
                 max_new_tokens: int = 512,
                 temperature: float = 0.1,
                 timeout_s: int = 120):
        self._model = model
        self._api_key = (
            api_key
            or os.getenv("HF_API_KEY", "")
            or os.getenv("HUGGINGFACE_API_KEY", "")
        )
        self._max_new_tokens = max_new_tokens
        self._temperature = temperature
        self._timeout_s = timeout_s

    @property
    def name(self) -> str:
        return f"huggingface:{self._model}"

    def available(self) -> bool:
        return bool(self._api_key)

    def generate(self, prompt: str, num_predict: int = 512, **kwargs) -> str:
        import json
        import urllib.request
        import urllib.error

        payload = json.dumps({
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": min(num_predict, self._max_new_tokens),
                "temperature": self._temperature,
                "return_full_text": False,
                "do_sample": self._temperature > 0.0,
            },
        }).encode("utf-8")

        url = f"{self.HF_API_BASE}/{self._model}"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HuggingFace API error {exc.code}: {body[:300]}") from exc

        # HF inference returns [{generated_text: "..."}, ...] for text-gen
        if isinstance(data, list) and data:
            return str(data[0].get("generated_text", "")).strip()
        if isinstance(data, dict):
            # Some models return {"generated_text": "..."} directly
            return str(data.get("generated_text", "")).strip()
        raise RuntimeError(f"Unexpected HuggingFace response shape: {str(data)[:200]}")


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------

class LLMPool:
    """
    Pool of LLM backends with fiber-style concurrent dispatch.

    Strategies:
      race        — submit to all available backends simultaneously,
                    return the first non-empty response. Remaining
                    fibers are cancelled (best-effort).
      round_robin — rotate across backends; one fiber per request.
      ensemble    — submit to all, return the longest valid response
                    (use generate_all() for custom merging).
    """

    STRATEGIES = ("race", "round_robin", "ensemble")

    def __init__(self, backends: list[LLMBackend],
                 strategy: str = "race",
                 max_workers: int = 4):
        self._backends = backends
        self._strategy = strategy if strategy in self.STRATEGIES else "race"
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="skg-llm",
        )
        self._rr_index = 0
        self._rr_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls) -> "LLMPool":
        """
        Build an LLMPool from skg_config.yaml resonance.llm_pool section.
        Falls back to single-backend pool using resonance.ollama config.
        """
        cfg = _load_pool_config()

        if not cfg.get("enabled", False):
            return cls._single_backend_pool()

        strategy = str(cfg.get("strategy", "race"))
        max_workers = int(cfg.get("max_workers", 4))
        backends: list[LLMBackend] = []

        for b in cfg.get("backends", []):
            btype = str(b.get("type", "ollama")).lower()
            if btype == "ollama":
                backends.append(OllamaLLMBackend(
                    url=str(b.get("url", "http://localhost:11434")),
                    model=b.get("model") or None,
                    temperature=float(b.get("temperature", 0.1)),
                    generation_timeout_s=int(b.get("generation_timeout_s", 900)),
                ))
            elif btype == "anthropic":
                backends.append(AnthropicLLMBackend(
                    model=str(b.get("model", "claude-haiku-4-5-20251001")),
                    api_key=b.get("api_key") or os.getenv("ANTHROPIC_API_KEY", ""),
                    max_tokens=int(b.get("max_tokens", 1024)),
                ))
            elif btype in ("huggingface", "hf"):
                backends.append(HuggingFaceAPIBackend(
                    model=str(b.get("model", "mistralai/Mistral-7B-Instruct-v0.3")),
                    api_key=b.get("api_key") or os.getenv("HF_API_KEY", "") or os.getenv("HUGGINGFACE_API_KEY", ""),
                    max_new_tokens=int(b.get("max_new_tokens", 512)),
                    temperature=float(b.get("temperature", 0.1)),
                    timeout_s=int(b.get("timeout_s", 120)),
                ))
            else:
                log.warning(f"[llm_pool] unknown backend type '{btype}', skipping")

        if not backends:
            log.warning("[llm_pool] no backends configured, falling back to single-backend pool")
            return cls._single_backend_pool()

        log.info(
            f"[llm_pool] initialized: strategy={strategy} "
            f"backends={[b.name for b in backends]} workers={max_workers}"
        )
        return cls(backends, strategy=strategy, max_workers=max_workers)

    @classmethod
    def _single_backend_pool(cls) -> "LLMPool":
        """Single-backend pool using the existing resonance.ollama config."""
        from skg.resonance.ollama_backend import OllamaBackend
        ollama_cfg = OllamaBackend.load_config()
        backend = OllamaLLMBackend(
            url=str(ollama_cfg.get("url", "http://localhost:11434")),
            model=ollama_cfg.get("model") or None,
            temperature=float(ollama_cfg.get("temperature", 0.1)),
            generation_timeout_s=int(ollama_cfg.get("generation_timeout_s", 900)),
        )
        return cls([backend], strategy="race", max_workers=1)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def available_backends(self) -> list[LLMBackend]:
        return [b for b in self._backends if b.available()]

    def any_available(self) -> bool:
        return any(b.available() for b in self._backends)

    def primary_model_name(self) -> str | None:
        """Return the name of the first available backend (for display)."""
        for b in self._backends:
            if b.available():
                if isinstance(b, OllamaLLMBackend):
                    return b.model()
                return b.name
        return None

    # ------------------------------------------------------------------
    # Synchronous generation
    # ------------------------------------------------------------------

    def generate(self, prompt: str, num_predict: int = 512, **kwargs) -> str:
        """
        Dispatch generation according to the configured strategy.
        Blocks until a result is available.
        Raises RuntimeError if no backends respond.
        """
        backends = self.available_backends()
        if not backends:
            raise RuntimeError("No LLM backends available in pool")

        if self._strategy == "round_robin":
            return self._generate_round_robin(backends, prompt, num_predict, **kwargs)
        elif self._strategy == "ensemble":
            return self._generate_ensemble(backends, prompt, num_predict, **kwargs)
        else:
            return self._generate_race(backends, prompt, num_predict, **kwargs)

    def generate_all(self, prompt: str, num_predict: int = 512,
                     **kwargs) -> dict[str, str]:
        """
        Submit to all available backends concurrently.
        Returns {backend_name: response_text} for every backend that succeeded.
        Useful for ensemble merging at the caller level.
        """
        backends = self.available_backends()
        if not backends:
            return {}
        return self._collect_all(backends, prompt, num_predict, **kwargs)

    # ------------------------------------------------------------------
    # Async (fire-and-forget fiber)
    # ------------------------------------------------------------------

    def generate_async(self, prompt: str, num_predict: int = 512,
                       callback=None, **kwargs) -> concurrent.futures.Future:
        """
        Submit generation as a background fiber.
        Returns a Future; result available via future.result().
        Optional callback(result_str) called when done.
        """
        def _run():
            result = self.generate(prompt, num_predict=num_predict, **kwargs)
            if callback is not None:
                try:
                    callback(result)
                except Exception:
                    pass
            return result

        return self._executor.submit(_run)

    # ------------------------------------------------------------------
    # Strategy implementations
    # ------------------------------------------------------------------

    def _generate_race(self, backends: list[LLMBackend], prompt: str,
                       num_predict: int, **kwargs) -> str:
        """First valid response wins; remaining fibers cancelled."""
        futures: dict[concurrent.futures.Future, LLMBackend] = {
            self._executor.submit(b.generate, prompt, num_predict, **kwargs): b
            for b in backends
        }
        errors: list[str] = []

        for fut in concurrent.futures.as_completed(futures):
            backend = futures[fut]
            try:
                result = fut.result()
                if result and result.strip():
                    for f in futures:
                        if f is not fut:
                            f.cancel()
                    log.debug(f"[llm_pool:race] winner: {backend.name}")
                    return result
            except Exception as exc:
                log.debug(f"[llm_pool:race] {backend.name} failed: {exc}")
                errors.append(f"{backend.name}: {exc}")

        raise RuntimeError(f"All LLM backends failed (race): {'; '.join(errors)}")

    def _generate_round_robin(self, backends: list[LLMBackend], prompt: str,
                               num_predict: int, **kwargs) -> str:
        """Send to next backend in rotation."""
        with self._rr_lock:
            idx = self._rr_index % len(backends)
            self._rr_index += 1
        backend = backends[idx]
        log.debug(f"[llm_pool:rr] → {backend.name}")
        return backend.generate(prompt, num_predict, **kwargs)

    def _generate_ensemble(self, backends: list[LLMBackend], prompt: str,
                            num_predict: int, **kwargs) -> str:
        """Submit to all; return longest valid response."""
        results = self._collect_all(backends, prompt, num_predict, **kwargs)
        if not results:
            raise RuntimeError("All LLM backends failed (ensemble)")
        winner = max(results.values(), key=len)
        log.debug(f"[llm_pool:ensemble] {len(results)}/{len(backends)} succeeded")
        return winner

    def _collect_all(self, backends: list[LLMBackend], prompt: str,
                     num_predict: int, **kwargs) -> dict[str, str]:
        futures: dict[concurrent.futures.Future, LLMBackend] = {
            self._executor.submit(b.generate, prompt, num_predict, **kwargs): b
            for b in backends
        }
        results: dict[str, str] = {}
        for fut in concurrent.futures.as_completed(futures):
            backend = futures[fut]
            try:
                result = fut.result()
                if result and result.strip():
                    results[backend.name] = result
            except Exception as exc:
                log.debug(f"[llm_pool] {backend.name} failed: {exc}")
        return results

    # ------------------------------------------------------------------
    # Status / lifecycle
    # ------------------------------------------------------------------

    def status(self) -> dict:
        return {
            "strategy": self._strategy,
            "backends": [
                {"name": b.name, "available": b.available()}
                for b in self._backends
            ],
        }

    def shutdown(self, wait: bool = False):
        self._executor.shutdown(wait=wait)


# ---------------------------------------------------------------------------
# Singleton pool (module-level, lazy-initialized)
# ---------------------------------------------------------------------------

_POOL: LLMPool | None = None
_POOL_LOCK = threading.Lock()


def get_pool() -> LLMPool:
    """Return the module-level LLMPool singleton, creating it if needed."""
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                _POOL = LLMPool.from_config()
    return _POOL


def reset_pool():
    """Shutdown and recreate the singleton pool (e.g. after config change)."""
    global _POOL
    with _POOL_LOCK:
        if _POOL is not None:
            _POOL.shutdown(wait=False)
        _POOL = LLMPool.from_config()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_pool_config() -> dict:
    try:
        import yaml
        from skg.core.paths import SKG_CONFIG_DIR, SKG_HOME
        candidates = [
            SKG_CONFIG_DIR / "skg_config.yaml",
            SKG_HOME / "config" / "skg_config.yaml",
        ]
        for p in candidates:
            if not p.exists():
                continue
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            pool_cfg = (data.get("resonance", {}) or {}).get("llm_pool", {}) or {}
            if isinstance(pool_cfg, dict):
                return pool_cfg
        return {}
    except Exception:
        return {}
