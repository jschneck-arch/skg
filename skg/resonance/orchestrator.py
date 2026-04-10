"""
skg.resonance.orchestrator
==========================
Layered local assistant orchestration on top of resonance memory and Ollama.

Pipeline:
  1) Route request to fast/code/deep tier.
  2) Retrieve resonance memory context (RAG).
  3) Build a bounded prompt with context.
  4) Generate from selected model, with fallback to fast tier.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Literal


log = logging.getLogger("skg.resonance.orchestrator")

Tier = Literal["fast", "code", "deep"]


@dataclass(frozen=True)
class RoutingDecision:
    tier: Tier
    reason: str


@dataclass(frozen=True)
class OrchestratorConfig:
    fast_model: str = "hermes3:3b"
    code_model: str = "qwen2.5-coder:1.5b"
    deep_model: str = "gemma4:e2b-it-q4_K_M"
    fast_fallback_models: tuple[str, ...] = ()
    code_fallback_models: tuple[str, ...] = ()
    deep_fallback_models: tuple[str, ...] = ()
    fast_num_predict: int = 192
    code_num_predict: int = 256
    deep_num_predict: int = 512
    rag_k_each: int = 3
    max_context_lines: int = 12
    deep_char_threshold: int = 320
    deep_token_threshold: int = 60

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OrchestratorConfig":
        if not isinstance(data, dict):
            return cls()

        def _str(name: str, default: str) -> str:
            val = data.get(name, default)
            if val is None:
                return default
            return str(val).strip() or default

        def _int(name: str, default: int, low: int, high: int) -> int:
            raw = data.get(name, default)
            try:
                value = int(raw)
            except (TypeError, ValueError):
                return default
            if value < low:
                return low
            if value > high:
                return high
            return value

        def _model_list(name: str) -> tuple[str, ...]:
            raw = data.get(name, ())
            if raw is None:
                return ()
            if isinstance(raw, str):
                values = [x.strip() for x in raw.split(",") if x and x.strip()]
            elif isinstance(raw, list):
                values = [str(x).strip() for x in raw if str(x).strip()]
            else:
                return ()
            seen: set[str] = set()
            out: list[str] = []
            for model in values:
                if not model or model in seen:
                    continue
                seen.add(model)
                out.append(model)
            return tuple(out)

        return cls(
            fast_model=_str("fast_model", cls.fast_model),
            code_model=_str("code_model", cls.code_model),
            deep_model=_str("deep_model", cls.deep_model),
            fast_fallback_models=_model_list("fast_fallback_models"),
            code_fallback_models=_model_list("code_fallback_models"),
            deep_fallback_models=_model_list("deep_fallback_models"),
            fast_num_predict=_int("fast_num_predict", cls.fast_num_predict, 32, 4096),
            code_num_predict=_int("code_num_predict", cls.code_num_predict, 32, 4096),
            deep_num_predict=_int("deep_num_predict", cls.deep_num_predict, 32, 4096),
            rag_k_each=_int("rag_k_each", cls.rag_k_each, 1, 12),
            max_context_lines=_int("max_context_lines", cls.max_context_lines, 3, 30),
            deep_char_threshold=_int("deep_char_threshold", cls.deep_char_threshold, 80, 2000),
            deep_token_threshold=_int("deep_token_threshold", cls.deep_token_threshold, 20, 400),
        )


class PromptRouter:
    """Heuristic prompt router for local tiered models."""

    _CODE_RE = re.compile(
        r"\b("
        r"code|python|javascript|typescript|java|c\+\+|go|rust|sql|regex|bash|shell|script|"
        r"function|class|compile|debug|stack\s*trace|traceback|unit\s*test|refactor|api"
        r")\b",
        re.IGNORECASE,
    )
    _DEEP_RE = re.compile(
        r"\b("
        r"architecture|tradeoff|design|protocol|thread|layer|orchestrate|orchestration|"
        r"compare|evaluate|benchmark|review|analyze|strategy|multi[- ]model|rag|vllm|quantum"
        r")\b",
        re.IGNORECASE,
    )

    def __init__(self, deep_char_threshold: int = 320, deep_token_threshold: int = 60):
        self._deep_char_threshold = deep_char_threshold
        self._deep_token_threshold = deep_token_threshold

    def decide(self, query: str, prefer: Tier | None = None) -> RoutingDecision:
        if prefer in ("fast", "code", "deep"):
            return RoutingDecision(prefer, "explicit_preference")

        text = (query or "").strip()
        if not text:
            return RoutingDecision("fast", "empty_query_default")

        if self._CODE_RE.search(text):
            return RoutingDecision("code", "code_signal")

        token_count = len(re.findall(r"[a-zA-Z0-9_]+", text))
        if (
            len(text) >= self._deep_char_threshold
            or token_count >= self._deep_token_threshold
            or self._DEEP_RE.search(text)
        ):
            return RoutingDecision("deep", "analysis_or_length_signal")

        return RoutingDecision("fast", "default_fast_path")


class LayeredAssistant:
    """
    Local assistant with:
      - prompt routing (fast/code/deep)
      - resonance memory retrieval
      - model fallback chain
    """

    def __init__(self, engine, backend=None, config: OrchestratorConfig | None = None):
        from skg.resonance.ollama_backend import OllamaBackend

        self._engine = engine
        self._backend = backend or OllamaBackend()
        self._config = config or OrchestratorConfig()
        self._router = PromptRouter(
            deep_char_threshold=self._config.deep_char_threshold,
            deep_token_threshold=self._config.deep_token_threshold,
        )

    @classmethod
    def from_config(cls, engine, backend=None) -> "LayeredAssistant":
        cfg = _load_orchestrator_config()
        return cls(engine=engine, backend=backend, config=OrchestratorConfig.from_dict(cfg))

    def ask(
        self,
        query: str,
        prefer: Tier | None = None,
        k_each: int | None = None,
        theta: str | None = None,
    ) -> dict[str, Any]:
        text = (query or "").strip()
        if not text:
            raise ValueError("query text is empty")
        if not self._backend.available():
            raise RuntimeError("Ollama backend is unavailable")

        decision = self._router.decide(text, prefer=prefer)
        retrieval_k = max(1, int(k_each if k_each is not None else self._config.rag_k_each))
        surfaced = self._engine.surface(text, k_each=retrieval_k)
        context_lines = self._build_context_lines(surfaced, query=text, theta=theta)
        prompt = self._build_prompt(text, decision, context_lines)
        available_models = self._available_models()

        start = time.perf_counter()
        attempts: list[str] = []
        response = ""
        used_model = ""
        used_tokens = 0

        for model, num_predict in self._candidate_plan(decision.tier, available_models=available_models):
            attempts.append(model)
            try:
                raw = self._backend.generate(prompt, model=model, num_predict=num_predict)
            except Exception as exc:
                log.warning("[orchestrator] generation failed model=%s: %s", model, exc)
                continue

            raw = (raw or "").strip()
            if raw:
                response = raw
                used_model = model
                used_tokens = num_predict
                break

        elapsed = round(time.perf_counter() - start, 3)
        if not response:
            raise RuntimeError(
                "All candidate models failed or returned empty output: "
                + ", ".join(attempts)
            )

        counts = {
            "wickets": len(surfaced.get("wickets", [])),
            "adapters": len(surfaced.get("adapters", [])),
            "domains": len(surfaced.get("domains", [])),
            "corpus": len(surfaced.get("corpus", [])),
        }
        return {
            "query": text,
            "route": decision.tier,
            "route_reason": decision.reason,
            "model_used": used_model,
            "models_attempted": attempts,
            "num_predict": used_tokens,
            "fallback_used": bool(attempts and used_model and attempts[0] != used_model),
            "latency_s": elapsed,
            "context_counts": counts,
            "context_preview": context_lines,
            "theta": (theta or "").strip(),
            "response": response,
        }

    def status(self) -> dict[str, Any]:
        backend_status = self._backend.status() if hasattr(self._backend, "status") else {}
        return {
            "config": {
                "fast_model": self._config.fast_model,
                "code_model": self._config.code_model,
                "deep_model": self._config.deep_model,
                "fast_fallback_models": list(self._config.fast_fallback_models),
                "code_fallback_models": list(self._config.code_fallback_models),
                "deep_fallback_models": list(self._config.deep_fallback_models),
                "rag_k_each": self._config.rag_k_each,
            },
            "backend": backend_status,
        }

    def _available_models(self) -> set[str] | None:
        if not hasattr(self._backend, "list_models"):
            return None
        try:
            listed = self._backend.list_models()
        except Exception:
            return None
        if not isinstance(listed, list):
            return None
        return {str(m).strip() for m in listed if str(m).strip()}

    def _candidate_plan(
        self,
        tier: Tier,
        *,
        available_models: set[str] | None = None,
    ) -> list[tuple[str, int]]:
        fast_main = (self._config.fast_model, self._config.fast_num_predict)
        fast_fallback = [(m, self._config.fast_num_predict) for m in self._config.fast_fallback_models]
        code_main = (self._config.code_model, self._config.code_num_predict)
        code_fallback = [(m, self._config.code_num_predict) for m in self._config.code_fallback_models]
        deep_main = (self._config.deep_model, self._config.deep_num_predict)
        deep_fallback = [(m, self._config.deep_num_predict) for m in self._config.deep_fallback_models]

        if tier == "code":
            ordered = [code_main, *code_fallback, fast_main, *fast_fallback]
        elif tier == "deep":
            ordered = [deep_main, *deep_fallback, fast_main, *fast_fallback]
        else:
            ordered = [fast_main, *fast_fallback]

        seen: set[str] = set()
        plan: list[tuple[str, int]] = []
        has_available_filter = bool(available_models)
        for model, num_predict in ordered:
            model = model.strip()
            if not model or model in seen:
                continue
            if has_available_filter and model not in available_models:
                continue
            seen.add(model)
            plan.append((model, num_predict))
        return plan

    def _build_prompt(
        self,
        query: str,
        decision: RoutingDecision,
        context_lines: list[str],
    ) -> str:
        context_block = "\n".join(f"- {line}" for line in context_lines) or "- no relevant resonance memory"
        return f"""You are SKG's local assistant.
Use retrieved context when relevant. If evidence is weak, say so briefly.
Answer concretely and keep it concise.

Routing tier: {decision.tier}
Routing reason: {decision.reason}

Retrieved context:
{context_block}

User request:
{query}

Rules:
- For coding requests, provide runnable code first.
- Do not invent file paths, tools, or observations.
- If assumptions are required, state one short assumption line.

Answer:"""

    def _build_context_lines(
        self,
        surfaced: dict[str, Any],
        query: str | None = None,
        theta: str | None = None,
    ) -> list[str]:
        lines: list[str] = []

        for item in surfaced.get("wickets", []):
            rec = item.get("record", {}) if isinstance(item, dict) else {}
            score = _score(item)
            wicket_id = _truncate(str(rec.get("wicket_id") or rec.get("record_id") or "?"), 32)
            label = _truncate(str(rec.get("label") or ""), 70)
            desc = _truncate(str(rec.get("description") or ""), 110)
            lines.append(f"[wicket {score}] {wicket_id} {label}: {desc}")

        for item in surfaced.get("adapters", []):
            rec = item.get("record", {}) if isinstance(item, dict) else {}
            score = _score(item)
            name = _truncate(str(rec.get("adapter_name") or rec.get("record_id") or "?"), 40)
            src = rec.get("evidence_sources") or []
            if isinstance(src, list):
                src_text = "; ".join(str(s) for s in src[:2])
            else:
                src_text = str(src)
            src_text = _truncate(src_text, 110)
            lines.append(f"[adapter {score}] {name}: {src_text}")

        for item in surfaced.get("domains", []):
            rec = item.get("record", {}) if isinstance(item, dict) else {}
            score = _score(item)
            domain = _truncate(str(rec.get("domain") or rec.get("record_id") or "?"), 32)
            desc = _truncate(str(rec.get("description") or ""), 110)
            lines.append(f"[domain {score}] {domain}: {desc}")

        corpus_items = list(surfaced.get("corpus", []))
        if corpus_items:
            corpus_items.sort(
                key=lambda item: self._corpus_sort_key(item, query=query, theta=theta),
                reverse=True,
            )

        for item in corpus_items:
            rec = item.get("record", {}) if isinstance(item, dict) else {}
            score = _score(item)
            source_kind = _truncate(str(rec.get("source_kind") or "corpus"), 12)
            source_ref = _truncate(str(rec.get("source_ref") or ""), 48)
            title = _truncate(str(rec.get("title") or ""), 72)
            text = _truncate(str(rec.get("text") or ""), 110)
            lines.append(
                f"[{source_kind} {score}] {source_ref} {title}: {text}"
            )

        return lines[: self._config.max_context_lines]

    def _corpus_sort_key(
        self,
        item: dict[str, Any],
        query: str | None = None,
        theta: str | None = None,
    ) -> tuple[float, float]:
        rec = item.get("record", {}) if isinstance(item, dict) else {}
        source_kind = str(rec.get("source_kind") or "").strip().lower()
        source_ref = str(rec.get("source_ref") or "").strip().lower()
        title = str(rec.get("title") or "").strip().lower()
        theta_text = (theta or "").strip().lower()
        query_tokens = _tokenize_query(query)

        try:
            score = float(item.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0

        bias = 0.0
        text_blob = f"{source_kind} {source_ref} {title}"
        source_basename = source_ref.rsplit("/", 1)[-1]
        source_no_ext = source_basename.rsplit(".", 1)[0]

        if query_tokens:
            if source_kind in {"help", "man"}:
                if source_basename in query_tokens or source_no_ext in query_tokens:
                    bias += 0.55
                if "help" in query_tokens and source_kind == "help":
                    bias += 0.2
                if "man" in query_tokens and source_kind == "man":
                    bias += 0.2
            if source_kind == "code":
                if any(tok in source_ref for tok in query_tokens if len(tok) >= 3):
                    bias += 0.2
                if any(tok in title for tok in query_tokens if len(tok) >= 3):
                    bias += 0.15
                if any(
                    source_ref.endswith(f".{ext}")
                    for ext in ("py", "sh", "yaml", "yml", "json", "md")
                    if ext in query_tokens
                ):
                    bias += 0.2
            if source_kind == "pearl" and any(tok in {"history", "timeline", "pearl"} for tok in query_tokens):
                bias += 0.2

        if any(tok in theta_text for tok in ("code", "debug", "compile", "test", "refactor")):
            if source_kind == "code":
                bias += 0.6
            if source_kind in {"help", "man"}:
                bias += 0.2
            if any(tok in text_blob for tok in ("py", "code", "src", "test")):
                bias += 0.1
        elif any(tok in theta_text for tok in ("rag", "doc", "research", "reason", "analysis")):
            if source_kind in {"doc", "code", "pearl"}:
                bias += 0.35
            if source_kind in {"man", "help"}:
                bias += 0.15
        elif any(tok in theta_text for tok in ("runtime", "ops", "shell", "cli")):
            if source_kind in {"help", "man"}:
                bias += 0.45
            if source_kind == "pearl":
                bias += 0.2

        return (score + bias, score)


def _tokenize_query(text: str | None) -> set[str]:
    if not text:
        return set()
    return {
        tok.lower()
        for tok in re.findall(r"[a-zA-Z0-9_+.-]+", str(text))
        if len(tok) >= 2
    }


def _score(item: Any) -> str:
    if not isinstance(item, dict):
        return "0.000"
    try:
        return f"{float(item.get('score', 0.0)):.3f}"
    except (TypeError, ValueError):
        return "0.000"


def _truncate(text: str, max_len: int) -> str:
    txt = (text or "").strip()
    if len(txt) <= max_len:
        return txt
    if max_len < 4:
        return txt[:max_len]
    return txt[: max_len - 3] + "..."


def _load_orchestrator_config() -> dict[str, Any]:
    try:
        import yaml
        from skg_core.config.paths import SKG_CONFIG_DIR, SKG_HOME
    except Exception:
        return {}

    candidates = [
        SKG_CONFIG_DIR / "skg_config.yaml",
        SKG_HOME / "config" / "skg_config.yaml",
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        resonance = data.get("resonance", {}) or {}
        orchestrator = resonance.get("orchestrator", {}) or {}
        if isinstance(orchestrator, dict):
            return orchestrator
    return {}
