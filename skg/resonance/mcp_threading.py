"""
skg.resonance.mcp_threading
===========================
Layered MCP-style threading over SKG as source-of-truth.

Thread layers:
  1) memory thread      -> resonance surface (wickets/adapters/domains/corpus)
  2) instrument thread  -> adapter evidence coverage for query
  3) capability thread  -> local runtime command/man capabilities
  4) reasoner thread    -> layered assistant generation grounded on SKG memory
  5) verification thread-> checks grounding against discovered instruments

The key contract is that SKG resonance remains the authority for memory
and instrument evidence. This module does not replace that store.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
import time
from dataclasses import dataclass
from typing import Any


log = logging.getLogger("skg.resonance.mcp")


@dataclass(frozen=True)
class MCPThreadingConfig:
    enabled: bool = True
    k_each: int = 3
    adapter_k: int = 8
    max_workers: int = 4
    capability_scan: bool = True
    max_help_cmds: int = 6
    max_man_cmds: int = 4
    max_context_lines: int = 12
    selector_top_n: int = 3
    selector_min_score: float = 0.05
    advisory_only: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MCPThreadingConfig":
        if not isinstance(data, dict):
            return cls()

        def _truthy(value: object) -> bool:
            if isinstance(value, bool):
                return value
            if value is None:
                return False
            return str(value).strip().lower() in {"1", "true", "yes", "on"}

        def _int(name: str, default: int, low: int, high: int) -> int:
            raw = data.get(name, default)
            try:
                value = int(raw)
            except (TypeError, ValueError):
                return default
            return max(low, min(high, value))

        def _float(name: str, default: float, low: float, high: float) -> float:
            raw = data.get(name, default)
            try:
                value = float(raw)
            except (TypeError, ValueError):
                return default
            return max(low, min(high, value))

        return cls(
            enabled=_truthy(data.get("enabled", cls.enabled)),
            k_each=_int("k_each", cls.k_each, 1, 24),
            adapter_k=_int("adapter_k", cls.adapter_k, 1, 48),
            max_workers=_int("max_workers", cls.max_workers, 1, 32),
            capability_scan=_truthy(data.get("capability_scan", cls.capability_scan)),
            max_help_cmds=_int("max_help_cmds", cls.max_help_cmds, 0, 32),
            max_man_cmds=_int("max_man_cmds", cls.max_man_cmds, 0, 32),
            max_context_lines=_int("max_context_lines", cls.max_context_lines, 3, 50),
            selector_top_n=_int("selector_top_n", cls.selector_top_n, 1, 16),
            selector_min_score=_float("selector_min_score", cls.selector_min_score, -5.0, 5.0),
            advisory_only=_truthy(data.get("advisory_only", cls.advisory_only)),
        )


class MCPThreadingOrchestrator:
    """
    Layered threaded orchestrator using SKG resonance as source-of-truth.
    """

    def __init__(self, engine, assistant=None, config: MCPThreadingConfig | None = None):
        from skg.resonance.orchestrator import LayeredAssistant

        self._engine = engine
        self._assistant = assistant or LayeredAssistant.from_config(engine)
        self._config = config or MCPThreadingConfig()

    @classmethod
    def from_config(cls, engine, assistant=None) -> "MCPThreadingOrchestrator":
        cfg = _load_mcp_threading_config()
        return cls(engine=engine, assistant=assistant, config=MCPThreadingConfig.from_dict(cfg))

    def status(self) -> dict[str, Any]:
        assistant_status = {}
        try:
            if hasattr(self._assistant, "status"):
                assistant_status = self._assistant.status()
        except Exception:
            assistant_status = {}
        return {
            "enabled": bool(self._config.enabled),
            "config": {
                "k_each": self._config.k_each,
                "adapter_k": self._config.adapter_k,
                "max_workers": self._config.max_workers,
                "capability_scan": self._config.capability_scan,
                "max_help_cmds": self._config.max_help_cmds,
                "max_man_cmds": self._config.max_man_cmds,
                "max_context_lines": self._config.max_context_lines,
                "selector_top_n": self._config.selector_top_n,
                "selector_min_score": self._config.selector_min_score,
                "advisory_only": self._config.advisory_only,
            },
            "assistant": assistant_status,
            "source_of_truth": "skg.resonance",
        }

    def thread(
        self,
        query: str,
        *,
        theta: str | None = None,
        prefer: str | None = None,
        k_each: int | None = None,
        max_workers: int | None = None,
    ) -> dict[str, Any]:
        if not self._config.enabled:
            raise RuntimeError("MCP threading is disabled in config")

        text = (query or "").strip()
        if not text:
            raise ValueError("query text is empty")

        theta_text = (theta or "").strip()
        resolved_k_each = max(1, int(k_each if k_each is not None else self._config.k_each))
        workers = max(1, min(int(max_workers or self._config.max_workers), 32))

        start = time.perf_counter()
        threads: dict[str, Any] = {}

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="mcp-layer",
        ) as pool:
            futures: dict[str, concurrent.futures.Future] = {
                "memory": pool.submit(self._memory_thread, text, resolved_k_each),
                "instruments": pool.submit(self._instrument_thread, text),
            }
            if self._config.capability_scan:
                futures["capabilities"] = pool.submit(self._capability_thread, text, theta_text)

            for name, future in futures.items():
                try:
                    threads[name] = future.result()
                except Exception as exc:
                    log.warning("[mcp] %s thread failed: %s", name, exc)
                    threads[name] = {"error": str(exc)}

        decision = self._instrument_decision_thread(text, theta_text, threads)
        threads["instrument_decision"] = decision

        reasoner_start = time.perf_counter()
        reasoner = self._reasoner_thread(
            text,
            theta=theta_text,
            prefer=prefer,
            k_each=resolved_k_each,
            decision=decision,
        )
        reasoner["thread_latency_s"] = round(time.perf_counter() - reasoner_start, 4)
        threads["reasoner"] = reasoner
        threads["verification"] = self._verification_thread(reasoner, threads)

        return {
            "query": text,
            "theta": theta_text,
            "prefer": (prefer or "").strip(),
            "source_of_truth": "skg.resonance",
            "execution": {
                "mode": "layered_mcp_threading",
                "k_each": resolved_k_each,
                "max_workers": workers,
                "elapsed_s": round(time.perf_counter() - start, 4),
            },
            "threads": threads,
        }

    def _memory_thread(self, query: str, k_each: int) -> dict[str, Any]:
        surfaced = self._engine.surface(query, k_each=k_each)
        counts = {
            "wickets": len(surfaced.get("wickets", [])),
            "adapters": len(surfaced.get("adapters", [])),
            "domains": len(surfaced.get("domains", [])),
            "corpus": len(surfaced.get("corpus", [])),
        }
        return {
            "counts": counts,
            "wickets": [_wicket_line(item) for item in surfaced.get("wickets", [])[: self._config.max_context_lines]],
            "adapters": [_adapter_line(item) for item in surfaced.get("adapters", [])[: self._config.max_context_lines]],
            "domains": [_domain_line(item) for item in surfaced.get("domains", [])[: self._config.max_context_lines]],
            "corpus": [_corpus_line(item) for item in surfaced.get("corpus", [])[: self._config.max_context_lines]],
        }

    def _instrument_thread(self, query: str) -> dict[str, Any]:
        rows = self._engine.query_adapters(query, k=self._config.adapter_k)
        instruments: list[dict[str, Any]] = []
        for rec, score in rows:
            instruments.append(
                {
                    "adapter": str(rec.adapter_name),
                    "domain": str(rec.domain),
                    "score": round(float(score), 6),
                    "wickets_covered": list(rec.wickets_covered[:12]),
                    "evidence_sources": list(rec.evidence_sources[:4]),
                }
            )
        return {
            "count": len(instruments),
            "instruments": instruments,
        }

    def _capability_thread(self, query: str, theta: str) -> dict[str, Any]:
        from skg.resonance.local_corpus import (
            discover_local_capabilities,
            plan_smart_local_index,
        )

        caps = discover_local_capabilities()
        plan = plan_smart_local_index(
            query=query,
            theta=theta,
            max_help_cmds=self._config.max_help_cmds,
            max_man_cmds=self._config.max_man_cmds,
        )
        return {
            "help_available": len(list(caps.get("available_help_commands", []) or [])),
            "man_available": len(list(caps.get("available_man_commands", []) or [])),
            "planned_help": list(plan.get("help_cmds", []) or []),
            "planned_man": list(plan.get("man_cmds", []) or []),
            "code_root": str((caps.get("code_root") or "")),
            "code_root_exists": bool(caps.get("code_root_exists")),
        }

    def _instrument_decision_thread(
        self,
        query: str,
        theta: str,
        threads: dict[str, Any],
    ) -> dict[str, Any]:
        instrument_rows = (
            threads.get("instruments", {}).get("instruments", [])
            if isinstance(threads.get("instruments"), dict)
            else []
        )
        if not instrument_rows:
            return {
                "policy": "skg_authoritative",
                "selected_adapters": [],
                "selected": [],
                "reason": "no_instruments",
            }

        memory_wickets = set(_memory_wicket_ids(threads.get("memory", {})))
        query_tokens = _query_tokens(f"{query} {theta}")

        scored: list[dict[str, Any]] = []
        for row in instrument_rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("adapter", "")).strip()
            if not name:
                continue
            domain = str(row.get("domain", "")).strip()
            coverage = [str(x) for x in (row.get("wickets_covered") or [])]
            evidence = [str(x) for x in (row.get("evidence_sources") or [])]

            try:
                base_score = float(row.get("score", 0.0))
            except (TypeError, ValueError):
                base_score = 0.0

            bonus = 0.0
            reasons: list[str] = [f"base={base_score:.3f}"]

            name_tokens = _query_tokens(name.replace("-", "_"))
            if name_tokens & query_tokens:
                bonus += 0.35
                reasons.append("name_match")
            if domain and domain.lower() in query_tokens:
                bonus += 0.12
                reasons.append("domain_match")
            if coverage and memory_wickets:
                overlap = len(set(coverage) & memory_wickets)
                if overlap > 0:
                    boost = min(0.24, 0.08 * overlap)
                    bonus += boost
                    reasons.append(f"wicket_overlap={overlap}")
            if evidence and query_tokens:
                evidence_blob = " ".join(evidence).lower()
                evidence_hits = sum(1 for tok in query_tokens if tok in evidence_blob and len(tok) >= 3)
                if evidence_hits > 0:
                    boost = min(0.2, 0.04 * evidence_hits)
                    bonus += boost
                    reasons.append(f"evidence_hits={evidence_hits}")

            final_score = base_score + bonus
            scored.append(
                {
                    "adapter": name,
                    "domain": domain,
                    "base_score": round(base_score, 6),
                    "bonus": round(bonus, 6),
                    "final_score": round(final_score, 6),
                    "wickets_covered": coverage[:12],
                    "evidence_sources": evidence[:4],
                    "reasons": reasons,
                }
            )

        scored.sort(key=lambda row: float(row.get("final_score", 0.0)), reverse=True)
        selected = [
            row
            for row in scored
            if float(row.get("final_score", 0.0)) >= float(self._config.selector_min_score)
        ][: self._config.selector_top_n]
        if not selected:
            selected = scored[: self._config.selector_top_n]

        return {
            "policy": "skg_authoritative",
            "query_tokens": sorted(query_tokens),
            "memory_wickets": sorted(memory_wickets),
            "selector_top_n": self._config.selector_top_n,
            "selector_min_score": self._config.selector_min_score,
            "selected_adapters": [str(row.get("adapter", "")) for row in selected],
            "selected": selected,
            "candidates_scored": scored[: max(self._config.selector_top_n * 3, 6)],
            "reason": "ok",
        }

    def _reasoner_thread(
        self,
        query: str,
        *,
        theta: str,
        prefer: str | None,
        k_each: int,
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        selected = list(decision.get("selected_adapters", []) or [])
        if self._config.advisory_only:
            selected_line = ", ".join(selected) if selected else "(none)"
            advisory_query = (
                f"{query}\n\n"
                "SKG authoritative instrument decision:\n"
                f"- selected_instruments: {selected_line}\n"
                "- policy: do not override selected instruments.\n"
                "- your role: advisory only.\n"
                "Return concise guidance with:\n"
                "1) how to use selected instruments better,\n"
                "2) what additional evidence to collect,\n"
                "3) optional secondary instrument suggestions (clearly marked as suggestions).\n"
            )
        else:
            advisory_query = query

        reasoner = self._assistant.ask(
            advisory_query,
            prefer=prefer,
            k_each=k_each,
            theta=theta,
        )
        reasoner["advisory_only"] = bool(self._config.advisory_only)
        reasoner["selected_instruments"] = selected
        return reasoner

    def _verification_thread(self, reasoner: dict[str, Any], threads: dict[str, Any]) -> dict[str, Any]:
        response = str(reasoner.get("response", "")).lower()
        instrument_rows = (
            threads.get("instruments", {}).get("instruments", [])
            if isinstance(threads.get("instruments"), dict)
            else []
        )
        selected_rows = (
            threads.get("instrument_decision", {}).get("selected_adapters", [])
            if isinstance(threads.get("instrument_decision"), dict)
            else []
        )
        selected = {str(name).strip().lower() for name in selected_rows if str(name).strip()}
        known = {
            str(row.get("adapter", "")).strip().lower()
            for row in instrument_rows
            if isinstance(row, dict)
        }
        known.discard("")
        mentioned = [name for name in sorted(known) if name and name in response]
        mentioned_selected = [name for name in sorted(selected) if name and name in response]
        mentioned_non_selected = [name for name in mentioned if name not in selected]
        return {
            "instrument_pool": len(known),
            "mentions_known_instrument": bool(mentioned),
            "mentioned_instruments": mentioned[:20],
            "selected_instrument_pool": len(selected),
            "mentions_selected_instrument": bool(mentioned_selected),
            "mentioned_selected_instruments": mentioned_selected[:20],
            "mentioned_non_selected_instruments": mentioned_non_selected[:20],
            "context_counts": dict(reasoner.get("context_counts", {}) or {}),
        }


def _wicket_line(item: dict[str, Any]) -> str:
    rec = item.get("record", {}) if isinstance(item, dict) else {}
    wid = str(rec.get("wicket_id") or rec.get("record_id") or "?")
    label = str(rec.get("label") or "")
    return f"{wid}: {label}".strip()


def _adapter_line(item: dict[str, Any]) -> str:
    rec = item.get("record", {}) if isinstance(item, dict) else {}
    name = str(rec.get("adapter_name") or rec.get("record_id") or "?")
    return name


def _domain_line(item: dict[str, Any]) -> str:
    rec = item.get("record", {}) if isinstance(item, dict) else {}
    domain = str(rec.get("domain") or rec.get("record_id") or "?")
    return domain


def _corpus_line(item: dict[str, Any]) -> str:
    rec = item.get("record", {}) if isinstance(item, dict) else {}
    kind = str(rec.get("source_kind") or "corpus")
    ref = str(rec.get("source_ref") or "")
    return f"{kind}:{ref}".strip(":")


def _query_tokens(text: str | None) -> set[str]:
    if not text:
        return set()
    return {
        tok.lower()
        for tok in re.findall(r"[a-zA-Z0-9_+.-]+", str(text))
        if len(tok) >= 2
    }


def _memory_wicket_ids(memory_thread: Any) -> list[str]:
    if not isinstance(memory_thread, dict):
        return []
    out: list[str] = []
    for line in list(memory_thread.get("wickets", []) or []):
        text = str(line).strip()
        if not text:
            continue
        wid = text.split(":", 1)[0].strip()
        if wid:
            out.append(wid)
    return out


def _load_mcp_threading_config() -> dict[str, Any]:
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
        mcp = resonance.get("mcp_threading", {}) or {}
        if isinstance(mcp, dict):
            return mcp
    return {}
