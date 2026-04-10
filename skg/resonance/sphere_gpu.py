"""
skg.resonance.sphere_gpu
========================
SphereGPU v0: local "virtual accelerator" scheduler for LLM inference.

This does not replace real GPU hardware. It provides a GPU-like interface
for local model orchestration:
  - spherical task coordinates (r, theta, phi)
  - shell-based concurrency lanes (inner/mid/outer)
  - tier routing onto local models (fast/code/deep)
  - small in-memory page cache (LRU)
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


log = logging.getLogger("skg.resonance.sphere_gpu")

Tier = str
Shell = str


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, float(value)))


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SpherePoint:
    """
    Spherical job coordinate.
      r     : radial compute depth preference [0..1]
      theta : task family angle (free-form label: code/rag/reason/verify/...)
      phi   : uncertainty / confidence requirement [0..1]
      stream: virtual stream id (future expansion)
    """
    r: float = 0.35
    theta: str = "general"
    phi: float = 0.5
    stream: int = 0

    @classmethod
    def from_values(
        cls,
        r: float | int | str = 0.35,
        theta: str = "general",
        phi: float | int | str = 0.5,
        stream: int | str = 0,
    ) -> "SpherePoint":
        try:
            r_val = float(r)
        except (TypeError, ValueError):
            r_val = 0.35
        try:
            phi_val = float(phi)
        except (TypeError, ValueError):
            phi_val = 0.5
        try:
            stream_val = int(stream)
        except (TypeError, ValueError):
            stream_val = 0
        return cls(
            r=_clamp(r_val, 0.0, 1.0),
            theta=(theta or "general").strip() or "general",
            phi=_clamp(phi_val, 0.0, 1.0),
            stream=max(0, stream_val),
        )


@dataclass(frozen=True)
class SphereGPUConfig:
    enabled: bool = True
    virtual_cores: int = 4
    shell_inner_max: int = 2
    shell_mid_max: int = 1
    shell_outer_max: int = 1
    cache_size: int = 96
    default_k_each: int = 3
    mid_r_threshold: float = 0.34
    outer_r_threshold: float = 0.67
    uncertainty_escalation_phi: float = 0.72
    persist_state: bool = True
    state_path: str = ""
    persist_response_chars: int = 8000
    enable_resource_guard: bool = True
    load_guard_warn_ratio: float = 1.2
    load_guard_hard_ratio: float = 1.8
    mem_guard_warn_ratio: float = 0.12
    mem_guard_hard_ratio: float = 0.08
    swap_guard_warn_ratio: float = 0.30
    swap_guard_hard_ratio: float = 0.55
    enable_auto_local_corpus: bool = False
    auto_local_index_interval_s: int = 1800
    auto_local_max_help_cmds: int = 10
    auto_local_max_man_cmds: int = 8
    auto_local_max_code_files: int = 160
    auto_local_chunk_chars: int = 900
    auto_local_max_pearl_records: int = 500
    auto_local_include_pearls: bool = True
    enable_micro_local_corpus: bool = True
    micro_local_ttl_s: int = 900
    micro_local_max_help_cmds: int = 2
    micro_local_max_man_cmds: int = 2
    micro_local_max_code_files: int = 3
    micro_local_chunk_chars: int = 700

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SphereGPUConfig":
        if not isinstance(data, dict):
            return cls()

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

        def _str(name: str, default: str) -> str:
            val = data.get(name, default)
            if val is None:
                return default
            return str(val).strip()

        return cls(
            enabled=_truthy(data.get("enabled", True)),
            virtual_cores=_int("virtual_cores", cls.virtual_cores, 1, 128),
            shell_inner_max=_int("shell_inner_max", cls.shell_inner_max, 1, 64),
            shell_mid_max=_int("shell_mid_max", cls.shell_mid_max, 1, 64),
            shell_outer_max=_int("shell_outer_max", cls.shell_outer_max, 1, 64),
            cache_size=_int("cache_size", cls.cache_size, 8, 5000),
            default_k_each=_int("default_k_each", cls.default_k_each, 1, 24),
            mid_r_threshold=_float("mid_r_threshold", cls.mid_r_threshold, 0.05, 0.95),
            outer_r_threshold=_float("outer_r_threshold", cls.outer_r_threshold, 0.05, 0.99),
            uncertainty_escalation_phi=_float(
                "uncertainty_escalation_phi",
                cls.uncertainty_escalation_phi,
                0.0,
                1.0,
            ),
            persist_state=_truthy(data.get("persist_state", cls.persist_state)),
            state_path=_str("state_path", cls.state_path),
            persist_response_chars=_int(
                "persist_response_chars",
                cls.persist_response_chars,
                500,
                120000,
            ),
            enable_resource_guard=_truthy(data.get("enable_resource_guard", cls.enable_resource_guard)),
            load_guard_warn_ratio=_float("load_guard_warn_ratio", cls.load_guard_warn_ratio, 0.2, 10.0),
            load_guard_hard_ratio=_float("load_guard_hard_ratio", cls.load_guard_hard_ratio, 0.2, 10.0),
            mem_guard_warn_ratio=_float("mem_guard_warn_ratio", cls.mem_guard_warn_ratio, 0.01, 0.95),
            mem_guard_hard_ratio=_float("mem_guard_hard_ratio", cls.mem_guard_hard_ratio, 0.01, 0.95),
            swap_guard_warn_ratio=_float("swap_guard_warn_ratio", cls.swap_guard_warn_ratio, 0.0, 1.0),
            swap_guard_hard_ratio=_float("swap_guard_hard_ratio", cls.swap_guard_hard_ratio, 0.0, 1.0),
            enable_auto_local_corpus=_truthy(
                data.get("enable_auto_local_corpus", cls.enable_auto_local_corpus)
            ),
            auto_local_index_interval_s=_int(
                "auto_local_index_interval_s",
                cls.auto_local_index_interval_s,
                60,
                7 * 24 * 3600,
            ),
            auto_local_max_help_cmds=_int(
                "auto_local_max_help_cmds",
                cls.auto_local_max_help_cmds,
                0,
                64,
            ),
            auto_local_max_man_cmds=_int(
                "auto_local_max_man_cmds",
                cls.auto_local_max_man_cmds,
                0,
                64,
            ),
            auto_local_max_code_files=_int(
                "auto_local_max_code_files",
                cls.auto_local_max_code_files,
                10,
                5000,
            ),
            auto_local_chunk_chars=_int(
                "auto_local_chunk_chars",
                cls.auto_local_chunk_chars,
                200,
                4000,
            ),
            auto_local_max_pearl_records=_int(
                "auto_local_max_pearl_records",
                cls.auto_local_max_pearl_records,
                10,
                100000,
            ),
            auto_local_include_pearls=_truthy(
                data.get("auto_local_include_pearls", cls.auto_local_include_pearls)
            ),
            enable_micro_local_corpus=_truthy(
                data.get("enable_micro_local_corpus", cls.enable_micro_local_corpus)
            ),
            micro_local_ttl_s=_int(
                "micro_local_ttl_s",
                cls.micro_local_ttl_s,
                30,
                30 * 24 * 3600,
            ),
            micro_local_max_help_cmds=_int(
                "micro_local_max_help_cmds",
                cls.micro_local_max_help_cmds,
                0,
                16,
            ),
            micro_local_max_man_cmds=_int(
                "micro_local_max_man_cmds",
                cls.micro_local_max_man_cmds,
                0,
                16,
            ),
            micro_local_max_code_files=_int(
                "micro_local_max_code_files",
                cls.micro_local_max_code_files,
                0,
                20,
            ),
            micro_local_chunk_chars=_int(
                "micro_local_chunk_chars",
                cls.micro_local_chunk_chars,
                200,
                4000,
            ),
        )


class SphereGPU:
    """
    Local virtual accelerator for inference orchestration.
    """

    def __init__(self, assistant, config: SphereGPUConfig | None = None):
        self._assistant = assistant
        self._config = config or SphereGPUConfig()

        cpu_default = max(1, min(int(os.cpu_count() or 1), 8))
        virtual_cores = max(1, min(self._config.virtual_cores, max(cpu_default, self._config.virtual_cores)))
        self._virtual_cores = virtual_cores

        self._shell_limits = {
            "inner": max(1, min(self._config.shell_inner_max, virtual_cores)),
            "mid": max(1, min(self._config.shell_mid_max, virtual_cores)),
            "outer": max(1, min(self._config.shell_outer_max, virtual_cores)),
        }
        self._semaphores: dict[Shell, threading.BoundedSemaphore] = {
            shell: threading.BoundedSemaphore(limit)
            for shell, limit in self._shell_limits.items()
        }

        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self._active = {"inner": 0, "mid": 0, "outer": 0}
        self._stats: dict[str, Any] = {
            "requests_total": 0,
            "jobs_total": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "guard_downgrades": 0,
            "shell_counts": {"inner": 0, "mid": 0, "outer": 0},
            "tier_counts": {"fast": 0, "code": 0, "deep": 0},
        }
        self._last_resource_snapshot: dict[str, Any] = {}
        self._auto_local_state: dict[str, Any] = {
            "enabled": bool(self._config.enable_auto_local_corpus),
            "running": False,
            "last_started_ts": 0.0,
            "last_completed_ts": 0.0,
            "last_error": "",
            "last_result": {},
        }
        self._micro_local_state: dict[str, Any] = {
            "enabled": bool(self._config.enable_micro_local_corpus),
            "runs_total": 0,
            "applied_runs": 0,
            "last_error": "",
            "last_result": {},
        }
        self._state_path = self._resolve_state_path(self._config.state_path)
        self._load_state()

    @classmethod
    def from_config(cls, engine, assistant=None) -> "SphereGPU":
        from skg.resonance.orchestrator import LayeredAssistant

        cfg = _load_sphere_gpu_config()
        sph_cfg = SphereGPUConfig.from_dict(cfg)
        resolved_assistant = assistant or LayeredAssistant.from_config(engine)
        return cls(assistant=resolved_assistant, config=sph_cfg)

    def infer(
        self,
        query: str,
        point: SpherePoint | None = None,
        k_each: int | None = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        text = (query or "").strip()
        if not text:
            raise ValueError("query text is empty")
        with self._lock:
            self._stats["requests_total"] += 1

        p = point or SpherePoint()
        micro_index = self._run_micro_local_index(text, theta=p.theta)
        auto_index = self._maybe_trigger_auto_local_index(text, theta=p.theta)
        shell = self._shell_for_r(p.r)
        prefer, route_reason = self._prefer_for_point(p, shell=shell)
        resource_snapshot = self._resource_snapshot()
        prefer, guard_reason = self._apply_resource_guard(prefer, resource_snapshot)
        if guard_reason:
            route_reason = f"{route_reason},{guard_reason}"
        retrieval_k = max(1, int(k_each if k_each is not None else self._config.default_k_each))
        cache_key = self._cache_key(text, p, prefer, retrieval_k)

        cached = self._cache_get(cache_key)
        if cached is not None:
            result = dict(cached)
            result["cache_hit"] = True
            result["latency_s"] = round(time.perf_counter() - start, 4)
            sphere_meta = dict(result.get("sphere", {}))
            sphere_meta["queue_wait_s"] = 0.0
            sphere_meta["cache_reused"] = True
            sphere_meta["shell_active"] = self._active_snapshot()
            sphere_meta["micro_local_index"] = micro_index
            sphere_meta["auto_local_index"] = auto_index
            result["sphere"] = sphere_meta
            with self._lock:
                self._stats["cache_hits"] += 1
            self._persist_state()
            return result

        with self._lock:
            self._stats["cache_misses"] += 1

        wait_start = time.perf_counter()
        sem = self._semaphores[shell]
        sem.acquire()
        wait_s = round(time.perf_counter() - wait_start, 3)
        self._set_active(shell, delta=1)
        try:
            core_result = self._assistant.ask(
                text,
                prefer=prefer,
                k_each=retrieval_k,
                theta=p.theta,
            )
        finally:
            self._set_active(shell, delta=-1)
            sem.release()

        result = dict(core_result)
        sphere_meta = {
            "r": p.r,
            "theta": p.theta,
            "phi": p.phi,
            "stream": p.stream,
            "shell": shell,
            "prefer": prefer,
            "route_reason": route_reason,
            "guard_reason": guard_reason,
            "queue_wait_s": wait_s,
            "resource_snapshot": resource_snapshot,
            "shell_active": self._active_snapshot(),
            "micro_local_index": micro_index,
            "auto_local_index": auto_index,
        }
        result["sphere"] = sphere_meta
        result["cache_hit"] = False

        self._cache_put(cache_key, result)
        self._record_job(shell=shell, tier=prefer)
        self._persist_state()
        return result

    def infer_batch(
        self,
        requests: list[dict[str, Any]],
        max_workers: int | None = None,
    ) -> list[dict[str, Any]]:
        if not requests:
            return []
        workers = int(max_workers) if max_workers else self._virtual_cores
        workers = max(1, min(workers, self._virtual_cores, len(requests)))

        out: list[dict[str, Any] | None] = [None] * len(requests)

        def _run(index: int, payload: dict[str, Any]):
            point = payload.get("point")
            if not isinstance(point, SpherePoint):
                point = SpherePoint.from_values(
                    r=payload.get("r", 0.35),
                    theta=str(payload.get("theta", "general")),
                    phi=payload.get("phi", 0.5),
                    stream=payload.get("stream", 0),
                )
            result = self.infer(
                query=str(payload.get("query", "")),
                point=point,
                k_each=payload.get("k_each"),
            )
            out[index] = result

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="sphere-gpu",
        ) as pool:
            futures = []
            for idx, item in enumerate(requests):
                futures.append(pool.submit(_run, idx, item))
            for fut in concurrent.futures.as_completed(futures):
                fut.result()

        return [item for item in out if item is not None]

    def status(self) -> dict[str, Any]:
        with self._lock:
            stats = {
                "requests_total": int(self._stats["requests_total"]),
                "jobs_total": int(self._stats["jobs_total"]),
                "cache_hits": int(self._stats["cache_hits"]),
                "cache_misses": int(self._stats["cache_misses"]),
                "guard_downgrades": int(self._stats["guard_downgrades"]),
                "shell_counts": dict(self._stats["shell_counts"]),
                "tier_counts": dict(self._stats["tier_counts"]),
            }
            active = dict(self._active)
            cache_entries = len(self._cache)
            last_resource = dict(self._last_resource_snapshot)
            auto_local_state = dict(self._auto_local_state)
            micro_local_state = dict(self._micro_local_state)
            if isinstance(auto_local_state.get("last_result"), dict):
                last_result = dict(auto_local_state["last_result"])
                if "result" in last_result and isinstance(last_result["result"], dict):
                    compact = dict(last_result["result"])
                    if "summary" in compact:
                        compact.pop("summary", None)
                    last_result["result"] = compact
                auto_local_state["last_result"] = last_result
            if isinstance(micro_local_state.get("last_result"), dict):
                micro_result = dict(micro_local_state["last_result"])
                if "summary" in micro_result and isinstance(micro_result["summary"], dict):
                    micro_result.pop("summary", None)
                micro_local_state["last_result"] = micro_result
        return {
            "enabled": self._config.enabled,
            "virtual_cores": self._virtual_cores,
            "shell_limits": dict(self._shell_limits),
            "active": active,
            "cache": {
                "entries": cache_entries,
                "max_size": self._config.cache_size,
            },
            "stats": stats,
            "thresholds": {
                "mid_r_threshold": self._config.mid_r_threshold,
                "outer_r_threshold": self._config.outer_r_threshold,
                "uncertainty_escalation_phi": self._config.uncertainty_escalation_phi,
            },
            "resource_guard": {
                "enabled": self._config.enable_resource_guard,
                "load_warn_ratio": self._config.load_guard_warn_ratio,
                "load_hard_ratio": self._config.load_guard_hard_ratio,
                "mem_warn_ratio": self._config.mem_guard_warn_ratio,
                "mem_hard_ratio": self._config.mem_guard_hard_ratio,
                "swap_warn_ratio": self._config.swap_guard_warn_ratio,
                "swap_hard_ratio": self._config.swap_guard_hard_ratio,
                "last_snapshot": last_resource,
            },
            "state": {
                "persist_state": self._config.persist_state,
                "state_path": str(self._state_path),
            },
            "auto_local_corpus": {
                **auto_local_state,
                "interval_s": int(self._config.auto_local_index_interval_s),
                "max_help_cmds": int(self._config.auto_local_max_help_cmds),
                "max_man_cmds": int(self._config.auto_local_max_man_cmds),
                "max_code_files": int(self._config.auto_local_max_code_files),
            },
            "micro_local_corpus": {
                **micro_local_state,
                "ttl_s": int(self._config.micro_local_ttl_s),
                "max_help_cmds": int(self._config.micro_local_max_help_cmds),
                "max_man_cmds": int(self._config.micro_local_max_man_cmds),
                "max_code_files": int(self._config.micro_local_max_code_files),
            },
        }

    def _engine_for_local_corpus(self):
        return getattr(self._assistant, "_engine", None)

    def _run_micro_local_index(
        self,
        query: str,
        *,
        theta: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        if not self._config.enable_micro_local_corpus:
            return {"started": False, "reason": "disabled"}

        engine = self._engine_for_local_corpus()
        if engine is None:
            return {"started": False, "reason": "engine_unavailable"}

        start = time.perf_counter()
        try:
            from skg.resonance.local_corpus import micro_index_local_corpus

            payload = micro_index_local_corpus(
                engine,
                query=query,
                theta=theta,
                force=force,
                ttl_s=self._config.micro_local_ttl_s,
                max_help_cmds=self._config.micro_local_max_help_cmds,
                max_man_cmds=self._config.micro_local_max_man_cmds,
                max_code_files=self._config.micro_local_max_code_files,
                chunk_chars=self._config.micro_local_chunk_chars,
            )
            elapsed = round(time.perf_counter() - start, 4)
            compact = {
                "started": True,
                "skipped": bool(payload.get("skipped")),
                "reason": str(payload.get("reason", "")),
                "latency_s": elapsed,
                "selected": dict(payload.get("selected", {}) or {}),
                "due": dict(payload.get("due", {}) or {}),
                "totals": dict(payload.get("totals", {}) or {}),
            }
            with self._lock:
                self._micro_local_state["runs_total"] = int(self._micro_local_state.get("runs_total", 0)) + 1
                if not compact["skipped"]:
                    self._micro_local_state["applied_runs"] = int(self._micro_local_state.get("applied_runs", 0)) + 1
                self._micro_local_state["last_error"] = ""
                self._micro_local_state["last_result"] = compact
            return compact
        except Exception as exc:
            elapsed = round(time.perf_counter() - start, 4)
            out = {"started": False, "reason": "error", "error": str(exc), "latency_s": elapsed}
            with self._lock:
                self._micro_local_state["runs_total"] = int(self._micro_local_state.get("runs_total", 0)) + 1
                self._micro_local_state["last_error"] = str(exc)
                self._micro_local_state["last_result"] = out
            return out

    def _maybe_trigger_auto_local_index(
        self,
        query: str,
        *,
        theta: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        if not self._config.enable_auto_local_corpus:
            return {"started": False, "reason": "disabled"}

        engine = self._engine_for_local_corpus()
        if engine is None:
            return {"started": False, "reason": "engine_unavailable"}

        now = time.time()
        with self._lock:
            if bool(self._auto_local_state.get("running")):
                return {"started": False, "reason": "running"}
            last_completed_ts = float(self._auto_local_state.get("last_completed_ts", 0.0) or 0.0)
            if (
                not force
                and last_completed_ts > 0.0
                and (now - last_completed_ts) < float(self._config.auto_local_index_interval_s)
            ):
                return {"started": False, "reason": "interval_not_elapsed"}
            self._auto_local_state["running"] = True
            self._auto_local_state["last_started_ts"] = now
            self._auto_local_state["last_error"] = ""

        thread = threading.Thread(
            target=self._run_auto_local_index,
            kwargs={"query": query, "theta": theta, "force": force, "engine": engine},
            name="sphere-auto-local-index",
            daemon=True,
        )
        thread.start()
        return {"started": True, "reason": "scheduled"}

    def _run_auto_local_index(
        self,
        *,
        query: str,
        theta: str | None,
        force: bool,
        engine,
    ) -> None:
        try:
            from skg.resonance.local_corpus import smart_index_local_corpus

            result = smart_index_local_corpus(
                engine,
                query=query,
                theta=theta,
                force=force,
                min_interval_s=self._config.auto_local_index_interval_s,
                include_pearls=self._config.auto_local_include_pearls,
                max_code_files=self._config.auto_local_max_code_files,
                chunk_chars=self._config.auto_local_chunk_chars,
                max_pearl_records=self._config.auto_local_max_pearl_records,
                max_help_cmds=self._config.auto_local_max_help_cmds,
                max_man_cmds=self._config.auto_local_max_man_cmds,
            )
            with self._lock:
                self._auto_local_state["last_result"] = result
                self._auto_local_state["last_error"] = ""
        except Exception as exc:
            with self._lock:
                self._auto_local_state["last_error"] = str(exc)
                self._auto_local_state["last_result"] = {"error": str(exc)}
        finally:
            with self._lock:
                self._auto_local_state["running"] = False
                self._auto_local_state["last_completed_ts"] = time.time()

    def _shell_for_r(self, r: float) -> Shell:
        if r >= self._config.outer_r_threshold:
            return "outer"
        if r >= self._config.mid_r_threshold:
            return "mid"
        return "inner"

    def _prefer_for_point(self, point: SpherePoint, *, shell: Shell) -> tuple[Tier, str]:
        theta = (point.theta or "general").strip().lower()
        base: Tier = {"inner": "fast", "mid": "code", "outer": "deep"}[shell]
        reason = [f"shell={shell}"]

        code_tokens = ("code", "coder", "debug", "compile", "test", "lint", "refactor")
        deep_tokens = ("rag", "reason", "analysis", "architecture", "design", "plan", "research")
        fast_tokens = ("quick", "summary", "status", "short")

        prefer = base
        if any(tok in theta for tok in code_tokens):
            prefer = "code"
            reason.append("theta=code")
        elif any(tok in theta for tok in deep_tokens):
            prefer = "deep"
            reason.append("theta=deep")
        elif any(tok in theta for tok in fast_tokens):
            prefer = "fast"
            reason.append("theta=fast")

        if point.phi >= self._config.uncertainty_escalation_phi:
            if prefer == "fast":
                prefer = "code"
            elif prefer == "code":
                prefer = "deep"
            reason.append("phi_escalation")

        return prefer, ",".join(reason)

    def _cache_key(self, query: str, point: SpherePoint, prefer: Tier, k_each: int) -> str:
        r_bucket = int(point.r * 20)
        phi_bucket = int(point.phi * 20)
        return "|".join(
            [
                query.strip().lower(),
                str(r_bucket),
                point.theta.strip().lower(),
                str(phi_bucket),
                str(point.stream),
                prefer,
                str(k_each),
            ]
        )

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._cache.get(key)
            if item is None:
                return None
            self._cache.move_to_end(key, last=True)
            return dict(item)

    def _cache_put(self, key: str, result: dict[str, Any]) -> None:
        value = self._safe_for_state(result)
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key, last=True)
            while len(self._cache) > self._config.cache_size:
                self._cache.popitem(last=False)

    def _record_job(self, *, shell: Shell, tier: Tier) -> None:
        with self._lock:
            self._stats["jobs_total"] += 1
            self._stats["shell_counts"][shell] += 1
            self._stats["tier_counts"][tier] += 1

    def _set_active(self, shell: Shell, delta: int) -> None:
        with self._lock:
            self._active[shell] = max(0, int(self._active.get(shell, 0)) + int(delta))

    def _active_snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._active)

    def _resolve_state_path(self, configured: str) -> Path:
        if configured:
            return Path(configured).expanduser()
        return _default_state_path()

    def _load_state(self) -> None:
        if not self._config.persist_state:
            return
        path = self._state_path
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("[sphere_gpu] failed to load state file %s: %s", path, exc)
            return
        if not isinstance(data, dict):
            return

        stats = data.get("stats", {}) if isinstance(data.get("stats"), dict) else {}
        with self._lock:
            for key in ("requests_total", "jobs_total", "cache_hits", "cache_misses"):
                try:
                    self._stats[key] = int(stats.get(key, self._stats.get(key, 0)))
                except Exception:
                    pass
            try:
                self._stats["guard_downgrades"] = int(
                    stats.get("guard_downgrades", self._stats.get("guard_downgrades", 0))
                )
            except Exception:
                pass

            for key in ("inner", "mid", "outer"):
                try:
                    self._stats["shell_counts"][key] = int(
                        (stats.get("shell_counts", {}) or {}).get(key, self._stats["shell_counts"].get(key, 0))
                    )
                except Exception:
                    pass

            for key in ("fast", "code", "deep"):
                try:
                    self._stats["tier_counts"][key] = int(
                        (stats.get("tier_counts", {}) or {}).get(key, self._stats["tier_counts"].get(key, 0))
                    )
                except Exception:
                    pass

            rows = data.get("cache", [])
            if isinstance(rows, list):
                for row in rows[-self._config.cache_size :]:
                    if not isinstance(row, dict):
                        continue
                    key = row.get("key")
                    value = row.get("value")
                    if not isinstance(key, str) or not isinstance(value, dict):
                        continue
                    self._cache[key] = dict(value)
                while len(self._cache) > self._config.cache_size:
                    self._cache.popitem(last=False)

    def _persist_state(self) -> None:
        if not self._config.persist_state:
            return
        with self._lock:
            snapshot = {
                "version": 1,
                "stats": {
                    "requests_total": int(self._stats.get("requests_total", 0)),
                    "jobs_total": int(self._stats.get("jobs_total", 0)),
                    "cache_hits": int(self._stats.get("cache_hits", 0)),
                    "cache_misses": int(self._stats.get("cache_misses", 0)),
                    "guard_downgrades": int(self._stats.get("guard_downgrades", 0)),
                    "shell_counts": dict(self._stats.get("shell_counts", {})),
                    "tier_counts": dict(self._stats.get("tier_counts", {})),
                },
                "cache": [
                    {"key": key, "value": value}
                    for key, value in self._cache.items()
                ],
            }
        path = self._state_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = path.with_suffix(path.suffix + ".tmp")
            tmp_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            os.replace(tmp_path, path)
        except Exception as exc:
            log.warning("[sphere_gpu] failed to persist state file %s: %s", path, exc)

    def _safe_for_state(self, result: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "query",
            "route",
            "route_reason",
            "model_used",
            "models_attempted",
            "num_predict",
            "fallback_used",
            "latency_s",
            "context_counts",
            "context_preview",
            "theta",
            "response",
            "sphere",
            "cache_hit",
        }
        payload: dict[str, Any] = {}
        for key in allowed:
            if key in result:
                payload[key] = result[key]

        models_attempted = payload.get("models_attempted")
        if isinstance(models_attempted, list):
            payload["models_attempted"] = [str(x) for x in models_attempted[:8]]

        context_preview = payload.get("context_preview")
        if isinstance(context_preview, list):
            trimmed = []
            for line in context_preview[:24]:
                line_s = str(line)
                if len(line_s) > 260:
                    line_s = line_s[:257] + "..."
                trimmed.append(line_s)
            payload["context_preview"] = trimmed

        response = str(payload.get("response", ""))
        max_chars = max(500, int(self._config.persist_response_chars))
        if len(response) > max_chars:
            payload["response"] = response[: max_chars - 3] + "..."
        else:
            payload["response"] = response
        return payload

    def _resource_snapshot(self) -> dict[str, Any]:
        load1 = 0.0
        load5 = 0.0
        load15 = 0.0
        try:
            load1, load5, load15 = os.getloadavg()
        except Exception:
            pass

        mem_total_kb = 0
        mem_available_kb = 0
        swap_total_kb = 0
        swap_free_kb = 0
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" not in line:
                    continue
                key, raw_val = line.split(":", 1)
                parts = raw_val.strip().split()
                if not parts:
                    continue
                try:
                    value = int(parts[0])
                except Exception:
                    continue
                if key == "MemTotal":
                    mem_total_kb = value
                elif key == "MemAvailable":
                    mem_available_kb = value
                elif key == "SwapTotal":
                    swap_total_kb = value
                elif key == "SwapFree":
                    swap_free_kb = value
        except Exception:
            pass

        mem_available_ratio = (
            float(mem_available_kb) / float(mem_total_kb)
            if mem_total_kb > 0
            else 1.0
        )
        swap_used_kb = max(0, swap_total_kb - swap_free_kb)
        swap_used_ratio = (
            float(swap_used_kb) / float(swap_total_kb)
            if swap_total_kb > 0
            else 0.0
        )
        load_ratio = float(load1) / float(max(1, self._virtual_cores))

        snapshot = {
            "load1": round(float(load1), 4),
            "load5": round(float(load5), 4),
            "load15": round(float(load15), 4),
            "load_ratio": round(load_ratio, 4),
            "mem_total_kb": int(mem_total_kb),
            "mem_available_kb": int(mem_available_kb),
            "mem_available_ratio": round(mem_available_ratio, 4),
            "swap_total_kb": int(swap_total_kb),
            "swap_used_kb": int(swap_used_kb),
            "swap_used_ratio": round(swap_used_ratio, 4),
        }
        with self._lock:
            self._last_resource_snapshot = dict(snapshot)
        return snapshot

    def _apply_resource_guard(self, prefer: Tier, snapshot: dict[str, Any]) -> tuple[Tier, str]:
        if not self._config.enable_resource_guard:
            return prefer, ""

        try:
            load_ratio = float(snapshot.get("load_ratio", 0.0))
        except Exception:
            load_ratio = 0.0
        try:
            mem_ratio = float(snapshot.get("mem_available_ratio", 1.0))
        except Exception:
            mem_ratio = 1.0
        try:
            swap_ratio = float(snapshot.get("swap_used_ratio", 0.0))
        except Exception:
            swap_ratio = 0.0

        hard = (
            load_ratio >= self._config.load_guard_hard_ratio
            or mem_ratio <= self._config.mem_guard_hard_ratio
            or swap_ratio >= self._config.swap_guard_hard_ratio
        )
        warn = (
            load_ratio >= self._config.load_guard_warn_ratio
            or mem_ratio <= self._config.mem_guard_warn_ratio
            or swap_ratio >= self._config.swap_guard_warn_ratio
        )

        if not hard and not warn:
            return prefer, ""

        downgraded = prefer
        if hard:
            if prefer == "deep":
                downgraded = "fast"
            elif prefer == "code":
                downgraded = "fast"
            reason_tag = "guard_hard"
        else:
            if prefer == "deep":
                downgraded = "code"
            elif prefer == "code" and (
                load_ratio >= (self._config.load_guard_warn_ratio * 1.3)
                or mem_ratio <= (self._config.mem_guard_warn_ratio * 0.9)
                or swap_ratio >= (self._config.swap_guard_warn_ratio * 1.2)
            ):
                downgraded = "fast"
            reason_tag = "guard_warn"

        if downgraded != prefer:
            with self._lock:
                self._stats["guard_downgrades"] += 1
            return (
                downgraded,
                f"{reason_tag}(load={load_ratio:.2f},mem={mem_ratio:.2f},swap={swap_ratio:.2f})",
            )

        return prefer, f"{reason_tag}(hold)"


def _load_sphere_gpu_config() -> dict[str, Any]:
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
        sphere = resonance.get("sphere_gpu", {}) or {}
        if isinstance(sphere, dict):
            return sphere
    return {}


def _default_state_path() -> Path:
    try:
        from skg_core.config.paths import SKG_STATE_DIR
        return SKG_STATE_DIR / "resonance" / "sphere_gpu_state.json"
    except Exception:
        return Path("/tmp/skg_sphere_gpu_state.json")
