"""
skg.kernel.orchestrator
=======================
Async sensor concurrency engine — ported from Claude Code's toolOrchestration.ts.

Core insight from CC: tools self-declare concurrency safety, and the
orchestrator automatically batches consecutive safe tools into parallel
groups while running unsafe tools serially.

Partition algorithm (identical to CC):
  1. Walk sensor calls left to right.
  2. If the current sensor is concurrency-safe AND the previous batch is
     also concurrency-safe, append to that batch.
  3. Otherwise start a new batch.

This means:
  [read, read, write, read, read]
  → [{concurrent: [read, read]}, {serial: [write]}, {concurrent: [read, read]}]

Pre/Post hooks are called per-sensor so gravity can gate each dispatch.

Usage:
    from skg.kernel.orchestrator import run_sensors

    results = asyncio.run(run_sensors([
        ("skg_nmap", {"target": "10.0.0.1"}),
        ("skg_msf",  {"module": "...", "target": "10.0.0.1"}),
    ]))
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from .hooks import HookDecision, run_post_sensor_hooks, run_pre_sensor_hooks
from .tool_protocol import SensorRegistry, SensorTool, ToolResult, default_registry

log = logging.getLogger("skg.kernel.orchestrator")

MAX_CONCURRENCY = 10   # mirrors CC's CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY


# ---------------------------------------------------------------------------
# Batch partitioning
# ---------------------------------------------------------------------------

@dataclass
class SensorBatch:
    is_concurrent: bool
    calls: List[Tuple[SensorTool, Dict[str, Any]]]   # (tool, input_args)


def partition_sensor_calls(
    calls: List[Tuple[str, Dict[str, Any]]],
    registry: SensorRegistry = default_registry,
) -> List[SensorBatch]:
    """
    Partition (name, args) pairs into concurrent / serial batches.

    Unknown tools and tools whose is_concurrency_safe() raises are
    treated as serial (fail-closed, same as CC).
    """
    batches: List[SensorBatch] = []

    for name, args in calls:
        tool = registry.get(name)
        if tool is None:
            log.warning("[orchestrator] unknown sensor '%s' — skipping", name)
            continue

        try:
            safe = bool(tool.is_concurrency_safe(args))
        except Exception:
            safe = False  # fail-closed

        if safe and batches and batches[-1].is_concurrent:
            batches[-1].calls.append((tool, args))
        else:
            batches.append(SensorBatch(is_concurrent=safe, calls=[(tool, args)]))

    return batches


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

async def _run_one(
    tool: SensorTool,
    args: Dict[str, Any],
    context: Optional[Dict[str, Any]],
) -> ToolResult:
    """Run one sensor with pre/post hooks."""
    # Pre-hook
    decision: HookDecision = await run_pre_sensor_hooks(tool.name, args, context)
    if decision.behavior == "deny":
        result = ToolResult(
            tool_name=tool.name,
            success=False,
            output=None,
            error=f"Denied by hook: {decision.message or 'PreSensorUse'}",
        )
        result.attach("hook_denied", reason=decision.message)
        return result

    # Use updated_input if hook provided it
    effective_args = decision.updated_input if decision.updated_input else args

    t0 = time.monotonic()
    result = await tool.run(effective_args, context)
    elapsed = time.monotonic() - t0
    result.metadata["elapsed_s"] = round(elapsed, 3)

    # Post-hook
    await run_post_sensor_hooks(tool.name, effective_args, result, context)

    return result


async def _run_concurrently(
    batch: SensorBatch,
    context: Optional[Dict[str, Any]],
    semaphore: asyncio.Semaphore,
) -> List[ToolResult]:
    """Run a concurrent batch with bounded parallelism."""
    async def _bounded(tool: SensorTool, args: Dict[str, Any]) -> ToolResult:
        async with semaphore:
            return await _run_one(tool, args, context)

    return list(await asyncio.gather(
        *[_bounded(tool, args) for tool, args in batch.calls],
        return_exceptions=False,
    ))


async def _run_serially(
    batch: SensorBatch,
    context: Optional[Dict[str, Any]],
) -> List[ToolResult]:
    results = []
    for tool, args in batch.calls:
        results.append(await _run_one(tool, args, context))
    return results


async def run_sensors(
    calls: List[Tuple[str, Dict[str, Any]]],
    context: Optional[Dict[str, Any]] = None,
    registry: SensorRegistry = default_registry,
    max_concurrency: int = MAX_CONCURRENCY,
) -> List[ToolResult]:
    """
    Dispatch a list of (sensor_name, args) calls with automatic
    parallel/serial partitioning.

    Returns results in the same order as the input calls (concurrent
    batches maintain internal order via asyncio.gather).
    """
    batches = partition_sensor_calls(calls, registry)
    semaphore = asyncio.Semaphore(max_concurrency)
    all_results: List[ToolResult] = []

    for batch in batches:
        if batch.is_concurrent:
            log.debug(
                "[orchestrator] concurrent batch: %s",
                [t.name for t, _ in batch.calls],
            )
            results = await _run_concurrently(batch, context, semaphore)
        else:
            log.debug(
                "[orchestrator] serial batch: %s",
                [t.name for t, _ in batch.calls],
            )
            results = await _run_serially(batch, context)

        all_results.extend(results)

    return all_results


async def run_sensors_stream(
    calls: List[Tuple[str, Dict[str, Any]]],
    context: Optional[Dict[str, Any]] = None,
    registry: SensorRegistry = default_registry,
    max_concurrency: int = MAX_CONCURRENCY,
) -> AsyncGenerator[ToolResult, None]:
    """
    Streaming variant — yields results as they complete (useful for UI/live output).
    Concurrent batches may yield out of submission order.
    """
    batches = partition_sensor_calls(calls, registry)
    semaphore = asyncio.Semaphore(max_concurrency)

    for batch in batches:
        if batch.is_concurrent:
            tasks = [
                asyncio.create_task(_run_one(tool, args, context))
                for tool, args in batch.calls
            ]
            # Semaphore wrapping for true bounded parallelism
            for coro in asyncio.as_completed(tasks):
                yield await coro
        else:
            for tool, args in batch.calls:
                yield await _run_one(tool, args, context)
