"""
skg.kernel.tool_protocol
========================
Lightweight tool/sensor abstraction ported from Claude Code's Tool.ts.

A SensorTool is the standard contract for anything SKG can dispatch:
  - sensors (nmap, msf, ssh, bloodhound, ...)
  - adapters (event converters)
  - projectors (domain scorers)
  - gravity instruments (indirect)

Key ideas borrowed from CC:
  - is_read_only() / is_concurrency_safe() → drives parallel vs. serial dispatch
  - input_schema validates before dispatch (no silent bad args)
  - ToolResult carries structured output + attachment metadata
  - fail-closed: unknown concurrency safety → serial

Existing sensors do NOT need to be rewritten. Register them via
`build_sensor_tool()` which wraps a plain callable.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Protocol, Union

log = logging.getLogger("skg.kernel.tool_protocol")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Structured result from a sensor tool call."""
    tool_name: str
    success: bool
    output: Any                          # raw output (dict, list, str, ...)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Side-channel attachments (like CC's AttachmentMessage)
    attachments: list[Dict[str, Any]] = field(default_factory=list)

    def attach(self, type_: str, **kwargs: Any) -> None:
        self.attachments.append({"type": type_, **kwargs})


@dataclass
class HookDecision:
    """Decision from a Pre/PostSensorUse hook."""
    behavior: str                        # "allow" | "deny" | "ask"
    message: Optional[str] = None
    updated_input: Optional[Dict[str, Any]] = None
    decision_reason: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# SensorTool protocol
# ---------------------------------------------------------------------------

class SensorTool(Protocol):
    """
    Protocol every SKG sensor/adapter must satisfy.

    Minimal required: name, description, run().
    Concurrency defaults to safe=False (serial) unless declared otherwise.
    """

    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    def is_read_only(self) -> bool:
        """True if this tool never writes state / fires exploits."""
        return False

    def is_concurrency_safe(self, input_args: Dict[str, Any]) -> bool:
        """
        True if this tool call can run in parallel with other safe calls.
        Conservative default: False (serial).
        Fail-closed: if this method raises, treated as False.
        """
        return False

    def validate_input(self, input_args: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate input args. Returns (ok, error_message).
        Default: always valid.
        """
        return True, None

    async def run(
        self,
        input_args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolResult: ...


# ---------------------------------------------------------------------------
# build_sensor_tool() factory
# ---------------------------------------------------------------------------

def build_sensor_tool(
    name: str,
    description: str,
    fn: Union[
        Callable[[Dict[str, Any]], Any],
        Callable[[Dict[str, Any]], Awaitable[Any]],
    ],
    *,
    read_only: bool = False,
    concurrency_safe: bool | None = None,
    required_keys: list[str] | None = None,
) -> "BuiltSensorTool":
    """
    Wrap any callable as a SensorTool.

    concurrency_safe defaults to read_only (read-only sensors are safe
    to parallelize; write sensors default to serial).

    Example:
        nmap_tool = build_sensor_tool(
            "skg_nmap",
            "Run nmap against a target",
            lambda args: run_nmap(args["target"]),
            read_only=True,
            required_keys=["target"],
        )
    """
    if concurrency_safe is None:
        concurrency_safe = read_only
    return BuiltSensorTool(
        _name=name,
        _description=description,
        _fn=fn,
        _read_only=read_only,
        _concurrency_safe=concurrency_safe,
        _required_keys=required_keys or [],
    )


class BuiltSensorTool:
    """Concrete SensorTool produced by build_sensor_tool()."""

    def __init__(
        self,
        _name: str,
        _description: str,
        _fn: Any,
        _read_only: bool,
        _concurrency_safe: bool,
        _required_keys: list[str],
    ) -> None:
        self._name = _name
        self._description = _description
        self._fn = _fn
        self._read_only = _read_only
        self._concurrency_safe = _concurrency_safe
        self._required_keys = _required_keys

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    def is_read_only(self) -> bool:
        return self._read_only

    def is_concurrency_safe(self, input_args: Dict[str, Any]) -> bool:
        return self._concurrency_safe

    def validate_input(self, input_args: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        missing = [k for k in self._required_keys if k not in input_args]
        if missing:
            return False, f"Missing required input keys: {missing}"
        return True, None

    async def run(
        self,
        input_args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        ok, err = self.validate_input(input_args)
        if not ok:
            return ToolResult(
                tool_name=self._name,
                success=False,
                output=None,
                error=err,
            )
        try:
            if asyncio.iscoroutinefunction(self._fn):
                raw = await self._fn(input_args)
            else:
                loop = asyncio.get_event_loop()
                raw = await loop.run_in_executor(None, self._fn, input_args)
            return ToolResult(tool_name=self._name, success=True, output=raw)
        except Exception as exc:
            log.exception("[tool_protocol] %s raised", self._name)
            return ToolResult(
                tool_name=self._name,
                success=False,
                output=None,
                error=str(exc),
            )


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

class SensorRegistry:
    """
    Lightweight registry — sensors register themselves; orchestrator looks them up.

    Usage:
        registry = SensorRegistry()
        registry.register(nmap_tool)
        tool = registry.get("skg_nmap")
    """

    def __init__(self) -> None:
        self._tools: Dict[str, SensorTool] = {}

    def register(self, tool: SensorTool) -> None:
        self._tools[tool.name] = tool
        log.debug("[registry] registered tool: %s", tool.name)

    def get(self, name: str) -> Optional[SensorTool]:
        return self._tools.get(name)

    def all(self) -> list[SensorTool]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools.keys())


# Module-level default registry
default_registry = SensorRegistry()
