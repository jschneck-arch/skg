"""
skg.mcp.server
==============
On-demand MCP stdio server — invoked as `skg mcp-serve`.

NOT always-on. Claude Code (or any MCP client) launches it as a subprocess
and communicates via JSON-RPC 2.0 over stdin/stdout. The process exits when
stdin closes.

Exposes SKG capabilities as MCP tools:
    skg_kernel_state     — kernel entropy + wicket states for a node
    skg_gravity_field    — gravity field status (instruments, energy)
    skg_sensor_run       — dispatch a sensor by name
    skg_surface          — full attack surface map (nodes + states)
    skg_proposals        — current action proposals

Transport: stdio (simplest MCP transport, no auth needed)
Protocol:  MCP 2024-11-05 (initialize / tools/list / tools/call)

Adding new tools:
    1. Define an async def _tool_<name>(params) -> dict
    2. Add an entry to TOOL_DEFINITIONS list
    3. Done — the server loop picks it up automatically.

Security:
    - Server only reads from stdin / writes to stdout
    - No network sockets opened
    - Subprocess inherits SKG env (paths, config) from parent shell
    - Input validation per-tool before any SKG call
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import traceback
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("skg.mcp.server")

# ---------------------------------------------------------------------------
# MCP protocol constants
# ---------------------------------------------------------------------------

MCP_VERSION = "2024-11-05"
SERVER_NAME = "skg"
SERVER_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

async def _tool_kernel_state(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return kernel entropy + wicket states for a node."""
    node = str(params.get("node") or "").strip()
    if not node:
        raise ValueError("'node' is required")

    from skg.kernel.engine import KernelStateEngine
    from skg.core.paths import DISCOVERY_DIR, EVENTS_DIR
    from pathlib import Path

    engine = KernelStateEngine(DISCOVERY_DIR, EVENTS_DIR)
    states = engine.states(node)
    energy = engine.energy(node, set(states.keys()), [])

    return {
        "node": node,
        "energy": energy,
        "wicket_states": {k: str(v) for k, v in states.items()},
    }


async def _tool_gravity_field(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return gravity field status: top instruments ranked by entropy reduction."""
    node = str(params.get("node") or "").strip()
    limit = int(params.get("limit") or 10)

    from skg.gravity import rank_instruments_for_node
    from skg.core.paths import DISCOVERY_DIR, EVENTS_DIR
    from skg.kernel.engine import KernelStateEngine

    engine = KernelStateEngine(DISCOVERY_DIR, EVENTS_DIR)
    states = engine.states(node) if node else {}
    ranked = rank_instruments_for_node(node, states) if node else []

    return {
        "node": node or "(all)",
        "ranked_instruments": ranked[:limit],
    }


async def _tool_sensor_run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch a registered sensor by name."""
    sensor_name = str(params.get("sensor") or "").strip()
    sensor_args = dict(params.get("args") or {})

    if not sensor_name:
        raise ValueError("'sensor' is required")

    from skg.kernel.orchestrator import run_sensors

    results = await run_sensors([(sensor_name, sensor_args)])
    if not results:
        return {"success": False, "error": f"sensor '{sensor_name}' not found in registry"}

    r = results[0]
    return {
        "sensor": r.tool_name,
        "success": r.success,
        "output": r.output,
        "error": r.error,
        "elapsed_s": r.metadata.get("elapsed_s"),
    }


async def _tool_surface(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return the full attack surface: nodes and their domain coverage."""
    from skg.core.paths import SKG_STATE_DIR
    import glob as _glob

    surface_files = sorted(
        _glob.glob(str(SKG_STATE_DIR / "surface_*.json")),
        reverse=True,
    )
    if not surface_files:
        return {"nodes": [], "message": "no surface files found"}

    import json as _json
    surface = _json.loads(open(surface_files[0]).read())
    return surface


async def _tool_proposals(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return current action proposals from the forge."""
    from skg.core.paths import SKG_STATE_DIR
    import glob as _glob, json as _json

    proposal_files = sorted(
        _glob.glob(str(SKG_STATE_DIR / "proposals" / "*.json")),
        key=lambda p: __import__("os").path.getmtime(p),
        reverse=True,
    )
    limit = int(params.get("limit") or 20)
    proposals = []
    for pf in proposal_files[:limit]:
        try:
            proposals.append(_json.loads(open(pf).read()))
        except Exception:
            pass

    return {"proposals": proposals, "total": len(proposal_files)}


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "skg_kernel_state",
        "description": "Get kernel entropy and wicket states for a node (IP or hostname).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {"type": "string", "description": "Node key (IP or hostname)"},
            },
            "required": ["node"],
        },
        "fn": _tool_kernel_state,
    },
    {
        "name": "skg_gravity_field",
        "description": "Get gravity field status: instruments ranked by entropy reduction potential.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": {"type": "string", "description": "Node key (optional — omit for global field)"},
                "limit": {"type": "integer", "description": "Max instruments to return", "default": 10},
            },
        },
        "fn": _tool_gravity_field,
    },
    {
        "name": "skg_sensor_run",
        "description": "Dispatch a registered SKG sensor by name with args.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sensor": {"type": "string", "description": "Sensor name (e.g. skg_nmap)"},
                "args": {"type": "object", "description": "Sensor-specific arguments"},
            },
            "required": ["sensor"],
        },
        "fn": _tool_sensor_run,
    },
    {
        "name": "skg_surface",
        "description": "Return the current attack surface map (nodes and domain coverage).",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "fn": _tool_surface,
    },
    {
        "name": "skg_proposals",
        "description": "Return current action proposals from the SKG forge.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max proposals to return", "default": 20},
            },
        },
        "fn": _tool_proposals,
    },
]

_TOOL_FN_MAP: Dict[str, Callable] = {t["name"]: t["fn"] for t in TOOL_DEFINITIONS}
_TOOL_SCHEMA_MAP: Dict[str, Dict] = {
    t["name"]: {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
    for t in TOOL_DEFINITIONS
}


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _ok(id_: Any, result: Any) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": id_, "result": result})


def _err(id_: Any, code: int, message: str, data: Any = None) -> str:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": id_, "error": err})


# ---------------------------------------------------------------------------
# Request handlers
# ---------------------------------------------------------------------------

async def _handle(request: Dict[str, Any]) -> Optional[str]:
    """Dispatch one JSON-RPC request. Returns response string or None for notifications."""
    id_ = request.get("id")
    method = request.get("method", "")
    params = request.get("params") or {}

    # Notifications (no id) — no response
    if id_ is None and not method.startswith("initialize"):
        return None

    try:
        if method == "initialize":
            return _ok(id_, {
                "protocolVersion": MCP_VERSION,
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "capabilities": {"tools": {}},
            })

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return _ok(id_, {"tools": list(_TOOL_SCHEMA_MAP.values())})

        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            tool_args = dict(params.get("arguments") or {})

            fn = _TOOL_FN_MAP.get(tool_name)
            if fn is None:
                return _err(id_, -32601, f"Unknown tool: {tool_name}")

            result = await fn(tool_args)
            return _ok(id_, {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": False,
            })

        if method == "ping":
            return _ok(id_, {})

        return _err(id_, -32601, f"Method not found: {method}")

    except ValueError as exc:
        return _err(id_, -32602, f"Invalid params: {exc}")
    except Exception as exc:
        log.exception("[mcp] unhandled error in %s", method)
        return _err(id_, -32603, "Internal error", str(exc))


# ---------------------------------------------------------------------------
# stdio event loop
# ---------------------------------------------------------------------------

async def _serve_stdio() -> None:
    """Read JSON-RPC requests from stdin, write responses to stdout."""
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()

    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    transport, _ = await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout)

    log.info("[mcp] SKG MCP server started (stdio)")

    while True:
        try:
            line = await reader.readline()
        except Exception:
            break
        if not line:
            break

        line = line.decode("utf-8", errors="replace").strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _err(None, -32700, f"Parse error: {exc}")
            sys.stdout.write(response + "\n")
            sys.stdout.flush()
            continue

        response = await _handle(request)
        if response is not None:
            sys.stdout.write(response + "\n")
            sys.stdout.flush()


def serve() -> None:
    """
    Entry point: `skg mcp-serve`.

    Runs the stdio MCP server until stdin closes.
    """
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,    # all logs to stderr, never stdout (MCP transport)
    )
    try:
        asyncio.run(_serve_stdio())
    except KeyboardInterrupt:
        pass
    log.info("[mcp] SKG MCP server stopped")
