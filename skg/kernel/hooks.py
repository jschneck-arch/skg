"""
skg.kernel.hooks
================
Pre/Post sensor hooks — ported from Claude Code's toolHooks.ts.

Hooks are shell commands defined in skg_config.yaml under `hooks:`.
They run before and after each sensor dispatch and can:
  - allow  (explicit allow, skip gravity check)
  - deny   (block the sensor call)
  - ask    (defer to interactive prompt or gravity decision)
  - (no output / exit 0) → pass-through (normal flow continues)

Config shape in skg_config.yaml:
    hooks:
      pre_sensor_use:
        - match: "*"                   # glob against sensor name
          command: "/opt/skg/hooks/gravity_gate.sh"
          timeout_s: 5
      post_sensor_use:
        - match: "skg_msf*"
          command: "/opt/skg/hooks/record_exploit.sh"
          timeout_s: 10

Hook stdout protocol (JSON):
    {"decision": "allow"}
    {"decision": "deny",  "message": "gravity score too low"}
    {"decision": "ask",   "message": "requires operator approval"}
    {"decision": "allow", "updated_input": {"target": "10.0.0.2"}}

Exit code 2 → deny (same as CC's exit-code-2 convention).
Exit code 0 + no JSON → pass-through.

Key safety invariant (copied from CC):
  Hook "allow" does NOT bypass a gravity deny. The gravity field
  still evaluates after a hook allow; hook deny overrides all.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("skg.kernel.hooks")


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class HookDecision:
    """Result from a pre-sensor hook evaluation."""
    behavior: str                             # "allow" | "deny" | "ask" | "pass"
    message: Optional[str] = None
    updated_input: Optional[Dict[str, Any]] = None
    decision_reason: Optional[Dict[str, Any]] = None

    @classmethod
    def passthrough(cls) -> "HookDecision":
        return cls(behavior="pass")

    @classmethod
    def deny(cls, message: str, hook_name: str = "") -> "HookDecision":
        return cls(
            behavior="deny",
            message=message,
            decision_reason={"type": "hook", "hook_name": hook_name, "reason": message},
        )

    @classmethod
    def allow(cls, updated_input: Optional[Dict] = None) -> "HookDecision":
        return cls(behavior="allow", updated_input=updated_input)


@dataclass
class HookConfig:
    match: str           # glob pattern against sensor name
    command: str         # shell command to execute
    timeout_s: float = 5.0
    env: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_hook_config_cache: Optional[Dict[str, List[HookConfig]]] = None


def _load_hook_config() -> Dict[str, List[HookConfig]]:
    global _hook_config_cache
    if _hook_config_cache is not None:
        return _hook_config_cache

    try:
        import yaml
        from skg_core.config.paths import SKG_CONFIG_DIR
        cfg_path = SKG_CONFIG_DIR / "skg_config.yaml"
        if not cfg_path.exists():
            _hook_config_cache = {}
            return _hook_config_cache
        data = yaml.safe_load(cfg_path.read_text()) or {}
    except Exception as exc:
        log.debug("[hooks] could not load config: %s", exc)
        _hook_config_cache = {}
        return _hook_config_cache

    hooks_raw = data.get("hooks", {})
    result: Dict[str, List[HookConfig]] = {}

    for event_name, entries in hooks_raw.items():
        if not isinstance(entries, list):
            continue
        result[event_name] = [
            HookConfig(
                match=str(e.get("match", "*")),
                command=str(e.get("command", "")),
                timeout_s=float(e.get("timeout_s", 5.0)),
                env={k: str(v) for k, v in (e.get("env") or {}).items()},
            )
            for e in entries
            if e.get("command")
        ]

    _hook_config_cache = result
    return _hook_config_cache


def reload_hook_config() -> None:
    """Force a reload on next access (call after config changes)."""
    global _hook_config_cache
    _hook_config_cache = None


# ---------------------------------------------------------------------------
# Hook execution
# ---------------------------------------------------------------------------

def _matching_hooks(event: str, sensor_name: str) -> List[HookConfig]:
    config = _load_hook_config()
    hooks = config.get(event, [])
    return [h for h in hooks if fnmatch.fnmatch(sensor_name, h.match)]


def _run_hook_sync(
    hook: HookConfig,
    payload: Dict[str, Any],
) -> Optional[HookDecision]:
    """
    Run a single hook command synchronously (used in async via executor).

    payload is JSON-encoded and passed via SKG_HOOK_PAYLOAD env var.
    stdout is parsed for decision JSON.
    """
    env = {**os.environ, **hook.env}
    env["SKG_HOOK_PAYLOAD"] = json.dumps(payload)

    try:
        proc = subprocess.run(
            hook.command,
            shell=True,
            capture_output=True,
            timeout=hook.timeout_s,
            env=env,
            text=True,
        )
    except subprocess.TimeoutExpired:
        log.warning("[hooks] hook timed out: %s", hook.command)
        return None

    # Exit code 2 → deny (CC convention)
    if proc.returncode == 2:
        msg = proc.stdout.strip() or proc.stderr.strip() or "hook exit-2 denial"
        log.debug("[hooks] hook exit-2 deny: %s", hook.command)
        return HookDecision.deny(msg, hook_name=hook.command)

    if proc.returncode != 0:
        log.warning("[hooks] hook non-zero exit %d: %s", proc.returncode, hook.command)
        return None

    stdout = proc.stdout.strip()
    if not stdout:
        return None   # pass-through

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        log.debug("[hooks] hook stdout not JSON, treating as pass-through: %s", hook.command)
        return None

    decision = str(data.get("decision", "")).lower()
    message = data.get("message")
    updated_input = data.get("updated_input")

    if decision == "deny":
        return HookDecision.deny(message or "hook denied", hook_name=hook.command)
    if decision == "allow":
        return HookDecision.allow(updated_input=updated_input)
    if decision == "ask":
        return HookDecision(behavior="ask", message=message, updated_input=updated_input)

    return None  # unrecognized decision → pass-through


async def run_pre_sensor_hooks(
    sensor_name: str,
    input_args: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
) -> HookDecision:
    """
    Run all PreSensorUse hooks for a sensor.

    Returns the first decisive (non-pass) decision.
    If all hooks pass-through, returns HookDecision.passthrough().

    Safety invariant: a hook "allow" does not prevent gravity from
    later denying — that check is the orchestrator's responsibility.
    """
    hooks = _matching_hooks("pre_sensor_use", sensor_name)
    if not hooks:
        return HookDecision.passthrough()

    payload = {
        "event": "PreSensorUse",
        "sensor_name": sensor_name,
        "input": input_args,
        "context": context or {},
    }

    loop = asyncio.get_event_loop()
    for hook in hooks:
        decision = await loop.run_in_executor(None, _run_hook_sync, hook, payload)
        if decision is not None and decision.behavior != "pass":
            log.debug(
                "[hooks] PreSensorUse %s → %s (hook: %s)",
                sensor_name, decision.behavior, hook.command,
            )
            return decision

    return HookDecision.passthrough()


async def run_post_sensor_hooks(
    sensor_name: str,
    input_args: Dict[str, Any],
    result: Any,  # ToolResult
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Run all PostSensorUse hooks. Post-hooks are informational —
    they cannot cancel a completed sensor run, but can trigger
    follow-on actions (e.g. recording exploit evidence, gravity update).
    """
    hooks = _matching_hooks("post_sensor_use", sensor_name)
    if not hooks:
        return

    payload = {
        "event": "PostSensorUse",
        "sensor_name": sensor_name,
        "input": input_args,
        "success": getattr(result, "success", None),
        "error": getattr(result, "error", None),
        "context": context or {},
    }

    loop = asyncio.get_event_loop()
    for hook in hooks:
        try:
            await loop.run_in_executor(None, _run_hook_sync, hook, payload)
        except Exception as exc:
            log.warning("[hooks] PostSensorUse hook error (%s): %s", hook.command, exc)
