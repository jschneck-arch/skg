#!/usr/bin/env python3
"""
adapter: frida_trace
========================================
Uses Frida dynamic instrumentation to hook dangerous function calls at runtime
and inspect argument values. Provides higher-fidelity confirmation than ltrace
(BA-05) by capturing argument types, sizes, and content under controlled input.

REQUIRES authorized=True — this adapter executes the target binary.

Collection pipeline (two modes, tried in order):
  Mode A — Remote frida-server:
    1. SSH to target, check for running frida-server
    2. Connect via Python frida library to remote device
    3. Spawn binary, inject hook agent, capture intercepts
    4. Terminate spawned process

  Mode B — Local execution (binary fetched via SFTP):
    1. SFTP download binary to local temp
    2. Run frida locally against local binary copy
    3. Capture intercepts, clean up

Wicket map:
  BA-10  runtime_hook_confirmed  Frida intercepted ≥ 1 dangerous call;
                                  argument inspection data available

Evidence ranks:
  rank 1 = runtime (live execution, frida intercept — highest fidelity)

Usage:
  python parse.py \\
    --host 192.168.1.50 --user root --key ~/.ssh/id_rsa \\
    --binary /usr/local/bin/target_app \\
    --out /tmp/frida_events.ndjson \\
    --attack-path-id binary_runtime_confirmed_v1 \\
    --workload-id vuln-binary-host \\
    --authorized
"""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-binary-toolchain"
SOURCE_ID = "adapter.frida_trace"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

FRIDA_SERVER_PORT = 27042   # Frida default
HOOK_TIMEOUT = 15           # seconds to wait for hooks after binary spawn

_DANGEROUS_FUNCS = [
    "strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf",
    "strncpy", "strncat", "system", "popen",
    "execv", "execve", "execvp", "execl", "execlp",
]

# Frida JavaScript agent: hooks each dangerous function and sends a message
# with the function name and a safe preview of the first argument.
_HOOK_AGENT = r"""
'use strict';

const dangerous = {hooks};

dangerous.forEach(function(name) {{
    const sym = Module.findExportByName(null, name);
    if (!sym) return;
    Interceptor.attach(sym, {{
        onEnter: function(args) {{
            let arg0 = null;
            try {{
                arg0 = args[0].readCString(128);
            }} catch(_) {{}}
            send({{
                type: 'hook',
                func: name,
                arg0_preview: arg0
            }});
        }}
    }});
}});
""".replace("{hooks}", json.dumps(_DANGEROUS_FUNCS))


def _version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(out_path: Path, wicket_id: str, status: str,
          evidence_rank: int, source_kind: str, pointer: str, confidence: float,
          attack_path_id: str, run_id: str, workload_id: str,
          notes: str = "", attributes: dict | None = None) -> None:
    now = _now()
    payload: dict = {
        "wicket_id": wicket_id,
        "status": status,
        "attack_path_id": attack_path_id,
        "run_id": run_id,
        "workload_id": workload_id,
        "observed_at": now,
        "notes": notes,
    }
    if attributes:
        payload["attributes"] = attributes

    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": _version(),
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": source_kind,
                "pointer": pointer,
                "collected_at": now,
                "confidence": confidence,
            },
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------------------
# Frida device helpers
# ---------------------------------------------------------------------------

def _check_remote_frida_server(ssh, port: int = FRIDA_SERVER_PORT) -> bool:
    """Return True if frida-server appears to be listening on the target."""
    try:
        _, stdout, _ = ssh.exec_command(
            f"ss -tlnp 2>/dev/null | grep {port} || netstat -tlnp 2>/dev/null | grep {port}",
            timeout=10,
        )
        out = stdout.read().decode("utf-8", errors="replace").strip()
        if out:
            return True
        # Also check by process name
        _, stdout2, _ = ssh.exec_command(
            "pgrep -x frida-server 2>/dev/null || pgrep -x frida 2>/dev/null",
            timeout=10,
        )
        return bool(stdout2.read().decode("utf-8", errors="replace").strip())
    except Exception:
        return False


def _run_frida_session(device, binary_path: str, timeout: int) -> list[dict]:
    """
    Spawn binary on device, inject hook agent, collect messages.
    Returns list of hook intercept dicts.
    """
    intercepts: list[dict] = []
    done = threading.Event()

    def _on_message(message: dict, _data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "hook":
                intercepts.append(payload)
        elif message.get("type") == "error":
            done.set()

    pid = None
    session = None
    script = None
    try:
        pid = device.spawn([binary_path], stdio="pipe")
        session = device.attach(pid)
        script = session.create_script(_HOOK_AGENT)
        script.on("message", _on_message)
        script.load()
        device.resume(pid)
        # Give the binary a moment to run and trigger hooks
        done.wait(timeout=timeout)
        time.sleep(min(2, timeout))
    except Exception:
        pass
    finally:
        if script:
            try:
                script.unload()
            except Exception:
                pass
        if pid is not None:
            try:
                device.kill(pid)
            except Exception:
                pass
        if session:
            try:
                session.detach()
            except Exception:
                pass

    return intercepts


# ---------------------------------------------------------------------------
# Check function
# ---------------------------------------------------------------------------

def check_ba_10(
    ssh,
    local_binary: Path | None,
    remote_binary: str,
    out: Path,
    apid: str,
    run_id: str,
    wid: str,
    remote_host: str,
    authorized: bool = False,
    hook_timeout: int = HOOK_TIMEOUT,
) -> None:
    """BA-10: runtime_hook_confirmed."""
    pointer = f"binary://{remote_binary}/frida"

    if not authorized:
        _emit(out, "BA-10", "unknown", 1, "frida", pointer, 0.0, apid, run_id, wid,
              "Frida hook skipped: authorized=False. "
              "Set authorized=True to enable runtime binary execution.")
        return

    try:
        import frida
    except ImportError:
        _emit(out, "BA-10", "unknown", 1, "frida", pointer, 0.15, apid, run_id, wid,
              "frida Python library not installed; runtime hook skipped. "
              "Install with: pip install frida frida-tools")
        return

    import frida

    intercepts: list[dict] = []
    mode_used: str = "none"

    # Mode A: remote frida-server
    if _check_remote_frida_server(ssh):
        try:
            device = frida.get_device_manager().add_remote_device(
                f"{remote_host}:{FRIDA_SERVER_PORT}"
            )
            intercepts = _run_frida_session(device, remote_binary, hook_timeout)
            mode_used = "remote_frida_server"
        except Exception:
            pass

    # Mode B: local execution of SCP'd binary
    if not intercepts and local_binary and local_binary.exists():
        try:
            device = frida.get_local_device()
            intercepts = _run_frida_session(device, str(local_binary), hook_timeout)
            mode_used = "local_frida"
        except Exception:
            pass

    if mode_used == "none" and not intercepts:
        _emit(out, "BA-10", "unknown", 1, "frida", pointer, 0.20, apid, run_id, wid,
              "Frida could not attach (no remote frida-server found; local fallback also failed). "
              "Deploy frida-server on target or ensure local frida is functional.",
              {"remote_host": remote_host, "frida_port": FRIDA_SERVER_PORT})
        return

    if not intercepts:
        _emit(out, "BA-10", "blocked", 1, "frida", pointer, 0.70, apid, run_id, wid,
              f"Frida attached successfully ({mode_used}) but no dangerous function calls "
              f"were intercepted during {hook_timeout}s execution window with empty input. "
              f"Binary may require specific input to trigger vulnerable paths.",
              {"mode": mode_used, "hook_timeout_s": hook_timeout,
               "hooks_installed": _DANGEROUS_FUNCS})
        return

    funcs_hit = sorted({i["func"] for i in intercepts})
    sample_args = [
        {"func": i["func"], "arg0_preview": i.get("arg0_preview")}
        for i in intercepts[:10]
    ]
    confidence = min(0.97, 0.80 + len(funcs_hit) * 0.03)

    _emit(out, "BA-10", "realized", 1, "frida", pointer, confidence, apid, run_id, wid,
          f"Frida intercepted {len(intercepts)} call(s) to {len(funcs_hit)} dangerous function(s) "
          f"via {mode_used}: {', '.join(funcs_hit)}. Argument inspection available.",
          {
              "mode": mode_used,
              "total_intercepts": len(intercepts),
              "functions_hit": funcs_hit,
              "sample_intercepts": sample_args,
              "hook_timeout_s": hook_timeout,
          })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(
    host: str,
    user: str,
    workload_id: str,
    run_id: str,
    *,
    password: str | None = None,
    key: str | None = None,
    ssh_port: int = 22,
    timeout: int = 30,
    binary: str = "",
    attack_path_id: str = "binary_runtime_confirmed_v1",
    authorized: bool = False,
) -> list[dict]:
    """
    Programmatic entry point. Attempts remote frida-server first, then falls back
    to local frida with SFTP-fetched binary. Returns BA-10 events.
    """
    import paramiko

    if not authorized:
        return []

    try:
        import frida  # noqa: F401
    except ImportError:
        return []

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw: dict = {
        "hostname": host, "port": ssh_port,
        "username": user, "timeout": timeout,
    }
    if key:
        connect_kw["key_filename"] = str(Path(key).expanduser().resolve())
    elif password:
        connect_kw["password"] = password

    try:
        client.connect(**connect_kw)
    except Exception:
        return []

    candidates: list[str] = []
    if binary:
        candidates = [binary]
    else:
        try:
            _, out, _ = client.exec_command(
                "find / -perm -4000 -type f 2>/dev/null | head -5", timeout=20
            )
            candidates = [l.strip() for l in out.read().decode("utf-8", errors="replace").splitlines() if l.strip()]
        except Exception:
            candidates = []
    if not candidates:
        candidates = ["/bin/su"]

    all_events: list[dict] = []
    sftp = client.open_sftp()

    for bin_path in candidates:
        local_path: Path | None = None
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tf:
            local_path = Path(tf.name)
        out_path = local_path.with_suffix(".ndjson")
        try:
            try:
                sftp.get(bin_path, str(local_path))
            except Exception:
                local_path = None

            check_ba_10(
                ssh=client,
                local_binary=local_path,
                remote_binary=bin_path,
                out=out_path,
                apid=attack_path_id,
                run_id=run_id,
                wid=workload_id,
                remote_host=host,
                authorized=authorized,
            )

            if out_path.exists():
                for line in out_path.read_text().splitlines():
                    line = line.strip()
                    if line:
                        try:
                            all_events.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            if local_path:
                local_path.unlink(missing_ok=True)
            out_path.unlink(missing_ok=True)

    sftp.close()
    client.close()
    return all_events


def main() -> None:
    p = argparse.ArgumentParser(
        description="frida_trace adapter — emits BA-10 wicket events."
    )
    p.add_argument("--host",           required=True)
    p.add_argument("--user",           required=True)
    p.add_argument("--password",       default=None)
    p.add_argument("--key",            default=None)
    p.add_argument("--port",           type=int, default=22)
    p.add_argument("--timeout",        type=int, default=30)
    p.add_argument("--binary",         required=True)
    p.add_argument("--out",            required=True)
    p.add_argument("--attack-path-id", required=True, dest="attack_path_id")
    p.add_argument("--workload-id",    default=None,  dest="workload_id")
    p.add_argument("--run-id",         default=None,  dest="run_id")
    p.add_argument("--authorized",     action="store_true",
                   help="Must be explicitly set; adapter executes the binary")
    args = p.parse_args()

    run_id      = args.run_id      or str(uuid.uuid4())
    workload_id = args.workload_id or f"{args.host}:{args.binary}"
    out_path    = Path(args.out)

    events = run(
        args.host, args.user, workload_id, run_id,
        password=args.password, key=args.key,
        ssh_port=args.port, timeout=args.timeout,
        binary=args.binary, attack_path_id=args.attack_path_id,
        authorized=args.authorized,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    print(f"[frida_trace] {len(events)} events written to {out_path}")


if __name__ == "__main__":
    main()
