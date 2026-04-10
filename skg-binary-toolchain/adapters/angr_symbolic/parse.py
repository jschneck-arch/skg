#!/usr/bin/env python3
"""
adapter: angr_symbolic
========================================
Uses angr symbolic execution to confirm whether attacker-controlled input
can reach a dangerous function call. Supplements BA-05 (ltrace runtime check)
with static/symbolic verification that does not require executing the binary.

Collection pipeline:
  1. SSH/SFTP to target, download binary to local temp file
  2. Load in angr (auto_load_libs=False for speed)
  3. CFGFast → identify callers of dangerous functions in the call graph
  4. Symbolic exploration from program entry toward dangerous call addresses
  5. Emit BA-09; elevate BA-05 confidence if path confirmed

Wicket map:
  BA-09  symbolic_vuln_path_confirmed  angr found a feasible stdin-controlled
                                       execution path to a dangerous function

Evidence ranks:
  rank 2 = harvested (symbolic analysis; no live execution on target)

Performance constraints:
  - CFGFast only (not CFGEmulated) — sub-second on most binaries
  - Exploration capped at MAX_STEPS states and EXPLORE_TIMEOUT seconds
  - auto_load_libs=False prevents loading system libraries (fast + reproducible)

Usage:
  python parse.py \\
    --host 192.168.1.50 --user root --key ~/.ssh/id_rsa \\
    --binary /usr/local/bin/target_app \\
    --out /tmp/angr_events.ndjson \\
    --attack-path-id binary_symbolic_confirmed_v1 \\
    --workload-id vuln-binary-host
"""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-binary-toolchain"
SOURCE_ID = "adapter.angr_symbolic"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

EXPLORE_TIMEOUT = 60   # seconds for symbolic exploration
MAX_STEPS = 2_000      # max simulation steps before giving up

_DANGEROUS_FUNCS = frozenset({
    "strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf",
    "strncpy", "strncat", "system", "popen",
    "execv", "execve", "execvp", "execl", "execlp", "execle",
})


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
# angr analysis
# ---------------------------------------------------------------------------

def _find_dangerous_addrs(proj) -> dict[int, str]:
    """Return {addr: func_name} for dangerous functions found in PLT/imports."""
    found: dict[int, str] = {}

    # Check PLT stubs (most common for dynamically linked binaries)
    plt = getattr(proj.loader.main_object, "plt", {})
    for name, addr in plt.items():
        if name in _DANGEROUS_FUNCS and addr:
            found[addr] = name

    # Check exported symbols (for statically linked binaries)
    for sym in proj.loader.main_object.symbols:
        if sym.name in _DANGEROUS_FUNCS and sym.rebased_addr:
            found[sym.rebased_addr] = sym.name

    # Also check imports table
    for name in _DANGEROUS_FUNCS:
        sym = proj.loader.find_symbol(name)
        if sym and sym.rebased_addr and sym.rebased_addr not in found:
            found[sym.rebased_addr] = name

    return found


def _cfg_callers(cfg, dangerous_addrs: dict[int, str]) -> dict[str, list[str]]:
    """
    Walk CFG to find functions that call into dangerous addresses.
    Returns {dangerous_func_name: [caller_func_name, ...]}
    """
    callers: dict[str, list[str]] = {}
    addr_to_name = {addr: name for addr, name in dangerous_addrs.items()}

    for func in cfg.functions.values():
        for callee_addr in func.get_call_sites():
            if callee_addr in addr_to_name:
                dname = addr_to_name[callee_addr]
                callers.setdefault(dname, [])
                if func.name not in callers[dname]:
                    callers[dname].append(func.name)

    return callers


class _ExploreResult:
    found: bool = False
    timed_out: bool = False
    confirmed_func: str = ""
    confirmed_addr: int = 0
    error: str = ""


def _symbolic_explore(proj, dangerous_addrs: dict[int, str], timeout: int) -> _ExploreResult:
    """
    Run bounded symbolic exploration from entry state toward dangerous addrs.
    Executed in a daemon thread so we can enforce a wall-clock timeout.
    """
    import angr

    result = _ExploreResult()

    def _work() -> None:
        try:
            state = proj.factory.full_init_state(
                args=[proj.filename],
                add_options={
                    angr.options.LAZY_SOLVES,
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                },
            )
            simgr = proj.factory.simulation_manager(state)
            target_addrs = set(dangerous_addrs.keys())

            simgr.explore(
                find=target_addrs,
                num_find=1,
                step_func=lambda sm: sm if sum(len(s) for s in sm.stashes.values()) < MAX_STEPS else sm.move("active", "deadended"),
            )

            if simgr.found:
                found_state = simgr.found[0]
                pc = found_state.solver.eval(found_state.regs.ip)
                result.found = True
                result.confirmed_addr = pc
                result.confirmed_func = dangerous_addrs.get(pc, "unknown")
        except Exception as exc:
            result.error = str(exc)[:200]

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        result.timed_out = True

    return result


# ---------------------------------------------------------------------------
# Check function
# ---------------------------------------------------------------------------

def check_ba_09(
    local_binary: Path,
    out: Path,
    binary: str,
    apid: str,
    run_id: str,
    wid: str,
    explore_timeout: int = EXPLORE_TIMEOUT,
) -> None:
    """BA-09: symbolic_vuln_path_confirmed."""
    pointer = f"binary://{binary}/angr"

    try:
        import angr  # noqa: F401
    except ImportError:
        _emit(out, "BA-09", "unknown", 2, "angr", pointer, 0.15, apid, run_id, wid,
              "angr not installed; symbolic path analysis skipped. Install with: pip install angr")
        return

    import angr as _angr

    try:
        proj = _angr.Project(str(local_binary), auto_load_libs=False,
                             load_options={"rebase_granularity": 0x1000})
    except Exception as exc:
        _emit(out, "BA-09", "unknown", 2, "angr", pointer, 0.20, apid, run_id, wid,
              f"angr failed to load binary: {exc!s:.200}",
              {"load_error": str(exc)[:200]})
        return

    # Phase 1: CFGFast to find dangerous function addresses and their callers
    try:
        cfg = proj.analyses.CFGFast(resolve_indirect_jumps=False, force_complete_scan=False)
    except Exception as exc:
        _emit(out, "BA-09", "unknown", 2, "angr", pointer, 0.20, apid, run_id, wid,
              f"CFGFast failed: {exc!s:.200}")
        return

    dangerous_addrs = _find_dangerous_addrs(proj)
    if not dangerous_addrs:
        _emit(out, "BA-09", "blocked", 2, "angr", pointer, 0.75, apid, run_id, wid,
              "angr found no dangerous function symbols/PLT entries; "
              "binary may be statically linked, stripped, or free of dangerous calls.",
              {"dangerous_funcs_checked": sorted(_DANGEROUS_FUNCS)})
        return

    callers = _cfg_callers(cfg, dangerous_addrs)
    if not callers:
        _emit(out, "BA-09", "blocked", 2, "angr", pointer, 0.70, apid, run_id, wid,
              "Dangerous functions present in binary but CFG shows no callers — "
              "possibly dead code or indirect dispatch only.",
              {"dangerous_addrs_found": {v: hex(k) for k, v in dangerous_addrs.items()}})
        return

    # Phase 2: Symbolic exploration toward dangerous call sites
    result = _symbolic_explore(proj, dangerous_addrs, explore_timeout)

    if result.timed_out:
        # CFG callers were found but symbolic exploration timed out — partial evidence
        caller_summary = {k: v[:5] for k, v in callers.items()}
        _emit(out, "BA-09", "unknown", 2, "angr", pointer, 0.55, apid, run_id, wid,
              f"Symbolic exploration timed out after {explore_timeout}s. "
              f"CFG callers of dangerous functions found: {caller_summary}. "
              f"Path reachability probable but not symbolically confirmed.",
              {
                  "timed_out": True,
                  "explore_timeout_s": explore_timeout,
                  "cfg_callers": caller_summary,
                  "dangerous_funcs": list(dangerous_addrs.values()),
              })
        return

    if result.error:
        _emit(out, "BA-09", "unknown", 2, "angr", pointer, 0.25, apid, run_id, wid,
              f"angr exploration error: {result.error}",
              {"error": result.error})
        return

    if result.found:
        caller_summary = {k: v[:5] for k, v in callers.items()}
        _emit(out, "BA-09", "realized", 2, "angr", pointer, 0.90, apid, run_id, wid,
              f"Symbolic execution found feasible path from program entry to "
              f"'{result.confirmed_func}' (@ {hex(result.confirmed_addr)}). "
              f"Attacker-controlled stdin may reach dangerous call.",
              {
                  "confirmed_func": result.confirmed_func,
                  "confirmed_addr": hex(result.confirmed_addr),
                  "cfg_callers": caller_summary,
                  "dangerous_funcs": list(dangerous_addrs.values()),
              })
    else:
        _emit(out, "BA-09", "blocked", 2, "angr", pointer, 0.65, apid, run_id, wid,
              "Symbolic exploration completed without finding a path to dangerous functions. "
              "Constraints may prevent exploitation under standard input models.",
              {
                  "cfg_callers": {k: v[:5] for k, v in callers.items()},
                  "dangerous_funcs": list(dangerous_addrs.values()),
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
    attack_path_id: str = "binary_symbolic_confirmed_v1",
) -> list[dict]:
    """
    Programmatic entry point. Downloads binary via SFTP, runs angr locally,
    returns BA-09 events.
    """
    import paramiko

    try:
        import angr  # noqa: F401
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
                "find / -perm -4000 -type f 2>/dev/null | head -8", timeout=20
            )
            candidates = [l.strip() for l in out.read().decode("utf-8", errors="replace").splitlines() if l.strip()]
        except Exception:
            candidates = []
    if not candidates:
        candidates = ["/bin/su"]

    all_events: list[dict] = []
    sftp = client.open_sftp()

    for bin_path in candidates:
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tf:
            local_path = Path(tf.name)
        out_path = local_path.with_suffix(".ndjson")
        try:
            sftp.get(bin_path, str(local_path))
            check_ba_09(local_path, out_path, bin_path, attack_path_id, run_id, workload_id)
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
            local_path.unlink(missing_ok=True)
            out_path.unlink(missing_ok=True)

    sftp.close()
    client.close()
    return all_events


def main() -> None:
    p = argparse.ArgumentParser(
        description="angr symbolic adapter — emits BA-09 wicket events."
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
    p.add_argument("--explore-timeout", type=int, default=EXPLORE_TIMEOUT, dest="explore_timeout")
    args = p.parse_args()

    run_id      = args.run_id      or str(uuid.uuid4())
    workload_id = args.workload_id or f"{args.host}:{args.binary}"
    out_path    = Path(args.out)

    events = run(
        args.host, args.user, workload_id, run_id,
        password=args.password, key=args.key,
        ssh_port=args.port, timeout=args.timeout,
        binary=args.binary, attack_path_id=args.attack_path_id,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    print(f"[angr_symbolic] {len(events)} events written to {out_path}")


if __name__ == "__main__":
    main()
