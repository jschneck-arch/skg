#!/usr/bin/env python3
"""
adapter: binary_analysis (ssh_collect)
========================================
Runs binary exploitation precondition checks against a target binary via SSH.

Collection pipeline:
  1. SSH to host, copy binary locally if not already accessible
  2. Run checksec, rabin2/readelf, ROPgadget, ltrace (whichever are available)
  3. Parse output → emit BA-01..BA-06 wicket events

Wicket map:
  BA-01  nx_disabled                   checksec NX: disabled
  BA-02  aslr_disabled_or_weak         PIE: No or /proc/sys/kernel/randomize_va_space < 2
  BA-03  no_stack_canary               Canary: No
  BA-04  dangerous_function_imported   rabin2/nm finds strcpy/gets/sprintf/system/exec*
  BA-05  controlled_input_reaches_call ltrace shows dangerous call during controlled input
  BA-06  exploit_chain_constructible   ROPgadget finds ≥ 20 ROP gadgets OR cyclic EIP confirmed

Evidence ranks:
  rank 1 = runtime (ltrace, cyclic crash)
  rank 2 = harvested (import table, dynamic analysis)
  rank 3 = config/binary attributes (checksec, readelf)
  rank 4 = network (not used here)

Usage:
  python parse.py \\
    --host 192.168.1.50 --user root --key ~/.ssh/id_rsa \\
    --binary /usr/local/bin/target_app \\
    --out /tmp/binary_events.ndjson \\
    --attack-path-id binary_stack_overflow_v1 \\
    --workload-id vuln-binary-host
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-binary-toolchain"
SOURCE_ID = "adapter.binary_analysis"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

_DANGEROUS_FUNCS = re.compile(
    r'\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|strncpy|strncat|'
    r'system|popen|execv|execve|execvp|execl|execlp)\b'
)


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, source_kind: str, pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         notes: str = "", attributes: dict = None) -> None:
    now = iso_now()
    payload = {
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
            "version": get_version(),
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


def _run(ssh, cmd: str, timeout: int = 30) -> str:
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def _is_error(val: str) -> bool:
    return not val or val.startswith("ERROR:")


def _tool_available(ssh, tool: str) -> bool:
    out = _run(ssh, f"command -v {tool} 2>/dev/null")
    return bool(out) and not out.startswith("ERROR:")


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def collect(ssh, binary_path: str, timeout: int = 30) -> dict:
    """Run all collection commands. Returns raw output keyed by check name."""
    c: dict[str, str] = {}

    # File exists and is ELF
    c["file_type"] = _run(ssh, f"file '{binary_path}' 2>/dev/null")

    # checksec (python-pwntools checksec or standalone)
    if _tool_available(ssh, "checksec"):
        c["checksec"] = _run(ssh, f"checksec --file='{binary_path}' 2>/dev/null", timeout)
    else:
        # Fall back: read ELF headers with readelf
        c["checksec"] = ""
        c["readelf_s"] = _run(ssh, f"readelf -s '{binary_path}' 2>/dev/null | head -60")
        c["readelf_d"] = _run(ssh, f"readelf -d '{binary_path}' 2>/dev/null | grep -i 'flags\\|gnu_relro\\|bind_now'")
        c["readelf_n"] = _run(ssh, f"readelf -n '{binary_path}' 2>/dev/null | head -20")

    # ASLR system setting
    c["aslr_setting"] = _run(ssh, "cat /proc/sys/kernel/randomize_va_space 2>/dev/null")

    # Import table: dangerous functions
    if _tool_available(ssh, "rabin2"):
        c["imports"] = _run(ssh, f"rabin2 -i '{binary_path}' 2>/dev/null")
    elif _tool_available(ssh, "nm"):
        c["imports"] = _run(ssh, f"nm -D '{binary_path}' 2>/dev/null || strings '{binary_path}' | grep -E 'strcpy|gets|sprintf|system|exec'")
    else:
        c["imports"] = _run(ssh, f"strings '{binary_path}' 2>/dev/null | grep -E 'strcpy|strcat|gets|sprintf|vsprintf|scanf|system|popen|exec'")

    # ROP gadgets
    if _tool_available(ssh, "ROPgadget"):
        c["rop_gadgets"] = _run(ssh, f"ROPgadget --binary '{binary_path}' --rop 2>/dev/null | tail -5", timeout=60)
    elif _tool_available(ssh, "ropper"):
        c["rop_gadgets"] = _run(ssh, f"ropper -f '{binary_path}' --type rop 2>/dev/null | tail -5", timeout=60)
    else:
        c["rop_gadgets"] = ""

    # ltrace with controlled input (safe: /dev/null as stdin, no harmful input)
    if _tool_available(ssh, "ltrace"):
        c["ltrace"] = _run(ssh,
            f"echo '' | ltrace -e 'strcpy+strcat+gets+sprintf+vsprintf+system+popen+exec*' "
            f"'{binary_path}' </dev/null 2>&1 | head -30",
            timeout=15,
        )
    else:
        c["ltrace"] = ""

    return c


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_ba_01(c: dict, out: Path, apid: str, run_id: str, wid: str, binary: str) -> None:
    """BA-01: nx_disabled — NX/DEP not set; stack memory is executable."""
    checksec = c.get("checksec", "")
    readelf_n = c.get("readelf_n", "")
    readelf_d = c.get("readelf_d", "")
    pointer = f"binary://{binary}/checksec"

    if checksec and not _is_error(checksec):
        nx_disabled = bool(re.search(r'NX\s*[:\s]+disabled', checksec, re.I))
        nx_enabled  = bool(re.search(r'NX\s*[:\s]+enabled',  checksec, re.I))
        if nx_disabled:
            emit(out, "BA-01", "realized", 3, "checksec", pointer, 0.95, apid, run_id, wid,
                 "checksec: NX disabled — stack/heap memory is executable.",
                 {"checksec_snippet": checksec[:300]})
        elif nx_enabled:
            emit(out, "BA-01", "blocked", 3, "checksec", pointer, 0.95, apid, run_id, wid,
                 "checksec: NX enabled — non-executable stack protection active.",
                 {"checksec_snippet": checksec[:300]})
        else:
            emit(out, "BA-01", "unknown", 3, "checksec", pointer, 0.40, apid, run_id, wid,
                 "checksec output did not contain NX status.")
        return

    # Fallback: readelf PT_GNU_STACK
    if readelf_n and not _is_error(readelf_n):
        # GNU_STACK with flags RWE = executable, RW = not executable
        m = re.search(r'GNU_STACK.*?([RWE]+)', readelf_n, re.I)
        if m:
            flags = m.group(1)
            if "E" in flags:
                emit(out, "BA-01", "realized", 3, "readelf", pointer, 0.85, apid, run_id, wid,
                     f"GNU_STACK segment has execute flag ({flags}); NX disabled.",
                     {"gnu_stack_flags": flags})
            else:
                emit(out, "BA-01", "blocked", 3, "readelf", pointer, 0.85, apid, run_id, wid,
                     f"GNU_STACK segment lacks execute flag ({flags}); NX enabled.",
                     {"gnu_stack_flags": flags})
            return

    emit(out, "BA-01", "unknown", 3, "readelf", pointer, 0.30, apid, run_id, wid,
         "checksec unavailable and readelf did not yield NX status.")


def check_ba_02(c: dict, out: Path, apid: str, run_id: str, wid: str, binary: str) -> None:
    """BA-02: aslr_disabled_or_weak — PIE disabled or system ASLR < 2."""
    checksec = c.get("checksec", "")
    aslr     = c.get("aslr_setting", "").strip()
    pointer  = f"binary://{binary}/aslr"

    aslr_val = None
    if aslr and not _is_error(aslr) and aslr.isdigit():
        aslr_val = int(aslr)

    pie_disabled = None
    if checksec and not _is_error(checksec):
        if re.search(r'PIE\s*[:\s]+(?:No PIE|disabled|no)', checksec, re.I):
            pie_disabled = True
        elif re.search(r'PIE\s*[:\s]+(?:enabled|PIE enabled)', checksec, re.I):
            pie_disabled = False

    if pie_disabled is True or (aslr_val is not None and aslr_val < 2):
        reason_parts = []
        if pie_disabled:
            reason_parts.append("PIE disabled (fixed load address)")
        if aslr_val is not None and aslr_val < 2:
            reason_parts.append(f"system ASLR={aslr_val} (full ASLR requires 2)")
        emit(out, "BA-02", "realized", 3, "checksec+procfs", pointer, 0.90, apid, run_id, wid,
             "; ".join(reason_parts) + " — load address is predictable.",
             {"pie_disabled": pie_disabled, "aslr_setting": aslr_val})
    elif pie_disabled is False and (aslr_val is None or aslr_val >= 2):
        emit(out, "BA-02", "blocked", 3, "checksec+procfs", pointer, 0.90, apid, run_id, wid,
             "PIE enabled and system ASLR=2; load address randomised.",
             {"pie_disabled": False, "aslr_setting": aslr_val})
    else:
        emit(out, "BA-02", "unknown", 3, "checksec+procfs", pointer, 0.40, apid, run_id, wid,
             "Could not determine PIE/ASLR status.",
             {"aslr_raw": aslr, "checksec_available": bool(checksec and not _is_error(checksec))})


def check_ba_03(c: dict, out: Path, apid: str, run_id: str, wid: str, binary: str) -> None:
    """BA-03: no_stack_canary — stack canary absent; overflow reaches return address."""
    checksec = c.get("checksec", "")
    pointer  = f"binary://{binary}/checksec"

    if not checksec or _is_error(checksec):
        emit(out, "BA-03", "unknown", 3, "checksec", pointer, 0.30, apid, run_id, wid,
             "checksec not available; cannot determine canary status.")
        return

    if re.search(r'Canary\s*[:\s]+(?:No canary|disabled|no\b)', checksec, re.I):
        emit(out, "BA-03", "realized", 3, "checksec", pointer, 0.95, apid, run_id, wid,
             "checksec: No stack canary — buffer overflow reaches return address directly.",
             {"checksec_snippet": checksec[:300]})
    elif re.search(r'Canary\s*[:\s]+(?:Canary found|enabled|yes\b)', checksec, re.I):
        emit(out, "BA-03", "blocked", 3, "checksec", pointer, 0.95, apid, run_id, wid,
             "checksec: Stack canary present.",
             {"checksec_snippet": checksec[:300]})
    else:
        emit(out, "BA-03", "unknown", 3, "checksec", pointer, 0.40, apid, run_id, wid,
             "Canary status ambiguous in checksec output.",
             {"checksec_snippet": checksec[:200]})


def check_ba_04(c: dict, out: Path, apid: str, run_id: str, wid: str, binary: str) -> None:
    """BA-04: dangerous_function_imported — imports strcpy/gets/system/exec*."""
    imports  = c.get("imports", "")
    pointer  = f"binary://{binary}/imports"

    if _is_error(imports):
        emit(out, "BA-04", "unknown", 2, "rabin2_imports", pointer, 0.30, apid, run_id, wid,
             "Could not read binary import table; rabin2/nm/strings unavailable.")
        return

    found = sorted(set(_DANGEROUS_FUNCS.findall(imports)))
    if found:
        emit(out, "BA-04", "realized", 2, "rabin2_imports", pointer, 0.90, apid, run_id, wid,
             f"Dangerous function(s) imported: {', '.join(found)}",
             {"dangerous_functions": found, "import_snippet": imports[:400]})
    else:
        emit(out, "BA-04", "blocked", 2, "rabin2_imports", pointer, 0.80, apid, run_id, wid,
             "No known dangerous functions found in import table.",
             {"checked_functions": _DANGEROUS_FUNCS.pattern[:80]})


def check_ba_05(c: dict, out: Path, apid: str, run_id: str, wid: str, binary: str) -> None:
    """BA-05: controlled_input_reaches_dangerous_call — ltrace shows dangerous call."""
    ltrace  = c.get("ltrace", "")
    imports = c.get("imports", "")
    pointer = f"binary://{binary}/ltrace"

    if not ltrace or _is_error(ltrace):
        # No ltrace: downgrade to unknown, note that BA-04 provides partial coverage
        if imports and not _is_error(imports) and _DANGEROUS_FUNCS.search(imports):
            emit(out, "BA-05", "unknown", 1, "ltrace", pointer, 0.40, apid, run_id, wid,
                 "ltrace unavailable; dangerous imports exist (see BA-04) but dynamic "
                 "reachability from user input not confirmed.")
        else:
            emit(out, "BA-05", "unknown", 1, "ltrace", pointer, 0.25, apid, run_id, wid,
                 "ltrace unavailable and no dangerous imports found; cannot assess.")
        return

    # ltrace output: look for dangerous function calls in the trace
    called = sorted(set(_DANGEROUS_FUNCS.findall(ltrace)))
    if called:
        emit(out, "BA-05", "realized", 1, "ltrace", pointer, 0.85, apid, run_id, wid,
             f"ltrace confirmed call to dangerous function(s) during execution: {', '.join(called)}",
             {"called_functions": called, "ltrace_snippet": ltrace[:400]})
    else:
        # ltrace ran but didn't intercept dangerous calls with /dev/null input
        emit(out, "BA-05", "unknown", 1, "ltrace", pointer, 0.50, apid, run_id, wid,
             "ltrace ran but no dangerous function calls intercepted with empty input; "
             "manual testing with controlled payload required.",
             {"ltrace_snippet": ltrace[:200]})


def check_ba_06(c: dict, out: Path, apid: str, run_id: str, wid: str, binary: str) -> None:
    """BA-06: exploit_chain_constructible — sufficient ROP gadgets or EIP control confirmed."""
    rop     = c.get("rop_gadgets", "")
    pointer = f"binary://{binary}/rop_gadgets"

    if not rop or _is_error(rop):
        emit(out, "BA-06", "unknown", 3, "ROPgadget", pointer, 0.25, apid, run_id, wid,
             "ROPgadget/ropper not available; cannot assess ROP chain constructibility.")
        return

    # ROPgadget output ends with "Unique gadgets found: N"
    m = re.search(r'Unique gadgets found[:\s]+(\d+)', rop, re.I)
    if m:
        count = int(m.group(1))
        if count >= 20:
            emit(out, "BA-06", "realized", 3, "ROPgadget", pointer, 0.85, apid, run_id, wid,
                 f"{count} unique ROP gadgets found — sufficient for chain construction.",
                 {"rop_gadget_count": count, "rop_snippet": rop[:300]})
        elif count >= 5:
            emit(out, "BA-06", "unknown", 3, "ROPgadget", pointer, 0.55, apid, run_id, wid,
                 f"{count} ROP gadgets found — marginal; chain may require ret2libc or external gadgets.",
                 {"rop_gadget_count": count})
        else:
            emit(out, "BA-06", "blocked", 3, "ROPgadget", pointer, 0.70, apid, run_id, wid,
                 f"Only {count} ROP gadgets found — insufficient for practical chain.",
                 {"rop_gadget_count": count})
    else:
        # Fallback: count lines that look like gadgets
        gadget_lines = [l for l in rop.splitlines() if "0x" in l and ":" in l]
        count = len(gadget_lines)
        if count >= 20:
            emit(out, "BA-06", "realized", 3, "ROPgadget", pointer, 0.75, apid, run_id, wid,
                 f"~{count} ROP gadget lines in output (summary not found).",
                 {"rop_lines_approx": count})
        else:
            emit(out, "BA-06", "unknown", 3, "ROPgadget", pointer, 0.40, apid, run_id, wid,
                 "ROP gadget count unclear; manual review needed.",
                 {"rop_snippet": rop[:200]})


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def run_checks(c: dict, out: Path, attack_path_id: str,
               run_id: str, workload_id: str, binary: str) -> None:
    check_ba_01(c, out, attack_path_id, run_id, workload_id, binary)
    check_ba_02(c, out, attack_path_id, run_id, workload_id, binary)
    check_ba_03(c, out, attack_path_id, run_id, workload_id, binary)
    check_ba_04(c, out, attack_path_id, run_id, workload_id, binary)
    check_ba_05(c, out, attack_path_id, run_id, workload_id, binary)
    check_ba_06(c, out, attack_path_id, run_id, workload_id, binary)


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
    attack_path_id: str = "binary_stack_overflow_v1",
) -> list[dict]:
    """
    Programmatic entry point called by gravity_field._exec_binary_analysis.

    Connects via SSH, discovers candidate binaries if none specified,
    runs the full BA-01..BA-06 check suite, and returns all events as a list.
    """
    import paramiko
    import tempfile

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw: dict = {"hostname": host, "port": ssh_port,
                        "username": user, "timeout": timeout}
    if key:
        connect_kw["key_filename"] = str(Path(key).expanduser().resolve())
    elif password:
        connect_kw["password"] = password

    try:
        client.connect(**connect_kw)
    except Exception as exc:
        return []

    # Discover candidate binaries if none provided
    candidates: list[str] = []
    if binary:
        candidates = [binary]
    else:
        def _find(cmd: str) -> list[str]:
            try:
                _, out, _ = client.exec_command(cmd, timeout=20)
                return [l.strip() for l in out.read().decode("utf-8", errors="replace").splitlines()
                        if l.strip()]
            except Exception:
                return []

        suid_bins = _find("find / -perm -4000 -type f 2>/dev/null | head -10")
        tmp_bins  = _find("find /tmp /var/tmp -type f -executable 2>/dev/null | head -5")
        candidates = (suid_bins + tmp_bins)[:8] or ["/bin/su"]

    all_events: list[dict] = []
    for bin_path in candidates:
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tf:
            out_path = Path(tf.name)
        try:
            c = collect(client, bin_path, timeout=timeout)
            run_checks(c, out_path, attack_path_id, run_id, workload_id, bin_path)
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
            try:
                out_path.unlink(missing_ok=True)
            except Exception:
                pass

    client.close()
    return all_events


def main() -> None:
    import paramiko

    p = argparse.ArgumentParser(
        description="Binary analysis adapter — emits BA-01..BA-06 wicket events via SSH."
    )
    p.add_argument("--host",           required=True,  help="Target hostname or IP")
    p.add_argument("--user",           required=True,  help="SSH username")
    p.add_argument("--password",       default=None,   help="SSH password")
    p.add_argument("--key",            default=None,   help="Path to SSH private key")
    p.add_argument("--port",           type=int, default=22)
    p.add_argument("--timeout",        type=int, default=30)
    p.add_argument("--binary",         required=True,  help="Absolute path to binary on remote host")
    p.add_argument("--out",            required=True,  help="Output NDJSON file path")
    p.add_argument("--attack-path-id", required=True,  dest="attack_path_id")
    p.add_argument("--workload-id",    default=None,   dest="workload_id")
    p.add_argument("--run-id",         default=None,   dest="run_id")
    args = p.parse_args()

    run_id     = args.run_id     or str(uuid.uuid4())
    workload_id = args.workload_id or f"{args.host}:{args.binary}"
    out_path   = Path(args.out)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw: dict = {
        "hostname": args.host,
        "port": args.port,
        "username": args.user,
        "timeout": args.timeout,
    }
    if args.key:
        connect_kw["key_filename"] = str(Path(args.key).expanduser().resolve())
    elif args.password:
        connect_kw["password"] = args.password

    try:
        client.connect(**connect_kw)
    except Exception as exc:
        print(f"[binary_analysis] SSH connect failed: {exc}")
        raise SystemExit(1)

    try:
        print(f"[binary_analysis] Collecting from {args.host}:{args.binary}")
        collection = collect(client, args.binary, timeout=args.timeout)
        run_checks(collection, out_path, args.attack_path_id, run_id, workload_id, args.binary)
        n = sum(1 for _ in out_path.read_text().splitlines() if _)
        print(f"[binary_analysis] {n} events written to {out_path}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
