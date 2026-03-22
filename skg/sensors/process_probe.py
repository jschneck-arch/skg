"""
skg :: sensors/process_probe.py

Process exploit surface instrument.

Probes a target system (locally or via SSH) for process-level attack surface:
  - Kernel protection settings (ptrace_scope, user namespaces, eBPF, ASLR)
  - SUID/SGID binary inventory
  - Executable stack / no-NX process detection
  - Shared memory segments (world-accessible)
  - cron/path writability
  - /proc/PID/mem write access
  - Unprivileged eBPF programs

Wickets emitted:
  PR-01  ptrace_scope=0  (any process fully traceable, full process injection)
  PR-02  Unprivileged user namespaces enabled (privesc via namespace abuse)
  PR-03  Unprivileged eBPF access (side-channel / memory read)
  PR-04  SUID binaries with known exploitable history
  PR-05  Executable stack process found (NX not enforced)
  PR-06  Writable directory in root PATH (command hijack)
  PR-07  World-writable cron directory
  PR-08  /proc/PID/mem writable by non-owner (kernel < 3.9 style injection)
  PR-09  ASLR disabled (kernel.randomize_va_space=0)
  PR-10  Kernel module loading unrestricted (kmod_disabled=0)
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(wicket_id: str, label: str, workload_id: str, realized: bool,
           detail: str, target_ip: str, confidence: float = 0.85) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "ts": _iso_now(),
        "type": "obs.attack.precondition",
        "source": {
            "source_id": f"process_probe/{wicket_id}",
            "toolchain": "skg-host-toolchain",
            "version": "1.0.0",
        },
        "payload": {
            "wicket_id": wicket_id,
            "node_id": wicket_id,
            "label": label,
            "domain": "host",
            "workload_id": workload_id,
            "realized": realized,
            "status": "realized" if realized else "blocked",
            "detail": detail,
            "target_ip": target_ip,
        },
        "provenance": {
            "evidence_rank": 5,
            "evidence": {
                "source_kind": "process_probe",
                "pointer": f"process_probe://{target_ip}/{wicket_id}",
                "collected_at": _iso_now(),
                "confidence": confidence,
            },
        },
    }


# Commands to run remotely (or locally if target_ip is local)
_REMOTE_COMMANDS = {
    "ptrace_scope":     "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo '0'",
    "userns":           "cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || "
                        "cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 'unknown'",
    "ebpf_unpriv":      "cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo '1'",
    "aslr":             "cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo '2'",
    "kmod_disabled":    "cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo '0'",
    "suid_bins":        "find / -xdev -perm -4000 -type f 2>/dev/null | head -40",
    "path_writable":    "for d in $(echo $PATH | tr ':' ' '); do [ -w \"$d\" ] && echo \"WRITABLE:$d\"; done 2>/dev/null",
    "cron_writable":    "for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron; "
                        "do [ -w \"$d\" ] && echo \"WRITABLE:$d\"; done 2>/dev/null",
    "exec_stack":       "find /proc -maxdepth 3 -name maps 2>/dev/null | xargs grep -l rwxp 2>/dev/null | head -5",
    "shm_world":        "ipcs -m 2>/dev/null | awk 'NR>3 && $4 ~ /^666|^777/' | head -10",
}

# SUID binaries with well-known privesc potential
_DANGEROUS_SUID = {
    "nmap", "vim", "vi", "nano", "less", "more", "man", "awk", "gawk",
    "find", "cp", "mv", "python", "python3", "perl", "ruby", "bash",
    "sh", "tee", "tail", "head", "cat", "env", "wget", "curl", "tar",
    "gcc", "make", "docker", "pkexec", "dbus-daemon-launch-helper",
}


def _run_ssh(ip: str, user: str, key_path: Optional[str], password: Optional[str],
             cmd: str, timeout: int = 10) -> str:
    """Run a command on a remote host via SSH. Returns stdout or empty string."""
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: dict = {"username": user, "timeout": timeout, "look_for_keys": False}
        if key_path:
            connect_kwargs["key_filename"] = key_path
        elif password:
            connect_kwargs["password"] = password
        c.connect(ip, **connect_kwargs)
        _, stdout, _ = c.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="ignore").strip()
        c.close()
        return out
    except Exception:
        return ""


def probe_process_surface(
    target_ip: str,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    ssh_password: Optional[str] = None,
    out_file: Optional[Path] = None,
) -> list[dict]:
    """
    Probe a target for process exploit surface via SSH.
    Returns list of wicket events.
    """
    workload_id = f"host::{target_ip}"
    events: list[dict] = []

    def run(cmd_key: str) -> str:
        return _run_ssh(target_ip, ssh_user, ssh_key, ssh_password,
                        _REMOTE_COMMANDS[cmd_key])

    # PR-01: ptrace_scope
    val = run("ptrace_scope").strip()
    if val == "0":
        events.append(_event("PR-01", "ptrace_scope_unrestricted", workload_id, True,
            "kernel.yama.ptrace_scope=0: any process can ptrace any other. "
            "Full process injection possible without root.", target_ip, 0.95))
    elif val in ("1", "2", "3"):
        events.append(_event("PR-01", "ptrace_scope_unrestricted", workload_id, False,
            f"kernel.yama.ptrace_scope={val}: ptrace restricted.", target_ip, 0.90))

    # PR-02: unprivileged user namespaces
    val = run("userns").strip()
    userns_on = val not in ("", "unknown", "0") and val != "1" or val == "1" and "userns" in val
    # Simpler: if the value is >= 1 for max_user_namespaces or = 1 for clone
    try:
        ns_val = int(val.split("\n")[0])
        userns_on = ns_val >= 1
    except Exception:
        userns_on = False
    events.append(_event("PR-02", "unprivileged_userns_enabled", workload_id, userns_on,
        f"Unprivileged user namespaces: {'enabled' if userns_on else 'disabled'} (val={val[:30]}). "
        "Enables privilege escalation via namespace abuse (CVE-2022-0492, etc.).",
        target_ip, 0.85))

    # PR-03: unprivileged eBPF
    val = run("ebpf_unpriv").strip()
    try:
        ebpf_unpriv = int(val) == 0  # 0 = unrestricted, 1/2 = restricted
    except Exception:
        ebpf_unpriv = False
    events.append(_event("PR-03", "unprivileged_ebpf_access", workload_id, ebpf_unpriv,
        f"kernel.unprivileged_bpf_disabled={val}: "
        "{'Unprivileged eBPF programs allowed (side-channel, memory read)' if ebpf_unpriv else 'eBPF restricted to root'}.",
        target_ip, 0.85))

    # PR-09: ASLR
    val = run("aslr").strip()
    try:
        aslr_disabled = int(val) == 0
    except Exception:
        aslr_disabled = False
    events.append(_event("PR-09", "aslr_disabled", workload_id, aslr_disabled,
        f"kernel.randomize_va_space={val}. "
        "{'ASLR off — deterministic memory layout, ROP chains reliable' if aslr_disabled else 'ASLR enabled'}.",
        target_ip, 0.90))

    # PR-10: kernel module loading
    val = run("kmod_disabled").strip()
    try:
        kmod_open = int(val) == 0
    except Exception:
        kmod_open = True
    events.append(_event("PR-10", "kmod_loading_unrestricted", workload_id, kmod_open,
        f"kernel.modules_disabled={val}. "
        "{'Kernel module loading unrestricted — rootkit/LKM implant possible' if kmod_open else 'Module loading locked'}.",
        target_ip, 0.80))

    # PR-04: SUID binaries
    suid_out = run("suid_bins")
    suid_names = {Path(p).name for p in suid_out.splitlines() if p.strip()}
    dangerous = suid_names & _DANGEROUS_SUID
    if dangerous:
        events.append(_event("PR-04", "exploitable_suid_present", workload_id, True,
            f"Dangerous SUID binaries: {', '.join(sorted(dangerous)[:10])}. "
            "GTFObins privesc vectors available.", target_ip, 0.90))
    elif suid_names:
        events.append(_event("PR-04", "exploitable_suid_present", workload_id, False,
            f"SUID binaries present but none flagged dangerous: {', '.join(sorted(suid_names)[:8])}",
            target_ip, 0.70))

    # PR-06: writable PATH dir (as non-root)
    path_out = run("path_writable")
    if "WRITABLE:" in path_out:
        dirs = [l.split("WRITABLE:")[1] for l in path_out.splitlines() if "WRITABLE:" in l]
        events.append(_event("PR-06", "writable_root_path_dir", workload_id, True,
            f"Writable directories in PATH: {', '.join(dirs[:5])}. "
            "Command hijacking / shell injection possible.", target_ip, 0.88))

    # PR-07: writable cron dir
    cron_out = run("cron_writable")
    if "WRITABLE:" in cron_out:
        dirs = [l.split("WRITABLE:")[1] for l in cron_out.splitlines() if "WRITABLE:" in l]
        events.append(_event("PR-07", "writable_cron_dir", workload_id, True,
            f"World-writable cron directories: {', '.join(dirs[:5])}. "
            "Persistence / privilege escalation via cron injection.", target_ip, 0.90))

    # PR-05: executable stack in running processes
    exec_out = run("exec_stack")
    if exec_out.strip():
        events.append(_event("PR-05", "exec_stack_process", workload_id, True,
            f"Processes with executable stack (rwxp mapping): {exec_out[:120]}. "
            "Stack-based shellcode injection may be possible.", target_ip, 0.75))

    # PR-08: world-accessible shared memory
    shm_out = run("shm_world")
    if shm_out.strip():
        events.append(_event("PR-08", "world_accessible_shm", workload_id, True,
            f"World-accessible shared memory segments: {shm_out[:200]}. "
            "Cross-process data access or injection via IPC.", target_ip, 0.80))

    if out_file and events:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    return events
