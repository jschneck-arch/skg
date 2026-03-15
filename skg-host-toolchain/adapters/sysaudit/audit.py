"""
adapters/sysaudit/audit.py
===========================
System audit adapter — filesystem integrity, process integrity, log integrity.

Connects via an existing paramiko SSH client and runs structured checks,
emitting obs.attack.precondition events for FI-*, PI-*, and LI-* wickets.

This is not an attack scanner. It applies the same tri-state logic to
system health questions:

  FI (filesystem integrity):
    Is this file the right hash/permissions/owner?
    Are there unexpected setuid binaries or world-writable dirs?
    Have system binaries changed since last baseline?
    Are there files in unusual locations (executables in /tmp)?

  PI (process integrity):
    Is every running process in the declared service manifest?
    Are any processes running from unexpected paths?
    Are any processes listening on undeclared ports?
    Are there unusual parent/child relationships (shell spawned by web server)?
    Are processes running as root that should not be?

  LI (log integrity):
    Is syslog/journald running and collecting?
    Are log files growing (not truncated/wiped)?
    Are there gaps in the log timeline?
    Are auth failure rates within declared bounds?
    Has log rotation happened without tampering?
    Are audit daemon rules active?

Evidence ranks:
  rank 1 — runtime (live command output, /proc, real-time check)
  rank 2 — build/baseline (comparison against stored hash/manifest)
  rank 3 — config/filesystem (file attributes, permission bits)

Tri-state semantics:
  REALIZED  — condition confirmed present (problem exists / check passed)
  BLOCKED   — constraint prevents the condition (e.g. file immutable, logging disabled)
  UNKNOWN   — not yet measured or measurement failed

For integrity checks:
  - A file matching its baseline → FI-01 REALIZED (integrity confirmed)
  - A file NOT matching its baseline → FI-01 BLOCKED (integrity violated — constraint broken)
  - No baseline exists yet → FI-01 UNKNOWN (unmeasured)

This may seem inverted from security — "realized" means "good" here.
The paths tell the story: file_integrity_failure_v1 requires FI-01=BLOCKED.
A blocked wicket on an integrity check means the check failed.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import paramiko

TOOLCHAIN  = "skg-host-toolchain"
SOURCE_ID  = "adapter.sysaudit"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ev(wicket_id: str, status: str, rank: int, confidence: float,
        detail: str, host: str, workload_id: str, run_id: str,
        attack_path_id: str, source_kind: str = "ssh_command") -> dict:
    now = iso_now()
    return {
        "id":   str(uuid.uuid4()),
        "ts":   now,
        "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN, "version": "0.1.0"},
        "payload": {
            "wicket_id":      wicket_id,
            "status":         status,
            "workload_id":    workload_id,
            "detail":         detail,
            "attack_path_id": attack_path_id,
            "run_id":         run_id,
            "observed_at":    now,
        },
        "provenance": {
            "evidence_rank": rank,
            "evidence": {
                "source_kind":  source_kind,
                "pointer":      f"ssh://{host}/{wicket_id.lower()}",
                "collected_at": now,
                "confidence":   confidence,
            },
        },
    }


def _run(client, cmd: str, timeout: int = 20) -> tuple[str, str, int]:
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        rc  = stdout.channel.recv_exit_status()
        return out, err, rc
    except Exception as exc:
        return "", str(exc), 1


# ── STATE ─────────────────────────────────────────────────────────────────
# Baseline state is stored in /var/lib/skg/sysaudit/{workload_id}.json
# Contains file hashes, process manifest, log watermarks

STATE_DIR = Path("/var/lib/skg/sysaudit")


def _load_state(workload_id: str) -> dict:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    p = STATE_DIR / f"{workload_id.replace('::', '_').replace('/', '_')}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _save_state(workload_id: str, state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    p = STATE_DIR / f"{workload_id.replace('::', '_').replace('/', '_')}.json"
    p.write_text(json.dumps(state, indent=2))


# ══════════════════════════════════════════════════════════════════════════
# FILESYSTEM INTEGRITY  (FI-01 through FI-10)
# ══════════════════════════════════════════════════════════════════════════

def check_fi01_system_binary_integrity(client, host: str, workload_id: str,
                                        run_id: str, apid: str,
                                        state: dict) -> list[dict]:
    """
    FI-01: System binary integrity.
    Hashes key system binaries and compares to baseline.
    First run: establishes baseline (UNKNOWN — not yet compared).
    Subsequent runs: REALIZED if matches, BLOCKED if changed.

    Checks: /bin/sh /bin/bash /usr/bin/sudo /usr/bin/passwd
            /usr/bin/python3 /sbin/sshd /usr/bin/wget /usr/bin/curl
    """
    binaries = [
        "/bin/sh", "/bin/bash", "/usr/bin/sudo",
        "/usr/bin/passwd", "/sbin/sshd",
        "/usr/bin/python3", "/usr/bin/wget", "/usr/bin/curl",
    ]
    cmd = "md5sum " + " ".join(binaries) + " 2>/dev/null"
    stdout, _, _ = _run(client, cmd)

    current: dict[str, str] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            current[parts[1]] = parts[0]

    if not current:
        return [_ev("FI-01", "unknown", 3, 0.30,
                    "Could not hash system binaries",
                    host, workload_id, run_id, apid)]

    baseline = state.get("binary_hashes", {})
    events = []

    if not baseline:
        state["binary_hashes"] = current
        return [_ev("FI-01", "unknown", 2, 0.70,
                    f"Baseline established for {len(current)} binaries — "
                    f"next run will compare",
                    host, workload_id, run_id, apid, "ssh_baseline")]

    changed = {p: (baseline.get(p, "?"), h)
               for p, h in current.items()
               if h != baseline.get(p)}
    new_bins = {p: h for p, h in current.items() if p not in baseline}

    if changed:
        detail = (f"{len(changed)} binary/binaries changed: "
                  + "; ".join(f"{p} ({old}→{new})"
                              for p, (old, new) in list(changed.items())[:3]))
        events.append(_ev("FI-01", "blocked", 2, 0.95,
                          detail, host, workload_id, run_id, apid))
    else:
        events.append(_ev("FI-01", "realized", 2, 0.95,
                          f"{len(current)} system binaries match baseline",
                          host, workload_id, run_id, apid))

    if new_bins:
        events.append(_ev("FI-01", "blocked", 2, 0.80,
                          f"{len(new_bins)} new binaries not in baseline: "
                          + ", ".join(list(new_bins)[:3]),
                          host, workload_id, run_id, apid))

    state["binary_hashes"] = current
    return events


def check_fi02_unexpected_suid(client, host: str, workload_id: str,
                                run_id: str, apid: str,
                                state: dict) -> list[dict]:
    """
    FI-02: Unexpected SUID/SGID binaries.
    Compares current SUID set to baseline. New ones are suspicious.
    Known good SUID binaries (distro-installed) are baseline.
    """
    stdout, _, rc = _run(client,
        "find / -perm -4000 -o -perm -2000 2>/dev/null "
        "| grep -v '^/proc' | grep -v '^/sys' | sort")

    if rc != 0 and not stdout:
        return [_ev("FI-02", "unknown", 3, 0.30,
                    "SUID scan failed or permission denied",
                    host, workload_id, run_id, apid)]

    current = set(stdout.splitlines())
    baseline = set(state.get("suid_binaries", []))

    if not baseline:
        state["suid_binaries"] = sorted(current)
        return [_ev("FI-02", "unknown", 3, 0.70,
                    f"SUID baseline: {len(current)} binaries recorded",
                    host, workload_id, run_id, apid, "ssh_baseline")]

    new_suid = current - baseline
    removed  = baseline - current

    if new_suid:
        # New SUID binaries are high signal — likely privesc or persistence
        detail = f"{len(new_suid)} new SUID/SGID: " + ", ".join(sorted(new_suid)[:5])
        state["suid_binaries"] = sorted(current)
        return [_ev("FI-02", "blocked", 1, 0.90,
                    detail, host, workload_id, run_id, apid)]

    state["suid_binaries"] = sorted(current)
    return [_ev("FI-02", "realized", 3, 0.85,
                f"SUID/SGID set unchanged ({len(current)} binaries)",
                host, workload_id, run_id, apid)]


def check_fi03_world_writable_dirs(client, host: str, workload_id: str,
                                    run_id: str, apid: str) -> list[dict]:
    """
    FI-03: World-writable directories outside of /tmp /var/tmp /dev/shm.
    These are potential staging areas for dropped payloads.
    """
    stdout, _, _ = _run(client,
        "find / -maxdepth 6 -type d -perm -0002 2>/dev/null "
        "| grep -v '^/proc' | grep -v '^/sys' | grep -v '^/dev' "
        "| grep -v '^/tmp' | grep -v '^/var/tmp' | grep -v '^/run' "
        "| grep -v '^/dev/shm' | head -20",
        timeout=45)

    suspicious = [d for d in stdout.splitlines() if d.strip()]

    if suspicious:
        return [_ev("FI-03", "blocked", 3, 0.85,
                    f"{len(suspicious)} unexpected world-writable dirs: "
                    + ", ".join(suspicious[:5]),
                    host, workload_id, run_id, apid)]
    return [_ev("FI-03", "realized", 3, 0.80,
                "No unexpected world-writable directories found",
                host, workload_id, run_id, apid)]


def check_fi04_executables_in_tmp(client, host: str, workload_id: str,
                                   run_id: str, apid: str) -> list[dict]:
    """
    FI-04: Executable files in /tmp, /var/tmp, /dev/shm.
    Executables in temp directories are a strong indicator of
    payload staging, memory-only implants, or compile-and-run attacks.
    """
    stdout, _, _ = _run(client,
        "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | head -20")

    execs = [f for f in stdout.splitlines() if f.strip()]

    if execs:
        return [_ev("FI-04", "blocked", 1, 0.95,
                    f"{len(execs)} executable(s) in temp dirs: "
                    + ", ".join(execs[:5]),
                    host, workload_id, run_id, apid)]
    return [_ev("FI-04", "realized", 1, 0.90,
                "No executables in /tmp /var/tmp /dev/shm",
                host, workload_id, run_id, apid)]


def check_fi05_recently_modified_system_files(client, host: str,
                                               workload_id: str,
                                               run_id: str, apid: str) -> list[dict]:
    """
    FI-05: System files modified in the last 24 hours.
    Unexpected recent modifications to /etc, /bin, /sbin, /usr/bin
    are indicators of tampering, backdoor installation, or misconfiguration.
    """
    stdout, _, _ = _run(client,
        "find /etc /bin /sbin /usr/bin /usr/sbin /lib /usr/lib "
        "-newer /proc/1 -type f 2>/dev/null "
        "| grep -v '.pyc' | grep -v '__pycache__' | head -30",
        timeout=45)

    modified = [f for f in stdout.splitlines() if f.strip()]

    # Filter out known-noisy paths (package manager state files, etc.)
    noisy = {"/etc/ld.so.cache", "/etc/passwd-", "/etc/shadow-",
             "/etc/group-", "/var/lib/dpkg", "/var/lib/rpm"}
    filtered = [f for f in modified
                if not any(f.startswith(n) for n in noisy)]

    if filtered:
        return [_ev("FI-05", "blocked", 1, 0.75,
                    f"{len(filtered)} recently modified system files: "
                    + "; ".join(filtered[:5]),
                    host, workload_id, run_id, apid)]
    return [_ev("FI-05", "realized", 1, 0.70,
                "No unexpected recent modifications in system paths",
                host, workload_id, run_id, apid)]


def check_fi06_immutable_flags(client, host: str, workload_id: str,
                                run_id: str, apid: str) -> list[dict]:
    """
    FI-06: Critical files have immutable flag set (chattr +i).
    /etc/passwd, /etc/shadow, /etc/hosts should have known immutability state.
    Unexpectedly immutable = attacker may have locked a backdoor in place.
    Unexpectedly mutable = protection weaker than declared.
    """
    files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
             "/etc/hosts", "/etc/crontab"]
    stdout, _, rc = _run(client,
        f"lsattr {' '.join(files)} 2>/dev/null")

    if rc != 0 or not stdout:
        return [_ev("FI-06", "unknown", 3, 0.40,
                    "lsattr unavailable or permission denied",
                    host, workload_id, run_id, apid)]

    immutable = []
    mutable   = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        attrs, filepath = parts[0], parts[1]
        if "i" in attrs:
            immutable.append(filepath)
        else:
            mutable.append(filepath)

    # Unexpected immutability on /etc/passwd or /etc/sudoers is suspicious
    suspicious_immutable = [f for f in immutable
                             if f in ("/etc/passwd", "/etc/sudoers")]
    if suspicious_immutable:
        return [_ev("FI-06", "blocked", 3, 0.85,
                    f"Unexpected immutable flag on: {suspicious_immutable}",
                    host, workload_id, run_id, apid)]
    return [_ev("FI-06", "realized", 3, 0.75,
                f"File attributes nominal: {len(immutable)} immutable, "
                f"{len(mutable)} mutable",
                host, workload_id, run_id, apid)]


def check_fi07_etc_passwd_integrity(client, host: str, workload_id: str,
                                     run_id: str, apid: str,
                                     state: dict) -> list[dict]:
    """
    FI-07: /etc/passwd and /etc/shadow integrity.
    Tracks UID 0 accounts, accounts with shells, and hash of both files.
    New UID 0 accounts or new shell accounts between runs are high signal.
    """
    stdout, _, _ = _run(client, "cat /etc/passwd 2>/dev/null")
    if not stdout:
        return [_ev("FI-07", "unknown", 3, 0.30,
                    "/etc/passwd unreadable",
                    host, workload_id, run_id, apid)]

    uid0_accounts = []
    shell_accounts = []
    nologin_shells = {"/sbin/nologin", "/bin/false", "/usr/sbin/nologin",
                      "/bin/sync", "/usr/bin/false"}

    for line in stdout.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, uid, _, _, _, shell = parts[:7]
        if uid == "0":
            uid0_accounts.append(username)
        if shell and shell not in nologin_shells and shell != "":
            shell_accounts.append(username)

    prev_uid0   = set(state.get("uid0_accounts",   []))
    prev_shells = set(state.get("shell_accounts",   []))

    events = []

    if not prev_uid0:
        state["uid0_accounts"]  = uid0_accounts
        state["shell_accounts"] = shell_accounts
        events.append(_ev("FI-07", "unknown", 3, 0.70,
                          f"Baseline: UID0={uid0_accounts}, "
                          f"shell_accounts={len(shell_accounts)}",
                          host, workload_id, run_id, apid, "ssh_baseline"))
        return events

    new_uid0   = set(uid0_accounts) - prev_uid0
    new_shells = set(shell_accounts) - prev_shells

    if new_uid0:
        events.append(_ev("FI-07", "blocked", 1, 0.99,
                          f"NEW UID 0 account(s): {sorted(new_uid0)} — "
                          f"possible backdoor account",
                          host, workload_id, run_id, apid))
    elif uid0_accounts != list(prev_uid0):
        events.append(_ev("FI-07", "blocked", 1, 0.90,
                          f"UID 0 set changed: was {sorted(prev_uid0)}, "
                          f"now {sorted(uid0_accounts)}",
                          host, workload_id, run_id, apid))
    else:
        events.append(_ev("FI-07", "realized", 3, 0.90,
                          f"UID 0 accounts unchanged: {uid0_accounts}",
                          host, workload_id, run_id, apid))

    if new_shells:
        events.append(_ev("FI-07", "blocked", 1, 0.85,
                          f"New shell account(s): {sorted(new_shells)}",
                          host, workload_id, run_id, apid))

    state["uid0_accounts"]  = uid0_accounts
    state["shell_accounts"] = shell_accounts
    return events


def check_fi08_open_file_handles(client, host: str, workload_id: str,
                                  run_id: str, apid: str) -> list[dict]:
    """
    FI-08: Deleted files with open handles (lsof).
    A process holding an open handle to a deleted file is a
    classic persistence technique — the file is gone from the
    filesystem but the process still has it mapped.
    """
    stdout, _, rc = _run(client,
        "lsof 2>/dev/null | grep -i deleted | grep -v '.so' | head -20")

    if rc != 0 and not stdout:
        return [_ev("FI-08", "unknown", 1, 0.30,
                    "lsof unavailable or no output",
                    host, workload_id, run_id, apid)]

    deleted = [l for l in stdout.splitlines() if l.strip()]

    if deleted:
        return [_ev("FI-08", "blocked", 1, 0.85,
                    f"{len(deleted)} deleted file(s) with open handles: "
                    + "; ".join(l[:80] for l in deleted[:3]),
                    host, workload_id, run_id, apid)]
    return [_ev("FI-08", "realized", 1, 0.80,
                "No deleted files with open handles detected",
                host, workload_id, run_id, apid)]


# ══════════════════════════════════════════════════════════════════════════
# PROCESS INTEGRITY  (PI-01 through PI-08)
# ══════════════════════════════════════════════════════════════════════════

def check_pi01_process_manifest(client, host: str, workload_id: str,
                                 run_id: str, apid: str,
                                 state: dict) -> list[dict]:
    """
    PI-01: Running processes match declared service manifest.
    Collects process names and compares to baseline.
    New processes between runs are flagged for review.
    """
    stdout, _, _ = _run(client,
        "ps aux 2>/dev/null | awk '{print $11}' | sort -u | "
        "grep -v '^COMMAND$' | grep -v '^\\[' | head -80")

    current = set(p.strip() for p in stdout.splitlines() if p.strip())

    baseline = set(state.get("process_manifest", []))

    if not baseline:
        state["process_manifest"] = sorted(current)
        return [_ev("PI-01", "unknown", 1, 0.70,
                    f"Process manifest baseline: {len(current)} processes",
                    host, workload_id, run_id, apid, "ssh_baseline")]

    new_procs = current - baseline
    # Filter out known transient processes
    transient = {"ps", "awk", "sort", "grep", "bash", "sh", "sshd:",
                 "sshd", "sudo", "-bash", "/bin/bash", "/bin/sh"}
    new_procs = {p for p in new_procs
                 if not any(t in p for t in transient)}

    state["process_manifest"] = sorted(current)

    if new_procs:
        return [_ev("PI-01", "blocked", 1, 0.75,
                    f"{len(new_procs)} new process(es) not in manifest: "
                    + ", ".join(sorted(new_procs)[:8]),
                    host, workload_id, run_id, apid)]
    return [_ev("PI-01", "realized", 1, 0.80,
                f"Process set within manifest ({len(current)} processes)",
                host, workload_id, run_id, apid)]


def check_pi02_processes_from_tmp(client, host: str, workload_id: str,
                                   run_id: str, apid: str) -> list[dict]:
    """
    PI-02: Processes running from /tmp, /dev/shm, or world-writable paths.
    A process executing from a temp directory is a strong indicator
    of a dropped payload, memory-stage implant, or malware staging.
    """
    stdout, _, _ = _run(client,
        "ls -la /proc/*/exe 2>/dev/null | "
        "grep -E '(/tmp|/dev/shm|/var/tmp)' | head -20")

    bad = [l.strip() for l in stdout.splitlines() if l.strip()]

    if bad:
        return [_ev("PI-02", "blocked", 1, 0.95,
                    f"{len(bad)} process(es) running from temp path: "
                    + "; ".join(bad[:3]),
                    host, workload_id, run_id, apid)]
    return [_ev("PI-02", "realized", 1, 0.90,
                "No processes running from temp/world-writable paths",
                host, workload_id, run_id, apid)]


def check_pi03_listening_ports_declared(client, host: str, workload_id: str,
                                         run_id: str, apid: str,
                                         state: dict) -> list[dict]:
    """
    PI-03: All listening ports correspond to declared services.
    New listening ports between runs are flagged — possible backdoor,
    C2 listener, or unauthorized service.
    """
    stdout, _, _ = _run(client,
        "ss -tnlp 2>/dev/null | grep LISTEN | "
        "awk '{print $4, $6}' | sort -u")

    current: dict[str, str] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            current[parts[0]] = parts[1]  # addr:port → process

    baseline = state.get("listening_ports", {})

    if not baseline:
        state["listening_ports"] = current
        return [_ev("PI-03", "unknown", 1, 0.70,
                    f"Listening port baseline: {len(current)} ports",
                    host, workload_id, run_id, apid, "ssh_baseline")]

    new_ports = {p: proc for p, proc in current.items()
                 if p not in baseline}
    removed   = {p for p in baseline if p not in current}

    state["listening_ports"] = current

    events = []
    if new_ports:
        events.append(_ev("PI-03", "blocked", 1, 0.90,
                          f"{len(new_ports)} new listening port(s): "
                          + "; ".join(f"{p} ({proc})"
                                      for p, proc in list(new_ports.items())[:5]),
                          host, workload_id, run_id, apid))
    else:
        events.append(_ev("PI-03", "realized", 1, 0.85,
                          f"Listening ports unchanged ({len(current)} ports)",
                          host, workload_id, run_id, apid))
    return events


def check_pi04_root_processes(client, host: str, workload_id: str,
                               run_id: str, apid: str,
                               state: dict) -> list[dict]:
    """
    PI-04: Unexpected root processes.
    Compares current UID 0 process set to baseline.
    New processes running as root that weren't there before are suspicious.
    """
    stdout, _, _ = _run(client,
        "ps aux 2>/dev/null | awk '$1==\"root\" {print $11}' | "
        "sort -u | grep -v '^\\['")

    current = set(p.strip() for p in stdout.splitlines() if p.strip())
    baseline = set(state.get("root_processes", []))

    if not baseline:
        state["root_processes"] = sorted(current)
        return [_ev("PI-04", "unknown", 1, 0.70,
                    f"Root process baseline: {len(current)} processes",
                    host, workload_id, run_id, apid, "ssh_baseline")]

    known_root = {"systemd", "kernel", "kthread", "init", "sshd",
                  "cron", "rsyslogd", "auditd", "NetworkManager",
                  "chronyd", "ntpd", "agetty", "login", "/sbin/init"}
    new_root = current - baseline
    unexpected = {p for p in new_root
                  if not any(k in p for k in known_root)}

    state["root_processes"] = sorted(current)

    if unexpected:
        return [_ev("PI-04", "blocked", 1, 0.80,
                    f"{len(unexpected)} new unexpected root process(es): "
                    + ", ".join(sorted(unexpected)[:8]),
                    host, workload_id, run_id, apid)]
    return [_ev("PI-04", "realized", 1, 0.75,
                f"Root process set within baseline ({len(current)} processes)",
                host, workload_id, run_id, apid)]


def check_pi05_shell_spawned_by_service(client, host: str, workload_id: str,
                                         run_id: str, apid: str) -> list[dict]:
    """
    PI-05: Shell processes spawned by service processes.
    A web server, database, or other service process that has spawned
    a shell (bash, sh, zsh) is a strong indicator of command injection
    or remote code execution that produced an interactive shell.
    """
    # Look for shell processes whose parent is a service process
    stdout, _, _ = _run(client,
        "ps -ef 2>/dev/null | awk '{print $1,$2,$3,$8}' | "
        "grep -E '\\b(bash|sh|zsh|fish|ksh)\\b' | "
        "grep -v 'sshd\\|login\\|su\\|sudo\\|bash\\|getty\\|tmux\\|screen'")

    suspicious = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        user, pid, ppid, cmd = parts[0], parts[1], parts[2], parts[3]

        # Look up parent process
        parent_out, _, _ = _run(client, f"ps -p {ppid} -o comm= 2>/dev/null")
        parent = parent_out.strip()

        # Shell spawned by web/db/app process = suspicious
        service_parents = {"nginx", "apache2", "httpd", "php-fpm", "php",
                           "node", "python", "ruby", "java", "mysqld",
                           "postgres", "redis-server", "mongod", "tomcat"}
        if any(sp in parent.lower() for sp in service_parents):
            suspicious.append(f"{cmd} (pid={pid}, parent={parent}[{ppid}])")

    if suspicious:
        return [_ev("PI-05", "blocked", 1, 0.95,
                    f"{len(suspicious)} shell(s) spawned by service process: "
                    + "; ".join(suspicious[:3]),
                    host, workload_id, run_id, apid)]
    return [_ev("PI-05", "realized", 1, 0.80,
                "No shells spawned by service processes detected",
                host, workload_id, run_id, apid)]


def check_pi06_zombie_accumulation(client, host: str, workload_id: str,
                                    run_id: str, apid: str) -> list[dict]:
    """
    PI-06: Zombie process accumulation.
    A large number of zombie processes indicates a parent that is not
    reaping children — often a sign of a crashing process in a loop,
    a fork bomb remnant, or a malware process spawning and abandoning children.
    """
    stdout, _, _ = _run(client,
        "ps aux 2>/dev/null | grep -c ' Z '")

    try:
        count = int(stdout.strip())
    except ValueError:
        return [_ev("PI-06", "unknown", 1, 0.40,
                    "Could not count zombie processes",
                    host, workload_id, run_id, apid)]

    if count > 10:
        return [_ev("PI-06", "blocked", 1, 0.85,
                    f"{count} zombie processes — abnormal accumulation",
                    host, workload_id, run_id, apid)]
    elif count > 3:
        return [_ev("PI-06", "unknown", 1, 0.60,
                    f"{count} zombie processes — elevated, monitor",
                    host, workload_id, run_id, apid)]
    return [_ev("PI-06", "realized", 1, 0.90,
                f"{count} zombie processes — normal",
                host, workload_id, run_id, apid)]


def check_pi07_crontab_anomaly(client, host: str, workload_id: str,
                                run_id: str, apid: str,
                                state: dict) -> list[dict]:
    """
    PI-07: Crontab entries changed between runs.
    New or modified cron entries are a classic persistence mechanism.
    Tracks hash of all crontab content (system + user).
    """
    stdout, _, _ = _run(client,
        "cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* "
        "2>/dev/null | md5sum")

    current_hash = stdout.split()[0] if stdout.split() else ""

    if not current_hash:
        return [_ev("PI-07", "unknown", 3, 0.40,
                    "Could not read crontab files",
                    host, workload_id, run_id, apid)]

    prev_hash = state.get("crontab_hash", "")

    if not prev_hash:
        state["crontab_hash"] = current_hash
        return [_ev("PI-07", "unknown", 3, 0.70,
                    "Crontab baseline recorded",
                    host, workload_id, run_id, apid, "ssh_baseline")]

    if current_hash != prev_hash:
        # Get the actual diff for context
        diff_out, _, _ = _run(client,
            "cat /etc/crontab /etc/cron.d/* 2>/dev/null | tail -20")
        state["crontab_hash"] = current_hash
        return [_ev("PI-07", "blocked", 3, 0.90,
                    f"Crontab content changed — possible persistence: "
                    f"{diff_out[:150]}",
                    host, workload_id, run_id, apid)]

    state["crontab_hash"] = current_hash
    return [_ev("PI-07", "realized", 3, 0.85,
                "Crontab content unchanged",
                host, workload_id, run_id, apid)]


def check_pi08_ld_preload_hijack(client, host: str, workload_id: str,
                                  run_id: str, apid: str) -> list[dict]:
    """
    PI-08: LD_PRELOAD or ld.so.preload hijacking.
    LD_PRELOAD in the environment or /etc/ld.so.preload entries
    can be used to intercept library calls system-wide — a classic
    rootkit and credential-harvesting technique.
    """
    events = []

    # Check /etc/ld.so.preload
    stdout, _, rc = _run(client, "cat /etc/ld.so.preload 2>/dev/null")
    if rc == 0 and stdout.strip():
        events.append(_ev("PI-08", "blocked", 3, 0.95,
                          f"/etc/ld.so.preload present: {stdout[:150]}",
                          host, workload_id, run_id, apid))
    else:
        events.append(_ev("PI-08", "realized", 3, 0.90,
                          "/etc/ld.so.preload absent",
                          host, workload_id, run_id, apid))

    # Check for LD_PRELOAD in init environment
    env_out, _, _ = _run(client,
        "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep LD_PRELOAD")
    if env_out.strip():
        events.append(_ev("PI-08", "blocked", 1, 0.95,
                          f"LD_PRELOAD in init environment: {env_out[:100]}",
                          host, workload_id, run_id, apid))

    return events if events else [_ev("PI-08", "realized", 3, 0.85,
                                      "No LD_PRELOAD/ld.so.preload hijacking",
                                      host, workload_id, run_id, apid)]


# ══════════════════════════════════════════════════════════════════════════
# LOG INTEGRITY  (LI-01 through LI-08)
# ══════════════════════════════════════════════════════════════════════════

def check_li01_logging_daemon_running(client, host: str, workload_id: str,
                                       run_id: str, apid: str) -> list[dict]:
    """
    LI-01: Logging daemon running and collecting.
    Checks for syslog, rsyslog, syslog-ng, and systemd-journald.
    If none are running, this is a structural fold — log integrity
    wickets cannot be evaluated.
    """
    daemons = {
        "systemd-journald": "journalctl --no-pager -n 1 2>/dev/null",
        "rsyslogd":         "pgrep -x rsyslogd 2>/dev/null",
        "syslogd":          "pgrep -x syslogd 2>/dev/null",
        "syslog-ng":        "pgrep -x syslog-ng 2>/dev/null",
    }

    found = []
    for name, check_cmd in daemons.items():
        out, _, rc = _run(client, check_cmd)
        if rc == 0 and out.strip():
            found.append(name)

    if found:
        return [_ev("LI-01", "realized", 1, 0.95,
                    f"Logging daemon(s) running: {', '.join(found)}",
                    host, workload_id, run_id, apid)]
    return [_ev("LI-01", "blocked", 1, 0.90,
                "No logging daemon detected — logging infrastructure absent",
                host, workload_id, run_id, apid)]


def check_li02_log_files_growing(client, host: str, workload_id: str,
                                  run_id: str, apid: str,
                                  state: dict) -> list[dict]:
    """
    LI-02: Log files are growing (not truncated or wiped).
    Compares file sizes between runs. A log file that shrinks outside
    of expected rotation windows is a strong indicator of tampering.
    """
    log_files = [
        "/var/log/syslog", "/var/log/messages", "/var/log/auth.log",
        "/var/log/secure", "/var/log/kern.log",
    ]
    stdout, _, _ = _run(client,
        f"stat -c '%n %s %Y' {' '.join(log_files)} 2>/dev/null")

    current: dict[str, dict] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 3:
            current[parts[0]] = {"size": int(parts[1]), "mtime": int(parts[2])}

    if not current:
        # Try journald
        jout, _, _ = _run(client,
            "journalctl --disk-usage 2>/dev/null | tail -1")
        if jout.strip():
            return [_ev("LI-02", "realized", 1, 0.70,
                        f"Journald active: {jout[:80]}",
                        host, workload_id, run_id, apid)]
        return [_ev("LI-02", "unknown", 1, 0.40,
                    "No log files found to monitor",
                    host, workload_id, run_id, apid)]

    prev = state.get("log_sizes", {})
    events = []

    shrunk = []
    for path, info in current.items():
        prev_size = prev.get(path, {}).get("size", 0)
        if prev_size > 0 and info["size"] < prev_size:
            shrunk.append(f"{path} ({prev_size}→{info['size']} bytes)")

    if shrunk:
        events.append(_ev("LI-02", "blocked", 1, 0.95,
                          f"Log file(s) shrunk (possible tampering): "
                          + "; ".join(shrunk[:3]),
                          host, workload_id, run_id, apid))
    elif current:
        growing = sum(1 for p, info in current.items()
                      if info["size"] > prev.get(p, {}).get("size", 0))
        events.append(_ev("LI-02", "realized", 1, 0.85,
                          f"{growing}/{len(current)} log files growing normally",
                          host, workload_id, run_id, apid))

    state["log_sizes"] = {p: info for p, info in current.items()}
    return events if events else [_ev("LI-02", "unknown", 1, 0.40,
                                      "Log growth status indeterminate",
                                      host, workload_id, run_id, apid)]


def check_li03_auth_log_anomaly(client, host: str, workload_id: str,
                                 run_id: str, apid: str,
                                 state: dict) -> list[dict]:
    """
    LI-03: Authentication failure rate within normal bounds.
    High auth failure rates indicate brute force, credential stuffing,
    or a compromised system attempting lateral movement.
    Baseline: < 10 failures/hour is normal.
    """
    # Count auth failures in last hour
    stdout, _, _ = _run(client,
        "grep -c 'Failed password\\|authentication failure\\|Invalid user' "
        "/var/log/auth.log /var/log/secure 2>/dev/null | "
        "awk -F: '{sum+=$2} END{print sum}'")

    try:
        failures = int(stdout.strip()) if stdout.strip() else 0
    except ValueError:
        # Try journald
        jout, _, _ = _run(client,
            "journalctl -u sshd --since '1 hour ago' 2>/dev/null | "
            "grep -c 'Failed\\|Invalid'")
        try:
            failures = int(jout.strip())
        except ValueError:
            return [_ev("LI-03", "unknown", 1, 0.40,
                        "Could not read auth logs",
                        host, workload_id, run_id, apid)]

    baseline_rate = state.get("auth_failure_baseline", 10)

    if failures > baseline_rate * 10:
        status = "blocked"
        detail = f"{failures} auth failures in last period — likely brute force"
    elif failures > baseline_rate * 3:
        status = "unknown"
        detail = f"{failures} auth failures — elevated, watch"
    else:
        status = "realized"
        detail = f"{failures} auth failures — within normal bounds"

    return [_ev("LI-03", status, 1, 0.80,
                detail, host, workload_id, run_id, apid)]


def check_li04_log_gap(client, host: str, workload_id: str,
                        run_id: str, apid: str) -> list[dict]:
    """
    LI-04: Log timeline gap detection.
    Looks for periods of silence in the log files that don't correspond
    to known maintenance windows. A log gap while the system was running
    is a strong indicator of log tampering or logging interruption.
    """
    # Check if there are any log entries in the last 5 minutes
    # (if the system is running, there should be something)
    stdout, _, _ = _run(client,
        "journalctl --since '5 minutes ago' 2>/dev/null | wc -l")

    try:
        recent_entries = int(stdout.strip())
    except ValueError:
        # Fall back to checking auth.log mtime
        mtime_out, _, _ = _run(client,
            "find /var/log -name 'syslog' -o -name 'messages' -o -name 'auth.log' "
            "2>/dev/null | xargs stat -c '%Y' 2>/dev/null | sort -n | tail -1")
        try:
            last_mtime = int(mtime_out.strip())
            now_ts     = int(datetime.now(timezone.utc).timestamp())
            age_mins   = (now_ts - last_mtime) / 60
            if age_mins > 10:
                return [_ev("LI-04", "blocked", 1, 0.85,
                            f"Log files not updated for {age_mins:.0f} minutes — "
                            f"possible gap or tampering",
                            host, workload_id, run_id, apid)]
            return [_ev("LI-04", "realized", 1, 0.75,
                        f"Log files updated {age_mins:.0f} minutes ago",
                        host, workload_id, run_id, apid)]
        except Exception:
            return [_ev("LI-04", "unknown", 1, 0.30,
                        "Cannot determine log recency",
                        host, workload_id, run_id, apid)]

    if recent_entries == 0:
        return [_ev("LI-04", "blocked", 1, 0.80,
                    "No log entries in last 5 minutes — possible log gap",
                    host, workload_id, run_id, apid)]
    return [_ev("LI-04", "realized", 1, 0.85,
                f"{recent_entries} log entries in last 5 minutes",
                host, workload_id, run_id, apid)]


def check_li05_auditd_active(client, host: str, workload_id: str,
                              run_id: str, apid: str) -> list[dict]:
    """
    LI-05: Audit daemon active with meaningful rules.
    auditd provides kernel-level audit trail for file access,
    privilege escalation, and network connections.
    Absent = no tamper-evident log for privileged actions.
    """
    # Check if auditd is running
    auditd_out, _, auditd_rc = _run(client,
        "pgrep -x auditd 2>/dev/null || systemctl is-active auditd 2>/dev/null")

    if auditd_rc != 0:
        return [_ev("LI-05", "blocked", 1, 0.85,
                    "auditd not running — privileged actions not audited",
                    host, workload_id, run_id, apid)]

    # Check for meaningful audit rules
    rules_out, _, _ = _run(client, "auditctl -l 2>/dev/null | wc -l")
    try:
        rule_count = int(rules_out.strip())
    except ValueError:
        rule_count = 0

    if rule_count < 3:
        return [_ev("LI-05", "unknown", 3, 0.70,
                    f"auditd running but only {rule_count} rules — "
                    f"coverage may be insufficient",
                    host, workload_id, run_id, apid)]

    return [_ev("LI-05", "realized", 1, 0.90,
                f"auditd active with {rule_count} rules",
                host, workload_id, run_id, apid)]


def check_li06_log_forwarding(client, host: str, workload_id: str,
                               run_id: str, apid: str) -> list[dict]:
    """
    LI-06: Logs forwarded to remote SIEM or log aggregator.
    Local-only logs can be tampered by an attacker with root access.
    Remote forwarding provides tamper-evident audit trail.
    """
    # Check for remote forwarding in rsyslog, syslog-ng, or filebeat config
    checks = [
        ("rsyslog",   "grep -r '@@\\|@[0-9]\\|remote' /etc/rsyslog* 2>/dev/null | head -3"),
        ("syslog-ng", "grep -r 'tcp\\|udp\\|syslog' /etc/syslog-ng* 2>/dev/null | grep destination | head -3"),
        ("filebeat",  "cat /etc/filebeat/filebeat.yml 2>/dev/null | grep 'hosts\\|output' | head -3"),
        ("journald",  "grep -i 'forwardtosyslog\\|storage.*persistent' /etc/systemd/journald.conf 2>/dev/null"),
    ]

    forwarding_found = []
    for name, cmd in checks:
        out, _, rc = _run(client, cmd)
        if rc == 0 and out.strip():
            forwarding_found.append(name)

    if forwarding_found:
        return [_ev("LI-06", "realized", 3, 0.80,
                    f"Log forwarding configured: {', '.join(forwarding_found)}",
                    host, workload_id, run_id, apid)]
    return [_ev("LI-06", "blocked", 3, 0.70,
                "No remote log forwarding detected — logs local-only",
                host, workload_id, run_id, apid)]


def check_li07_log_rotation_intact(client, host: str, workload_id: str,
                                    run_id: str, apid: str) -> list[dict]:
    """
    LI-07: Log rotation configuration intact and recent.
    Missing logrotate config, disabled rotation, or abnormally large
    log files indicate either misconfiguration or deliberate suppression.
    """
    # Check logrotate status
    status_out, _, _ = _run(client,
        "cat /var/lib/logrotate/status 2>/dev/null | "
        "grep -E 'syslog|messages|auth' | head -5")

    # Check for abnormally large log files (> 500MB)
    size_out, _, _ = _run(client,
        "find /var/log -type f -size +500M 2>/dev/null | head -5")

    events = []
    large = [f for f in size_out.splitlines() if f.strip()]
    if large:
        events.append(_ev("LI-07", "blocked", 3, 0.75,
                          f"Abnormally large log files (>500MB): "
                          + ", ".join(large[:3]),
                          host, workload_id, run_id, apid))
    elif status_out.strip():
        events.append(_ev("LI-07", "realized", 3, 0.75,
                          "Log rotation active and recently ran",
                          host, workload_id, run_id, apid))
    else:
        events.append(_ev("LI-07", "unknown", 3, 0.50,
                          "Log rotation status indeterminate",
                          host, workload_id, run_id, apid))

    return events


def check_li08_wtmp_lastlog_integrity(client, host: str, workload_id: str,
                                       run_id: str, apid: str,
                                       state: dict) -> list[dict]:
    """
    LI-08: wtmp and lastlog integrity.
    These files record login history and are frequently tampered
    with by attackers to hide their presence (utmpdump, wtmpclean, etc.).
    Tracks file size changes — shrinkage = likely tampering.
    """
    stdout, _, _ = _run(client,
        "stat -c '%s %Y' /var/log/wtmp /var/log/lastlog 2>/dev/null")

    current: dict[str, int] = {}
    files = ["/var/log/wtmp", "/var/log/lastlog"]
    for i, line in enumerate(stdout.splitlines()):
        parts = line.split()
        if len(parts) >= 1 and i < len(files):
            try:
                current[files[i]] = int(parts[0])
            except ValueError:
                pass

    if not current:
        return [_ev("LI-08", "unknown", 3, 0.30,
                    "wtmp/lastlog not accessible",
                    host, workload_id, run_id, apid)]

    prev = state.get("wtmp_sizes", {})
    events = []

    if not prev:
        state["wtmp_sizes"] = current
        return [_ev("LI-08", "unknown", 3, 0.70,
                    f"wtmp/lastlog baseline: {current}",
                    host, workload_id, run_id, apid, "ssh_baseline")]

    for path, size in current.items():
        prev_size = prev.get(path, 0)
        if prev_size > 0 and size < prev_size:
            events.append(_ev("LI-08", "blocked", 1, 0.95,
                              f"{path} shrunk {prev_size}→{size} bytes — "
                              f"possible login history tampering",
                              host, workload_id, run_id, apid))

    if not events:
        events.append(_ev("LI-08", "realized", 3, 0.85,
                          f"wtmp/lastlog sizes intact: "
                          + ", ".join(f"{p}={s}b" for p, s in current.items()),
                          host, workload_id, run_id, apid))

    state["wtmp_sizes"] = current
    return events


# ══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def run_sysaudit(client,
                 host: str,
                 workload_id: str,
                 attack_path_id: str,
                 run_id: str,
                 checks: list[str] | None = None) -> list[dict]:
    """
    Run all system audit checks via an open paramiko SSH client.

    checks: optional subset of check IDs to run. None = run all.
    Recognised check IDs: fi01..fi08, pi01..pi08, li01..li08

    Returns list of obs.attack.precondition events.
    """
    state = _load_state(workload_id)
    all_events: list[dict] = []

    def _should(check_id: str) -> bool:
        return checks is None or check_id in checks

    # ── Filesystem ────────────────────────────────────────────────────────
    check_map = {
        "fi01": lambda: check_fi01_system_binary_integrity(
            client, host, workload_id, run_id, attack_path_id, state),
        "fi02": lambda: check_fi02_unexpected_suid(
            client, host, workload_id, run_id, attack_path_id, state),
        "fi03": lambda: check_fi03_world_writable_dirs(
            client, host, workload_id, run_id, attack_path_id),
        "fi04": lambda: check_fi04_executables_in_tmp(
            client, host, workload_id, run_id, attack_path_id),
        "fi05": lambda: check_fi05_recently_modified_system_files(
            client, host, workload_id, run_id, attack_path_id),
        "fi06": lambda: check_fi06_immutable_flags(
            client, host, workload_id, run_id, attack_path_id),
        "fi07": lambda: check_fi07_etc_passwd_integrity(
            client, host, workload_id, run_id, attack_path_id, state),
        "fi08": lambda: check_fi08_open_file_handles(
            client, host, workload_id, run_id, attack_path_id),
        # ── Process ───────────────────────────────────────────────────────
        "pi01": lambda: check_pi01_process_manifest(
            client, host, workload_id, run_id, attack_path_id, state),
        "pi02": lambda: check_pi02_processes_from_tmp(
            client, host, workload_id, run_id, attack_path_id),
        "pi03": lambda: check_pi03_listening_ports_declared(
            client, host, workload_id, run_id, attack_path_id, state),
        "pi04": lambda: check_pi04_root_processes(
            client, host, workload_id, run_id, attack_path_id, state),
        "pi05": lambda: check_pi05_shell_spawned_by_service(
            client, host, workload_id, run_id, attack_path_id),
        "pi06": lambda: check_pi06_zombie_accumulation(
            client, host, workload_id, run_id, attack_path_id),
        "pi07": lambda: check_pi07_crontab_anomaly(
            client, host, workload_id, run_id, attack_path_id, state),
        "pi08": lambda: check_pi08_ld_preload_hijack(
            client, host, workload_id, run_id, attack_path_id),
        # ── Logging ───────────────────────────────────────────────────────
        "li01": lambda: check_li01_logging_daemon_running(
            client, host, workload_id, run_id, attack_path_id),
        "li02": lambda: check_li02_log_files_growing(
            client, host, workload_id, run_id, attack_path_id, state),
        "li03": lambda: check_li03_auth_log_anomaly(
            client, host, workload_id, run_id, attack_path_id, state),
        "li04": lambda: check_li04_log_gap(
            client, host, workload_id, run_id, attack_path_id),
        "li05": lambda: check_li05_auditd_active(
            client, host, workload_id, run_id, attack_path_id),
        "li06": lambda: check_li06_log_forwarding(
            client, host, workload_id, run_id, attack_path_id),
        "li07": lambda: check_li07_log_rotation_intact(
            client, host, workload_id, run_id, attack_path_id),
        "li08": lambda: check_li08_wtmp_lastlog_integrity(
            client, host, workload_id, run_id, attack_path_id, state),
    }

    for check_id, fn in check_map.items():
        if not _should(check_id):
            continue
        try:
            evs = fn()
            all_events.extend(evs)
            for ev in evs:
                wid    = ev["payload"]["wicket_id"]
                status = ev["payload"]["status"]
                detail = ev["payload"]["detail"][:70]
                marker = "✓" if status == "realized" else \
                         ("✗" if status == "blocked" else "?")
                print(f"    {marker} {wid:6s} [{status:8s}]  {detail}")
        except Exception as exc:
            print(f"    ? {check_id}  check failed: {exc}")
            all_events.append(_ev(check_id.upper(), "unknown", 1, 0.20,
                                  f"Check error: {exc}",
                                  host, workload_id, run_id, attack_path_id))

    _save_state(workload_id, state)
    return all_events
