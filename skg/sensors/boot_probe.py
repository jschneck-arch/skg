"""
skg :: sensors/boot_probe.py

Boot / firmware / UEFI attack surface instrument.

Probes a target system (via SSH or local) for boot-level attack surface:
  - UEFI mode vs legacy BIOS
  - Secure Boot enforcement
  - UEFI variable writability (persistence implant surface)
  - TPM presence and PCR state
  - Bootloader protection (GRUB password)
  - Kernel cmdline exposure (debug flags, single-user mode)
  - Signed kernel enforcement (lockdown=integrity/confidentiality)
  - EFI boot order manipulation possible

Wickets emitted:
  BT-01  UEFI mode active (EFI vars accessible — required for UEFI implants)
  BT-02  Secure Boot disabled (unsigned code can boot/execute at firmware level)
  BT-03  UEFI variables writable by OS (BootXXXX vars, persistence vector)
  BT-04  TPM absent or PCR values not enforcing
  BT-05  GRUB/bootloader unprotected (no password, cmdline injectable)
  BT-06  Kernel debug cmdline flags present (debug, single, emergency, nokaslr)
  BT-07  Kernel lockdown not active (module signing not enforced)
  BT-08  Legacy BIOS (no UEFI — full boot sector attack surface)
  BT-09  Recovery/rescue mode accessible without auth
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

try:
    from skg_protocol.events import (
        build_event_envelope as envelope,
        build_precondition_payload as precondition_payload,
    )
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import envelope, precondition_payload


def _event(wicket_id: str, label: str, workload_id: str, realized: bool,
           detail: str, target_ip: str, confidence: float = 0.85) -> dict:
    payload = precondition_payload(
        wicket_id=wicket_id,
        label=label,
        domain="host",
        workload_id=workload_id,
        realized=realized,
        detail=detail,
        target_ip=target_ip,
    )
    return envelope(
        "obs.attack.precondition",
        source_id=f"boot_probe/{wicket_id}",
        toolchain="skg-host-toolchain",
        payload=payload,
        evidence_rank=6,
        source_kind="boot_probe",
        pointer=f"boot_probe://{target_ip}/{wicket_id}",
        confidence=confidence,
    )


_REMOTE_COMMANDS = {
    "efi_vars":     "ls /sys/firmware/efi/efivars/ 2>/dev/null | wc -l",
    "secure_boot":  "mokutil --sb-state 2>/dev/null || "
                    "cat /sys/firmware/efi/efivars/SecureBoot-*/SecureBoot 2>/dev/null | "
                    "od -An -tu1 | awk '{print $NF}' | head -1 || echo 'unknown'",
    "efi_writable": "touch /sys/firmware/efi/efivars/.skg_probe 2>/dev/null && "
                    "rm /sys/firmware/efi/efivars/.skg_probe 2>/dev/null && echo 'WRITABLE' || echo 'readonly'",
    "tpm":          "ls /dev/tpm* 2>/dev/null | head -3 ; "
                    "tpm2_getcap properties-fixed 2>/dev/null | grep -i 'TPMGeneratedEPS' | head -1 || echo ''",
    "grub_pass":    "grep -r 'password' /boot/grub*/grub.cfg /etc/grub.d/ 2>/dev/null | grep -v '#' | head -5 || echo 'none'",
    "cmdline":      "cat /proc/cmdline 2>/dev/null",
    "lockdown":     "cat /sys/kernel/security/lockdown 2>/dev/null || echo 'none'",
    "bios_mode":    "[ -d /sys/firmware/efi ] && echo 'UEFI' || echo 'BIOS'",
    "recovery":     r"grep -r 'recovery\|rescue\|single\|emergency' /boot/grub*/grub.cfg 2>/dev/null | head -5",
}


def _run_ssh(ip: str, user: str, key_path: Optional[str], password: Optional[str],
             cmd: str, timeout: int = 10) -> str:
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw: dict = {"username": user, "timeout": timeout, "look_for_keys": False}
        if key_path:
            kw["key_filename"] = key_path
        elif password:
            kw["password"] = password
        c.connect(ip, **kw)
        _, out, _ = c.exec_command(cmd, timeout=timeout)
        result = out.read().decode(errors="ignore").strip()
        c.close()
        return result
    except Exception:
        return ""


def probe_boot_surface(
    target_ip: str,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    ssh_password: Optional[str] = None,
    out_file: Optional[Path] = None,
) -> list[dict]:
    """
    Probe a Linux target for boot/firmware attack surface via SSH.
    Returns list of wicket events.
    """
    workload_id = f"host::{target_ip}"
    events: list[dict] = []

    def run(key: str) -> str:
        return _run_ssh(target_ip, ssh_user, ssh_key, ssh_password,
                        _REMOTE_COMMANDS[key])

    # BT-08 / BT-01: UEFI vs BIOS mode
    mode = run("bios_mode").strip()
    is_uefi = mode == "UEFI"
    events.append(_event("BT-01", "uefi_mode_active", workload_id, is_uefi,
        f"Boot mode: {mode}. "
        f"{'UEFI active — EFI variable manipulation, bootkit persistence possible' if is_uefi else 'No UEFI vars accessible'}.",
        target_ip, 0.95))
    events.append(_event("BT-08", "legacy_bios_mode", workload_id, not is_uefi,
        f"{'Legacy BIOS detected — full MBR/VBR boot sector attack surface, no Secure Boot enforcement' if not is_uefi else 'UEFI mode, not legacy BIOS'}.",
        target_ip, 0.90))

    if is_uefi:
        # BT-02: Secure Boot state
        sb_out = run("secure_boot").strip().lower()
        sb_disabled = (
            "disabled" in sb_out or "off" in sb_out or
            sb_out == "0" or sb_out == "unknown" or sb_out == ""
        )
        events.append(_event("BT-02", "secure_boot_disabled", workload_id, sb_disabled,
            f"Secure Boot state: {sb_out[:80]}. "
            f"{'DISABLED — unsigned kernels/modules/bootloaders can execute' if sb_disabled else 'ENABLED — unsigned binaries blocked at firmware'}.",
            target_ip, 0.90))

        # BT-03: EFI vars writable
        efi_write = run("efi_writable").strip()
        efi_writable = "WRITABLE" in efi_write
        events.append(_event("BT-03", "efi_vars_writable", workload_id, efi_writable,
            f"EFI variable store: {'WRITABLE from OS — BootXXXX manipulation, UEFI implant persistence possible' if efi_writable else 'read-only or protected'}.",
            target_ip, 0.85))

    # BT-04: TPM presence
    tpm_out = run("tpm").strip()
    tpm_absent = not tpm_out or ("/dev/tpm" not in tpm_out and "TPM" not in tpm_out)
    events.append(_event("BT-04", "tpm_absent_or_weak", workload_id, tpm_absent,
        f"TPM: {'absent — no measured boot, PCR-based attestation not enforcing' if tpm_absent else tpm_out[:80]}.",
        target_ip, 0.80))

    # BT-05: GRUB bootloader protection
    grub_out = run("grub_pass").strip()
    grub_unprotected = grub_out == "none" or not grub_out.strip()
    events.append(_event("BT-05", "bootloader_unprotected", workload_id, grub_unprotected,
        f"GRUB password: {'not set — boot parameters freely editable (single-user, init bypass, nokaslr)' if grub_unprotected else 'configured: ' + grub_out[:60]}.",
        target_ip, 0.85))

    # BT-06: Debug/unsafe kernel cmdline flags
    cmdline = run("cmdline").strip()
    debug_flags = [f for f in ["debug", "single", "emergency", "nokaslr", "nosmep",
                                "nosmap", "nopti", "mitigations=off", "init=/bin/sh",
                                "init=/bin/bash", "rd.break", "systemd.debug-shell"]
                   if f in cmdline]
    if debug_flags:
        events.append(_event("BT-06", "debug_cmdline_flags", workload_id, True,
            f"Dangerous kernel cmdline flags present: {', '.join(debug_flags)}. "
            f"Full cmdline: {cmdline[:200]}",
            target_ip, 0.92))

    # BT-07: Kernel lockdown
    lockdown = run("lockdown").strip()
    lockdown_off = lockdown in ("", "none", "[none] integrity confidentiality") or "none" in lockdown.split()
    events.append(_event("BT-07", "kernel_lockdown_inactive", workload_id, lockdown_off,
        f"Kernel lockdown: {lockdown[:60] or 'not active'}. "
        f"{'Module signing not enforced, direct kernel memory access possible' if lockdown_off else 'Lockdown enforced'}.",
        target_ip, 0.80))

    # BT-09: Recovery/rescue boot entries
    recovery_out = run("recovery").strip()
    if recovery_out and recovery_out != "none":
        events.append(_event("BT-09", "recovery_mode_accessible", workload_id, True,
            f"Recovery/rescue boot entries detected: {recovery_out[:200]}. "
            "Attacker with physical/remote access may boot into single-user mode.",
            target_ip, 0.75))

    if out_file and events:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    return events
