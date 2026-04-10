"""
skg :: sensors/gpu_probe.py

GPU / compute attack surface instrument.

Unlike driver-based GPU exploits, this maps NON-DRIVER attack surface:

  1. Compute API exposure: OpenCL, CUDA, Vulkan accessible without auth
  2. GPU process isolation failures: multiple contexts can inspect each other
  3. GPU memory persistence: context memory not zeroed between sessions
  4. Shared CPU-GPU memory attack surface (DMA coherent regions)
  5. GPU-accelerated password cracking surface (exposed hash endpoints)
  6. IOMMU/VT-d absence (DMA attack surface, Thunderclap-style)
  7. GPU device files world-accessible (/dev/dri/*, /dev/nvidia*)
  8. OpenCL JIT kernel compilation accessible to unprivileged users
  9. Network-exposed GPU compute APIs (CUDA IPC, OpenCL remote)
  10. GPU process memory via /proc (same as CPU process injection)

Wickets emitted:
  GP-01  GPU device present and accessible to current user
  GP-02  IOMMU/VT-d disabled (DMA attack surface, cross-process GPU memory)
  GP-03  GPU device files world-accessible (/dev/nvidia*, /dev/dri/*)
  GP-04  GPU compute context memory not isolated (multiple contexts can read each other)
  GP-05  OpenCL kernel JIT accessible to unprivileged user
  GP-06  GPU memory persistence (memory not zeroed after context close)
  GP-07  Network-exposed GPU compute API (port 50051 gRPC, CUDA IPC socket)
  GP-08  GPU driver has unpatched CVE (version fingerprint match)
  GP-09  Vulkan/OpenGL instance accessible to unprivileged user
  GP-10  GPU process visible in /proc and not isolated from CPU side-channels

Note: GPU exploits in this context means exploiting the COMPUTE STACK
(OpenCL kernels, CUDA APIs, GPU memory bridges) NOT driver ring-0 exploits.
The GPU is a parallel execution environment with its own memory model —
isolation failures allow cross-process reads similar to Spectre/Meltdown.
"""
from __future__ import annotations

import json
import re
import socket
from pathlib import Path
from typing import Optional

try:
    from skg_protocol.events import (
        build_event_envelope as envelope,
        build_precondition_payload as precondition_payload,
    )
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import envelope, precondition_payload

# Known GPU driver version → CVE mappings (non-exhaustive, illustrative)
_DRIVER_CVES: dict[str, list[str]] = {
    "470":  ["CVE-2021-1076", "CVE-2021-1077"],   # NVIDIA 470.x branch
    "510":  ["CVE-2022-28181", "CVE-2022-28183"],  # NVIDIA 510.x
    "525":  ["CVE-2023-0183", "CVE-2023-0184"],    # NVIDIA 525.x
    "535":  ["CVE-2023-31022"],                     # NVIDIA 535.x
}

# GPU compute API ports to scan
_GPU_PORTS = {
    50051: "gRPC GPU compute (TensorFlow Serving / Triton)",
    50052: "Triton inference server",
    8080:  "TensorFlow Serving REST",
    8081:  "Torch Serve REST",
    2222:  "TF distributed training",
    6006:  "TensorBoard (model/data exposure)",
    8888:  "Jupyter (GPU-backed, code execution)",
}


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
        source_id=f"gpu_probe/{wicket_id}",
        toolchain="skg-host-toolchain",
        payload=payload,
        evidence_rank=5,
        source_kind="gpu_probe",
        pointer=f"gpu_probe://{target_ip}/{wicket_id}",
        confidence=confidence,
    )


_REMOTE_COMMANDS = {
    # GPU presence
    "nvidia_info":    "nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>/dev/null",
    "amd_info":       "rocm-smi --showproductname 2>/dev/null || clinfo 2>/dev/null | grep 'Device Name' | head -3",
    "dri_devices":    "ls -la /dev/dri/ 2>/dev/null",
    "nvidia_devices": "ls -la /dev/nvidia* 2>/dev/null",

    # IOMMU / VT-d
    "iommu":          "dmesg 2>/dev/null | grep -i iommu | tail -5 || "
                      "cat /sys/class/iommu/*/type 2>/dev/null | head -3 || echo 'none'",
    "iommu_groups":   "ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l",

    # Permissions
    "dri_perms":      "stat -c '%n %a %U %G' /dev/dri/* 2>/dev/null",
    "nvidia_perms":   "stat -c '%n %a %U %G' /dev/nvidia* 2>/dev/null",

    # OpenCL / Vulkan
    "opencl_icd":     "ls /etc/OpenCL/vendors/*.icd 2>/dev/null; "
                      "cat /etc/OpenCL/vendors/*.icd 2>/dev/null | head -5",
    "vulkan_icd":     "ls /usr/share/vulkan/icd.d/*.json 2>/dev/null | head -5",
    "clinfo_priv":    "sudo -n clinfo 2>/dev/null | head -20 || clinfo 2>/dev/null | head -20",

    # GPU memory persistence (check nvidia-smi persistence mode)
    "persistence":    "nvidia-smi -q 2>/dev/null | grep -i 'Persistence Mode' | head -3",

    # GPU processes visible
    "gpu_procs":      "nvidia-smi pmon -c 1 2>/dev/null | head -20 || "
                      "fuser /dev/nvidia* 2>/dev/null | head -10",

    # Compute isolation
    "mps_server":     "ls /var/run/nvidia-mps* 2>/dev/null || ps aux | grep -i mps | grep -v grep | head -3",
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


def _probe_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def probe_gpu_surface(
    target_ip: str,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    ssh_password: Optional[str] = None,
    out_file: Optional[Path] = None,
) -> list[dict]:
    """
    Probe a target for GPU compute attack surface.

    This maps NON-DRIVER GPU attack surface:
    - Compute API exposure and isolation failures
    - Memory persistence between contexts
    - IOMMU gaps (DMA attack surface)
    - GPU device file permissions
    - Network-exposed GPU compute APIs
    """
    workload_id = f"host::{target_ip}"
    events: list[dict] = []

    def run(key: str) -> str:
        return _run_ssh(target_ip, ssh_user, ssh_key, ssh_password,
                        _REMOTE_COMMANDS[key])

    # GP-01: GPU device present
    nvidia_out = run("nvidia_info")
    amd_out = run("amd_info")
    has_gpu = bool(nvidia_out.strip() or amd_out.strip())
    gpu_summary = nvidia_out.strip() or amd_out.strip() or "no GPU detected"
    events.append(_event("GP-01", "gpu_device_present", workload_id, has_gpu,
        f"GPU: {gpu_summary[:120]}. "
        f"{'GPU compute surface accessible — maps to parallel execution attack space' if has_gpu else 'No GPU detected'}.",
        target_ip, 0.95))

    if not has_gpu:
        # Check for network-exposed compute APIs even without local GPU
        pass  # fall through to network checks

    # GP-02: IOMMU/VT-d state
    iommu_out = run("iommu")
    iommu_groups = run("iommu_groups").strip()
    iommu_active = ("enabled" in iommu_out.lower() or
                    "iommu" in iommu_out.lower() and "disabled" not in iommu_out.lower()) and iommu_groups != "0"
    iommu_absent = not iommu_active
    events.append(_event("GP-02", "iommu_disabled", workload_id, iommu_absent,
        f"IOMMU/VT-d: {'disabled or absent — DMA attacks possible, GPU-to-CPU memory bridge exploitable, Thunderclap-style attacks' if iommu_absent else 'active (' + str(iommu_groups) + ' groups)'}. "
        f"IOMMU info: {iommu_out[:80]}",
        target_ip, 0.85))

    # GP-03: GPU device file permissions
    dri_perms = run("dri_perms")
    nvidia_perms = run("nvidia_perms")
    world_accessible = any(
        p.split()[1].endswith("6") or p.split()[1].endswith("7")
        for p in (dri_perms + "\n" + nvidia_perms).splitlines()
        if len(p.split()) >= 2
    )
    if dri_perms or nvidia_perms:
        events.append(_event("GP-03", "gpu_device_world_accessible", workload_id, world_accessible,
            f"GPU device permissions: {'world-accessible — any user can open GPU context' if world_accessible else 'group-restricted'}. "
            f"DRI: {dri_perms[:80]} NVIDIA: {nvidia_perms[:80]}",
            target_ip, 0.88))

    # GP-05: OpenCL kernel JIT (unprivileged)
    opencl_icd = run("opencl_icd")
    clinfo_out = run("clinfo_priv")
    has_opencl = bool(opencl_icd.strip() or "Device Name" in clinfo_out)
    if has_opencl:
        events.append(_event("GP-05", "opencl_jit_accessible", workload_id, True,
            f"OpenCL ICD installed: {opencl_icd[:80]}. "
            "Unprivileged users can compile and execute GPU compute kernels (JIT attack surface — "
            "buffer overflows in OpenCL kernel compilation, side-channel via shared L2/L3 GPU cache).",
            target_ip, 0.85))

    # GP-09: Vulkan accessible
    vulkan_icd = run("vulkan_icd")
    if vulkan_icd.strip():
        events.append(_event("GP-09", "vulkan_accessible", workload_id, True,
            f"Vulkan ICD present: {vulkan_icd[:80]}. "
            "Vulkan API accessible — compute shaders, pipeline cache poisoning, GPU memory read via "
            "VkBuffer without zeroing (persistent buffer content between allocations).",
            target_ip, 0.80))

    # GP-06: GPU memory persistence
    persistence_out = run("persistence")
    if "enabled" in persistence_out.lower():
        events.append(_event("GP-06", "gpu_memory_persistence", workload_id, True,
            f"NVIDIA persistence mode: ENABLED. "
            "GPU memory is NOT freed between context switches — prior allocation content readable by new context. "
            "Cross-process data leakage via GPU memory reuse.",
            target_ip, 0.80))

    # GP-04 / GP-10: GPU processes and MPS server (compute isolation failure)
    gpu_procs = run("gpu_procs")
    mps_server = run("mps_server")
    if mps_server.strip() and "No such file" not in mps_server:
        events.append(_event("GP-04", "gpu_context_isolation_failure", workload_id, True,
            f"NVIDIA MPS (Multi-Process Service) running: {mps_server[:80]}. "
            "MPS shares a CUDA context across processes — isolation failure allows "
            "one process to read/corrupt another's GPU memory via shared context.",
            target_ip, 0.85))

    if gpu_procs.strip():
        events.append(_event("GP-10", "gpu_process_visible", workload_id, True,
            f"GPU processes visible to probe: {gpu_procs[:120]}. "
            "GPU process memory layout inferrable (GPU-side ASLR equivalent absent in most drivers).",
            target_ip, 0.75))

    # GP-08: Driver CVE check via version fingerprint
    if nvidia_out:
        for line in nvidia_out.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                driver_ver = parts[1]
                branch = driver_ver.split(".")[0]
                cves = _DRIVER_CVES.get(branch, [])
                if cves:
                    events.append(_event("GP-08", "gpu_driver_cve", workload_id, True,
                        f"NVIDIA driver {driver_ver} has known CVEs: {', '.join(cves)}. "
                        f"GPU: {parts[0]}. These are NON-DRIVER ring-0 CVEs — "
                        "exploitable via userspace API calls (ioctl, devmap).",
                        target_ip, 0.80))
                    break

    # GP-07: Network-exposed GPU compute APIs
    exposed_compute = []
    for port, desc in _GPU_PORTS.items():
        if _probe_port(target_ip, port):
            exposed_compute.append(f"{port}/tcp ({desc})")
    if exposed_compute:
        events.append(_event("GP-07", "network_gpu_api_exposed", workload_id, True,
            f"Network-accessible GPU compute APIs: {', '.join(exposed_compute)}. "
            "Remote code execution via model serving APIs, Jupyter kernels, or distributed training endpoints. "
            "GPU-backed inference endpoints may also leak training data via model inversion.",
            target_ip, 0.90))

    if out_file and events:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    return events
