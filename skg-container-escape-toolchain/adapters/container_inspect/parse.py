#!/usr/bin/env python3
"""
adapter: container_inspect
==========================
Ingests `docker inspect <container>` JSON output and emits
obs.attack.precondition events for container escape wickets.

Evidence sources used:
  - .HostConfig.Privileged
  - .HostConfig.CapAdd / .HostConfig.CapDrop
  - .HostConfig.SecurityOpt
  - .HostConfig.PidMode / .HostConfig.IpcMode / .HostConfig.NetworkMode
  - .HostConfig.UsernsMode
  - .Mounts[]
  - .Config.User

Evidence ranks follow skg.event.envelope.v1.json hierarchy:
  rank 1 = runtime  (live docker inspect — most trusted)
  rank 3 = config   (static config values from inspect)

Usage:
  python parse.py --inspect /tmp/inspect.json --out /tmp/events.ndjson \\
                  [--attack-path-id container_escape_privileged_v1] \\
                  [--run-id <uuid>] [--workload-id <name>]
"""

import argparse, json, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-container-escape-toolchain"
SOURCE_ID = "adapter.container_inspect"
SENSITIVE_PATHS = {"/etc", "/proc", "/sys", "/root", "/var/run/docker.sock"}


def get_version() -> str:
    v = Path(__file__).resolve().parents[2] / "VERSION"
    return v.read_text(encoding="utf-8").strip() if v.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, evidence_source_kind: str,
         pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         extra_payload: dict = None):
    """Append one obs.attack.precondition event to the NDJSON file."""
    now = iso_now()
    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": get_version(),
        },
        "payload": {
            "wicket_id": wicket_id,
            "status": status,
            "attack_path_id": attack_path_id,
            "run_id": run_id,
            "workload_id": workload_id,
            **(extra_payload or {}),
        },
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": evidence_source_kind,
                "pointer": pointer,
                "collected_at": now,
                "confidence": confidence,
            },
        },
    }
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def load_inspect(path: Path) -> dict:
    """Load docker inspect JSON. Accepts list-wrapped or raw object."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        if not data:
            raise ValueError("docker inspect output is empty list")
        data = data[0]
    return data


def caps_effective(inspect: dict) -> set:
    """Return effective capability set, accounting for Privileged."""
    hc = inspect.get("HostConfig", {})
    if hc.get("Privileged", False):
        # Privileged grants full capability set
        return {"ALL"}
    added = set(hc.get("CapAdd") or [])
    dropped = set(hc.get("CapDrop") or [])
    # Docker default caps
    defaults = {
        "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID",
        "KILL", "MKNOD", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP",
        "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
    }
    effective = (defaults | added) - dropped
    return effective


def has_cap(caps: set, cap: str) -> bool:
    return "ALL" in caps or cap in caps


def check_privileged(inspect, caps, out, attack_path_id, run_id, workload_id):
    """CE-02: privileged flag."""
    privileged = inspect.get("HostConfig", {}).get("Privileged", False)
    status = "realized" if privileged else "blocked"
    emit(out, "CE-02", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.Privileged",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"privileged": privileged})


def check_running_as_root(inspect, out, attack_path_id, run_id, workload_id):
    """CE-01: container user."""
    user = inspect.get("Config", {}).get("User", "") or ""
    # Root if empty, "0", "root", or "0:0" style
    is_root = user.strip() in ("", "0", "root", "0:0", "root:root")
    status = "realized" if is_root else "blocked"
    emit(out, "CE-01", status,
         evidence_rank=3,
         evidence_source_kind="config",
         pointer="Config.User",
         confidence=0.9,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"user": user or "(empty=root)"})


def check_docker_socket(inspect, out, attack_path_id, run_id, workload_id):
    """CE-03: Docker socket mounted."""
    mounts = inspect.get("Mounts", []) or []
    socket_mount = next(
        (m for m in mounts if "/docker.sock" in m.get("Source", "")), None
    )
    status = "realized" if socket_mount else "blocked"
    emit(out, "CE-03", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="Mounts[].Source",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"socket_source": socket_mount.get("Source") if socket_mount else None})


def check_cap_sys_admin(inspect, caps, out, attack_path_id, run_id, workload_id):
    """CE-04: SYS_ADMIN capability."""
    present = has_cap(caps, "SYS_ADMIN")
    status = "realized" if present else "blocked"
    emit(out, "CE-04", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.CapAdd / HostConfig.Privileged",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"privileged": "ALL" in caps, "cap_add": list(inspect.get("HostConfig", {}).get("CapAdd") or [])})


def check_cap_sys_ptrace(inspect, caps, out, attack_path_id, run_id, workload_id):
    """CE-05: SYS_PTRACE capability."""
    present = has_cap(caps, "SYS_PTRACE")
    status = "realized" if present else "blocked"
    emit(out, "CE-05", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.CapAdd / HostConfig.Privileged",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id)


def check_host_pid(inspect, out, attack_path_id, run_id, workload_id):
    """CE-06: host PID namespace."""
    pid_mode = inspect.get("HostConfig", {}).get("PidMode", "") or ""
    status = "realized" if pid_mode.lower() == "host" else "blocked"
    emit(out, "CE-06", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.PidMode",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"pid_mode": pid_mode or "default"})


def check_host_network(inspect, out, attack_path_id, run_id, workload_id):
    """CE-07: host network namespace."""
    net_mode = inspect.get("HostConfig", {}).get("NetworkMode", "") or ""
    status = "realized" if net_mode.lower() == "host" else "blocked"
    emit(out, "CE-07", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.NetworkMode",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"network_mode": net_mode or "bridge"})


def check_sensitive_mounts(inspect, out, attack_path_id, run_id, workload_id):
    """CE-08 + CE-12: sensitive host path mounts and writability."""
    mounts = inspect.get("Mounts", []) or []
    sensitive = []
    writable_sensitive = []
    for m in mounts:
        src = m.get("Source", "") or ""
        rw = m.get("RW", False)
        # Check if source starts with any sensitive prefix
        is_sensitive = any(src == p or src.startswith(p + "/")
                          for p in SENSITIVE_PATHS)
        if is_sensitive:
            sensitive.append(src)
            if rw:
                writable_sensitive.append(src)

    # CE-08: sensitive path mounted (any access)
    emit(out, "CE-08",
         "realized" if sensitive else "blocked",
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="Mounts[].Source",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"sensitive_mounts": sensitive})

    # CE-12: writable sensitive path
    emit(out, "CE-12",
         "realized" if writable_sensitive else "blocked",
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="Mounts[].Source + Mounts[].RW",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"writable_sensitive_mounts": writable_sensitive})


def check_seccomp_apparmor(inspect, caps, out, attack_path_id, run_id, workload_id):
    """CE-09 + CE-10: seccomp and AppArmor status."""
    hc = inspect.get("HostConfig", {})
    privileged = hc.get("Privileged", False)
    security_opts = hc.get("SecurityOpt") or []

    seccomp_disabled = privileged or any(
        "seccomp=unconfined" in o or "seccomp:unconfined" in o
        for o in security_opts
    )
    apparmor_disabled = privileged or any(
        "apparmor=unconfined" in o or "apparmor:unconfined" in o
        for o in security_opts
    )

    emit(out, "CE-09",
         "realized" if seccomp_disabled else "blocked",
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.SecurityOpt / HostConfig.Privileged",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"security_opt": security_opts, "privileged": privileged})

    emit(out, "CE-10",
         "realized" if apparmor_disabled else "blocked",
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.SecurityOpt / HostConfig.Privileged",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"security_opt": security_opts, "privileged": privileged})


def check_cap_net_admin(inspect, caps, out, attack_path_id, run_id, workload_id):
    """CE-11: NET_ADMIN capability."""
    present = has_cap(caps, "NET_ADMIN")
    status = "realized" if present else "blocked"
    emit(out, "CE-11", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.CapAdd / HostConfig.Privileged",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id)


def check_host_ipc(inspect, out, attack_path_id, run_id, workload_id):
    """CE-13: host IPC namespace."""
    ipc_mode = inspect.get("HostConfig", {}).get("IpcMode", "") or ""
    status = "realized" if ipc_mode.lower() == "host" else "blocked"
    emit(out, "CE-13", status,
         evidence_rank=1,
         evidence_source_kind="runtime",
         pointer="HostConfig.IpcMode",
         confidence=1.0,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"ipc_mode": ipc_mode or "private"})


def check_user_namespace(inspect, out, attack_path_id, run_id, workload_id):
    """CE-14: user namespace remapping. Unknown without daemon config — emit unknown."""
    userns = inspect.get("HostConfig", {}).get("UsernsMode", "") or ""
    if userns.lower() in ("", "host", "default"):
        # No remapping configured in this container — likely host UIDs
        status = "realized"
        confidence = 0.7  # Can't be certain without daemon config
    else:
        status = "blocked"
        confidence = 0.9
    emit(out, "CE-14", status,
         evidence_rank=3,
         evidence_source_kind="config",
         pointer="HostConfig.UsernsMode",
         confidence=confidence,
         attack_path_id=attack_path_id,
         run_id=run_id,
         workload_id=workload_id,
         extra_payload={"userns_mode": userns or "(empty=host mapping)"})


def main():
    p = argparse.ArgumentParser(description="Container inspect adapter for SKG container escape toolchain")
    p.add_argument("--inspect", required=True, help="Path to docker inspect JSON output")
    p.add_argument("--out", required=True, help="Output NDJSON events file (append)")
    p.add_argument("--attack-path-id", default="container_escape_privileged_v1")
    p.add_argument("--run-id", default=None)
    p.add_argument("--workload-id", default=None)
    args = p.parse_args()

    inspect_path = Path(args.inspect)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    run_id = args.run_id or str(uuid.uuid4())
    workload_id = args.workload_id or "unknown"
    attack_path_id = args.attack_path_id

    inspect = load_inspect(inspect_path)
    caps = caps_effective(inspect)

    check_running_as_root(inspect, out_path, attack_path_id, run_id, workload_id)
    check_privileged(inspect, caps, out_path, attack_path_id, run_id, workload_id)
    check_docker_socket(inspect, out_path, attack_path_id, run_id, workload_id)
    check_cap_sys_admin(inspect, caps, out_path, attack_path_id, run_id, workload_id)
    check_cap_sys_ptrace(inspect, caps, out_path, attack_path_id, run_id, workload_id)
    check_host_pid(inspect, out_path, attack_path_id, run_id, workload_id)
    check_host_network(inspect, out_path, attack_path_id, run_id, workload_id)
    check_sensitive_mounts(inspect, out_path, attack_path_id, run_id, workload_id)
    check_seccomp_apparmor(inspect, caps, out_path, attack_path_id, run_id, workload_id)
    check_cap_net_admin(inspect, caps, out_path, attack_path_id, run_id, workload_id)
    check_host_ipc(inspect, out_path, attack_path_id, run_id, workload_id)
    check_user_namespace(inspect, out_path, attack_path_id, run_id, workload_id)

    print(f"[OK] emitted observations → {out_path}")


if __name__ == "__main__":
    main()
