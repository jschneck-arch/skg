from __future__ import annotations

import json
import os
import re
import socket
import uuid
from pathlib import Path
from typing import Any, Mapping


def canonical_host_adapter_available() -> bool:
    try:
        from skg_domain_host.adapters.host_ssh_assessment.run import map_ssh_assessments_to_events
        from skg_domain_host.adapters.host_winrm_assessment.run import map_winrm_assessments_to_events
    except Exception:
        return False
    return callable(map_ssh_assessments_to_events) and callable(map_winrm_assessments_to_events)


def _require_ssh_mapper():
    try:
        from skg_domain_host.adapters.host_ssh_assessment.run import map_ssh_assessments_to_events
    except Exception as exc:
        raise RuntimeError(
            "Canonical host domain adapter unavailable: "
            "skg_domain_host.adapters.host_ssh_assessment.run"
        ) from exc
    return map_ssh_assessments_to_events


def _require_winrm_mapper():
    try:
        from skg_domain_host.adapters.host_winrm_assessment.run import map_winrm_assessments_to_events
    except Exception as exc:
        raise RuntimeError(
            "Canonical host domain adapter unavailable: "
            "skg_domain_host.adapters.host_winrm_assessment.run"
        ) from exc
    return map_winrm_assessments_to_events


def _safe_channel_read(stream: Any) -> str:
    try:
        return stream.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _exec_ssh_command(client: Any, cmd: str, *, timeout: int = 15) -> tuple[str, str, int]:
    try:
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = _safe_channel_read(stdout)
        err = _safe_channel_read(stderr)
        rc = int(stdout.channel.recv_exit_status())
        return out, err, rc
    except Exception as exc:
        return "", str(exc), -1


def _is_admin_from_id_output(id_output: str) -> bool | None:
    text = str(id_output or "").lower()
    if not text:
        return None
    if "uid=0" in text or "gid=0" in text:
        return True
    return False


def _is_nopasswd(sudo_output: str) -> bool | None:
    text = str(sudo_output or "")
    if not text:
        return None
    if re.search(r"NOPASSWD", text, re.IGNORECASE):
        return True
    if "not allowed" in text.lower() or "password" in text.lower():
        return False
    return None


def _kernel_release(uname_output: str) -> str:
    value = str(uname_output or "").strip()
    if not value:
        return ""
    return value.split()[0]


def _write_events_ndjson(events: list[Mapping[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(dict(event), sort_keys=True) + "\n")


def collect_ssh_session_assessment(
    client: Any,
    *,
    host: str,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    username: str = "",
    auth_type: str = "",
    port: int = 22,
) -> list[dict[str, Any]]:
    """Collect minimal SSH runtime observations and map them via canonical host adapter."""

    mapper = _require_ssh_mapper()

    id_out, _id_err, _id_rc = _exec_ssh_command(client, "id")
    sudo_out, _sudo_err, _sudo_rc = _exec_ssh_command(client, "sudo -l -n 2>&1")
    uname_out, _uname_err, _uname_rc = _exec_ssh_command(client, "uname -r")

    assessment = {
        "host": host,
        "port": int(port or 22),
        "username": str(username or ""),
        "auth_type": str(auth_type or ""),
        "reachable": True,
        "ssh_exposed": True,
        "credential_valid": True,
        "is_admin": _is_admin_from_id_output(id_out),
        "sudo_nopasswd": _is_nopasswd(sudo_out),
        "kernel_release": _kernel_release(uname_out),
        "id_output": id_out,
        "sudo_output": sudo_out,
    }

    return mapper(
        [assessment],
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
    )


def collect_ssh_session_assessment_to_file(
    client: Any,
    *,
    host: str,
    out_path: Path,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    username: str = "",
    auth_type: str = "",
    port: int = 22,
) -> list[dict[str, Any]]:
    events = collect_ssh_session_assessment(
        client,
        host=host,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        username=username,
        auth_type=auth_type,
        port=port,
    )
    _write_events_ndjson(events, out_path)
    return events


def _tcp_reachable(host: str, port: int, *, timeout: float) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def collect_ssh_assessment(
    host: str,
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    username: str = "root",
    password: str = "",
    key: str = "",
    port: int = 22,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Service-owned SSH runtime wrapper that maps through canonical host adapter."""

    mapper = _require_ssh_mapper()
    reachable = _tcp_reachable(host, int(port), timeout=timeout)
    if not reachable:
        assessment = {
            "host": host,
            "port": int(port),
            "username": username,
            "auth_type": "unattempted",
            "reachable": False,
            "ssh_exposed": False,
            "credential_valid": None,
            "is_admin": None,
            "sudo_nopasswd": None,
            "kernel_release": "",
            "id_output": "",
            "sudo_output": "",
        }
        return mapper([assessment], attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id)

    try:
        import paramiko
    except Exception as exc:
        raise RuntimeError("paramiko is required for SSH runtime collection") from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    auth_type = "agent/default"
    try:
        if key:
            auth_type = "key"
            client.connect(
                host,
                port=int(port),
                username=username,
                key_filename=os.path.expanduser(key),
                timeout=timeout,
            )
        elif password:
            auth_type = "password"
            client.connect(
                host,
                port=int(port),
                username=username,
                password=os.path.expandvars(password),
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        else:
            client.connect(host, port=int(port), username=username, timeout=timeout)

        return collect_ssh_session_assessment(
            client,
            host=host,
            attack_path_id=attack_path_id,
            run_id=run_id,
            workload_id=workload_id,
            username=username,
            auth_type=auth_type,
            port=port,
        )
    except Exception:
        assessment = {
            "host": host,
            "port": int(port),
            "username": username,
            "auth_type": auth_type,
            "reachable": True,
            "ssh_exposed": True,
            "credential_valid": False,
            "is_admin": None,
            "sudo_nopasswd": None,
            "kernel_release": "",
            "id_output": "",
            "sudo_output": "",
        }
        return mapper([assessment], attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id)
    finally:
        try:
            client.close()
        except Exception:
            pass


def collect_ssh_assessment_to_file(
    host: str,
    *,
    out_path: Path,
    attack_path_id: str,
    run_id: str = "",
    workload_id: str = "",
    username: str = "root",
    password: str = "",
    key: str = "",
    port: int = 22,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    canonical_run_id = str(run_id or str(uuid.uuid4()))
    canonical_workload_id = str(workload_id or f"ssh::{host}")
    events = collect_ssh_assessment(
        host,
        attack_path_id=attack_path_id,
        run_id=canonical_run_id,
        workload_id=canonical_workload_id,
        username=username,
        password=password,
        key=key,
        port=port,
        timeout=timeout,
    )
    _write_events_ndjson(events, out_path)
    return events


def _winrm_run_ps(session: Any, cmd: str) -> tuple[str, int]:
    try:
        result = session.run_ps(cmd)
        out = result.std_out.decode("utf-8", errors="replace").strip() if result.std_out else ""
        return out, int(getattr(result, "status_code", -1))
    except Exception:
        return "", -1


def _winrm_is_admin(whoami_groups: str) -> bool | None:
    text = str(whoami_groups or "")
    if not text:
        return None
    if "S-1-5-32-544" in text or "Administrators" in text or "Domain Admins" in text:
        return True
    return False


def collect_winrm_session_assessment(
    session: Any,
    *,
    host: str,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    username: str = "",
    port: int = 5985,
) -> list[dict[str, Any]]:
    """Collect minimal WinRM runtime observations and map through canonical host adapter."""

    mapper = _require_winrm_mapper()

    whoami_groups, _whoami_rc = _winrm_run_ps(session, "whoami /groups")
    env_text, _env_rc = _winrm_run_ps(session, "Get-ChildItem Env: | ConvertTo-Json -Compress")

    assessment = {
        "host": host,
        "port": int(port or 5985),
        "username": str(username or ""),
        "winrm_exposed": True,
        "credential_valid": True,
        "is_admin": _winrm_is_admin(whoami_groups),
        "credential_in_env": None,
        "env_text": env_text,
        "whoami_groups": whoami_groups,
    }

    return mapper(
        [assessment],
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
    )


def collect_winrm_session_assessment_to_file(
    session: Any,
    *,
    host: str,
    out_path: Path,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    username: str = "",
    port: int = 5985,
) -> list[dict[str, Any]]:
    events = collect_winrm_session_assessment(
        session,
        host=host,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        username=username,
        port=port,
    )
    _write_events_ndjson(events, out_path)
    return events


def collect_winrm_assessment(
    host: str,
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    username: str,
    password: str,
    port: int = 5985,
    ssl: bool = False,
) -> list[dict[str, Any]]:
    """Service-owned WinRM runtime wrapper that maps through canonical host adapter."""

    mapper = _require_winrm_mapper()

    try:
        import winrm
    except Exception as exc:
        raise RuntimeError("pywinrm is required for WinRM runtime collection") from exc

    endpoint = f"{'https' if ssl else 'http'}://{host}:{int(port)}/wsman"
    try:
        session = winrm.Session(endpoint, auth=(username, password), transport=("ssl" if ssl else "ntlm"))
        test = session.run_ps("$true")
        if int(getattr(test, "status_code", -1)) != 0:
            raise RuntimeError("WinRM test command failed")
    except Exception:
        assessment = {
            "host": host,
            "port": int(port),
            "username": username,
            "winrm_exposed": True,
            "credential_valid": False,
            "is_admin": None,
            "credential_in_env": None,
            "env_text": "",
            "whoami_groups": "",
        }
        return mapper([assessment], attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id)

    return collect_winrm_session_assessment(
        session,
        host=host,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        username=username,
        port=port,
    )


def collect_winrm_assessment_to_file(
    host: str,
    *,
    out_path: Path,
    attack_path_id: str,
    run_id: str = "",
    workload_id: str = "",
    username: str,
    password: str,
    port: int = 5985,
    ssl: bool = False,
) -> list[dict[str, Any]]:
    canonical_run_id = str(run_id or str(uuid.uuid4()))
    canonical_workload_id = str(workload_id or f"winrm::{host}")
    events = collect_winrm_assessment(
        host,
        attack_path_id=attack_path_id,
        run_id=canonical_run_id,
        workload_id=canonical_workload_id,
        username=username,
        password=password,
        port=port,
        ssl=ssl,
    )
    _write_events_ndjson(events, out_path)
    return events


def _load_host_toolchain_adapter(relative_py: str, module_name: str):
    """
    Load a skg-host-toolchain adapter by path relative to SKG_HOME.
    Centralises the spec_from_file_location pattern away from gravity_field.py.
    """
    import importlib.util as _ilu
    from skg.core.paths import SKG_HOME
    from pathlib import Path as _Path
    path = _Path(SKG_HOME) / "skg-host-toolchain" / relative_py
    spec = _ilu.spec_from_file_location(module_name, path)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def collect_enum4linux_events(
    target_ip: str,
    *,
    out_dir: "Path",
    username: str = "",
    password: str = "",
) -> "list[dict[str, Any]]":
    """Run enum4linux-ng against target_ip and return SKG precondition events."""
    mod = _load_host_toolchain_adapter(
        "adapters/smb_collect/enum4linux_adapter.py", "enum4linux_adapter"
    )
    return mod.run_enum4linux(target_ip, out_dir, username=username, password=password)


def collect_enum4linux_events_to_file(
    target_ip: str,
    *,
    out_path: "Path",
    username: str = "",
    password: str = "",
) -> "list[dict[str, Any]]":
    """Run enum4linux-ng and write events NDJSON to out_path. Returns event list."""
    from pathlib import Path as _Path
    out_dir = _Path(out_path).parent
    events = collect_enum4linux_events(
        target_ip, out_dir=out_dir, username=username, password=password
    )
    _write_events_ndjson(events, _Path(out_path))
    return events


def collect_searchsploit_events(
    service_banners: "list[dict]",
    *,
    out_dir: "Path",
) -> "list[dict[str, Any]]":
    """
    Run searchsploit against service_banners and return SKG precondition events.
    service_banners: [{"service": "ssh", "banner": "OpenSSH 7.4", "port": 22, "target_ip": "..."}]
    """
    mod = _load_host_toolchain_adapter(
        "adapters/ssh_collect/searchsploit_adapter.py", "searchsploit_adapter"
    )
    return mod.run_searchsploit(service_banners, out_dir)


def collect_searchsploit_events_to_file(
    service_banners: "list[dict]",
    *,
    out_path: "Path",
) -> "list[dict[str, Any]]":
    """Run searchsploit and write events NDJSON to out_path. Returns event list."""
    from pathlib import Path as _Path
    out_dir = _Path(out_path).parent
    events = collect_searchsploit_events(service_banners, out_dir=out_dir)
    _write_events_ndjson(events, _Path(out_path))
    return events


__all__ = [
    "canonical_host_adapter_available",
    "collect_enum4linux_events",
    "collect_enum4linux_events_to_file",
    "collect_searchsploit_events",
    "collect_searchsploit_events_to_file",
    "collect_ssh_assessment",
    "collect_ssh_assessment_to_file",
    "collect_ssh_session_assessment",
    "collect_ssh_session_assessment_to_file",
    "collect_winrm_assessment",
    "collect_winrm_assessment_to_file",
    "collect_winrm_session_assessment",
    "collect_winrm_session_assessment_to_file",
]
