from __future__ import annotations

from pathlib import Path
from typing import Any

# Service policy: first-party daemon-native domains in legacy runtime mode.
DEFAULT_DAEMON_DOMAIN_KEYS = {
    "aprs",
    "container_escape",
    "ad_lateral",
    "host",
    "data",
}

# Service policy defaults for daemon execution hints.
DAEMON_DEFAULTS: dict[str, dict[str, Any]] = {
    "aprs": {
        "cli": "skg.py",
        "project_sub": ["project", "aprs"],
        "interp_type": "interp.attack_path.realizability",
        "default_path": "log4j_jndi_rce_v1",
    },
    "container_escape": {
        "cli": "skg_escape.py",
        "project_sub": ["project"],
        "interp_type": "interp.container_escape.realizability",
        "default_path": "container_escape_privileged_v1",
    },
    "ad_lateral": {
        "cli": "skg_lateral.py",
        "project_sub": ["project"],
        "interp_type": "interp.ad_lateral.realizability",
        "default_path": "ad_kerberoast_v1",
    },
    "host": {
        "cli": "skg_host.py",
        "project_sub": ["project"],
        "interp_type": "interp.host.realizability",
        "default_path": "host_ssh_initial_access_v1",
    },
    "data": {
        "cli": "skg_data.py",
        "project_sub": ["project"],
        "interp_type": "interp.data.pipeline",
        "default_path": "data_completeness_failure_v1",
    },
}


def load_daemon_domains_from_inventory(inventory: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Derive daemon runtime domains from registry inventory plus service defaults."""

    domains: dict[str, dict[str, Any]] = {}

    for row in inventory:
        name = str(row.get("name") or row.get("domain") or "").strip()
        if not name:
            continue

        runtime = str(row.get("runtime") or "").strip().lower()
        daemon_native = bool(row.get("daemon_native", False))
        if not daemon_native:
            daemon_native = name in DEFAULT_DAEMON_DOMAIN_KEYS
        if runtime == "domain-pack" and name not in DEFAULT_DAEMON_DOMAIN_KEYS:
            daemon_native = False
        if not daemon_native:
            continue

        dir_value = row.get("dir")
        if isinstance(dir_value, Path):
            domain_dir = dir_value
        elif dir_value:
            domain_dir = Path(str(dir_value))
        else:
            domain_dir = Path(str(row.get("root_dir") or ""))

        defaults = dict(DAEMON_DEFAULTS.get(name, {}))
        cli = str(row.get("cli") or defaults.get("cli") or "").strip()
        project_sub = list(row.get("project_sub") or defaults.get("project_sub") or [])
        interp_type = str(row.get("interp_type") or defaults.get("interp_type") or "").strip()
        default_path = str(row.get("default_path") or defaults.get("default_path") or "").strip()

        required = [domain_dir, cli, project_sub, interp_type, default_path]
        if not all(required):
            continue

        domains[name] = {
            "dir": domain_dir,
            "cli": cli,
            "project_sub": [str(part) for part in project_sub],
            "interp_type": interp_type,
            "default_path": default_path,
            "description": str(row.get("description") or "").strip(),
        }

    return domains
