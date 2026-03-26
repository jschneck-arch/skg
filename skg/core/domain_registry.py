from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from skg.core.paths import SKG_CONFIG_DIR, SKG_HOME


_DEFAULT_DOMAIN_REGISTRY: dict[str, Any] = {
    "domains": [
        {
            "name": "aprs",
            "daemon_native": True,
            "dir": "skg-aprs-toolchain",
            "cli": "skg.py",
            "project_sub": ["project", "aprs"],
            "interp_type": "interp.attack_path.realizability",
            "default_path": "log4j_jndi_rce_v1",
            "description": "APRS and radio telemetry substrate",
        },
        {
            "name": "container_escape",
            "daemon_native": True,
            "dir": "skg-container-escape-toolchain",
            "cli": "skg_escape.py",
            "project_sub": ["project"],
            "interp_type": "interp.container_escape.realizability",
            "default_path": "container_escape_privileged_v1",
            "description": "Container escape and kubelet exposure",
        },
        {
            "name": "ad_lateral",
            "daemon_native": True,
            "dir": "skg-ad-lateral-toolchain",
            "cli": "skg_lateral.py",
            "project_sub": ["project"],
            "interp_type": "interp.ad_lateral.realizability",
            "default_path": "ad_kerberoast_v1",
            "description": "Active Directory and lateral movement",
        },
        {
            "name": "host",
            "daemon_native": True,
            "dir": "skg-host-toolchain",
            "cli": "skg_host.py",
            "project_sub": ["project"],
            "interp_type": "interp.host.realizability",
            "default_path": "host_ssh_initial_access_v1",
            "description": "Host reachability and SSH-based collection",
        },
        {
            "name": "data",
            "daemon_native": True,
            "dir": "skg-data-toolchain",
            "cli": "skg_data.py",
            "project_sub": ["project"],
            "interp_type": "interp.data.pipeline",
            "default_path": "data_completeness_failure_v1",
            "description": "Database and data pipeline telemetry",
        },
        {
            "name": "web",
            "daemon_native": False,
            "dir": "skg-web-toolchain",
            "description": "Auxiliary or forge-installed web coverage",
        },
        {
            "name": "nginx",
            "daemon_native": False,
            "dir": "skg-nginx-toolchain",
            "description": "Auxiliary nginx configuration and fingerprinting",
        },
        {
            "name": "binary",
            "daemon_native": False,
            "dir": "skg-binary-toolchain",
            "description": "Binary analysis and SUID coverage",
        },
        {
            "name": "ai_target",
            "daemon_native": False,
            "dir": "skg-ai-toolchain",
            "description": "AI/LLM service exposure coverage",
        },
        {
            "name": "supply_chain",
            "daemon_native": False,
            "dir": "skg-supply-chain-toolchain",
            "description": "Supply chain and SBOM coverage",
        },
        {
            "name": "iot_firmware",
            "daemon_native": False,
            "dir": "skg-iot_firmware-toolchain",
            "description": "IoT and firmware coverage",
        },
        {
            "name": "metacognition",
            "daemon_native": False,
            "dir": "skg-metacognition-toolchain",
            "description": "Metacognitive and cognitive probe coverage",
        },
    ],
}


def _registry_paths() -> list[Path]:
    return [
        SKG_CONFIG_DIR / "daemon_domains.yaml",
        SKG_HOME / "config" / "daemon_domains.yaml",
    ]


def _load_registry_payload() -> dict[str, Any]:
    for path in _registry_paths():
        if not path.exists():
            continue
        try:
            payload = yaml.safe_load(path.read_text()) or {}
        except Exception:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("domains"), list):
            return payload
    return deepcopy(_DEFAULT_DOMAIN_REGISTRY)


def load_domain_inventory() -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    payload = _load_registry_payload()
    for row in payload.get("domains", []) or []:
        item = dict(row or {})
        name = str(item.get("name") or item.get("domain") or "").strip()
        if not name:
            continue
        item["name"] = name
        item["daemon_native"] = bool(item.get("daemon_native", False))
        project_sub = item.get("project_sub") or []
        item["project_sub"] = [str(part) for part in project_sub]
        dir_value = str(item.get("dir") or "").strip()
        if dir_value:
            dir_path = Path(dir_value)
            if not dir_path.is_absolute():
                dir_path = SKG_HOME / dir_value
            item["dir"] = dir_path
        inventory.append(item)
    return inventory


def load_daemon_domains() -> dict[str, dict[str, Any]]:
    domains: dict[str, dict[str, Any]] = {}
    for item in load_domain_inventory():
        if not item.get("daemon_native"):
            continue
        required = ("dir", "cli", "project_sub", "interp_type", "default_path")
        missing = [key for key in required if not item.get(key)]
        if missing:
            continue
        domains[item["name"]] = {
            "dir": item["dir"],
            "cli": item["cli"],
            "project_sub": list(item["project_sub"]),
            "interp_type": item["interp_type"],
            "default_path": item["default_path"],
            "description": item.get("description", ""),
        }
    return domains


def summarize_domain_inventory(inventory: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows = inventory if inventory is not None else load_domain_inventory()
    return [
        {
            "name": row.get("name", ""),
            "daemon_native": bool(row.get("daemon_native", False)),
            "dir": str(row.get("dir", "")),
            "default_path": row.get("default_path", ""),
            "description": row.get("description", ""),
        }
        for row in rows
    ]
