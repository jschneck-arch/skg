from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from skg_core.config.paths import SKG_CONFIG_DIR, SKG_HOME
try:
    from skg_registry import DomainRegistry as _CanonicalDomainRegistry
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    _CanonicalDomainRegistry = None

try:
    from skg_services.gravity.domain_runtime import (
        load_daemon_domains_from_inventory as _service_load_daemon_domains_from_inventory,
    )
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    _service_load_daemon_domains_from_inventory = None


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


def _domain_from_toolchain_dir(name: str) -> str:
    if not name.startswith("skg-") or not name.endswith("-toolchain"):
        return name.replace("-", "_")
    middle = name[len("skg-"):-len("-toolchain")]
    return middle.replace("-", "_")


def _load_manifest(tc_dir: Path) -> dict[str, Any]:
    manifest = tc_dir / "forge_meta.json"
    if not manifest.exists():
        return {}
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _infer_default_path(tc_dir: Path, manifest: dict[str, Any]) -> str:
    for key in ("default_path", "default_attack_path"):
        value = str(manifest.get(key) or "").strip()
        if value:
            return value

    for key in ("attack_path_ids", "capability_paths"):
        values = manifest.get(key)
        if isinstance(values, list):
            for item in values:
                value = str(item or "").strip()
                if value:
                    return value

    catalogs_dir = tc_dir / "contracts" / "catalogs"
    for catalog_file in sorted(catalogs_dir.glob("*.json")):
        try:
            catalog = json.loads(catalog_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        attack_paths = catalog.get("attack_paths") or {}
        if isinstance(attack_paths, dict) and attack_paths:
            return str(next(iter(attack_paths.keys())))
        if isinstance(attack_paths, list):
            for item in attack_paths:
                if isinstance(item, dict) and item.get("id"):
                    return str(item["id"])
    return ""


def _discover_projector_run(tc_dir: Path) -> Path | None:
    nested = sorted(tc_dir.glob("projections/*/run.py"))
    if nested:
        return nested[0]
    root_run = tc_dir / "projections" / "run.py"
    if root_run.exists():
        return root_run
    return None


def _discover_toolchain_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for tc_dir in sorted(SKG_HOME.glob("skg-*-toolchain")):
        if not tc_dir.is_dir() or tc_dir.name.endswith(".backup"):
            continue

        manifest = _load_manifest(tc_dir)
        domain = str(manifest.get("domain") or _domain_from_toolchain_dir(tc_dir.name)).strip()
        description = str(manifest.get("description") or "").strip()
        cli_candidates = sorted(p.name for p in tc_dir.glob("skg*.py"))
        projector_run = _discover_projector_run(tc_dir)
        catalogs = sorted((tc_dir / "contracts" / "catalogs").glob("*.json"))
        venv_python = tc_dir / ".venv" / "bin" / "python"

        row: dict[str, Any] = {
            "name": domain,
            "dir": tc_dir,
            "daemon_native": False,
            "description": description or f"{domain} toolchain",
            "default_path": _infer_default_path(tc_dir, manifest),
            "toolchain": str(manifest.get("toolchain") or tc_dir.name),
            "manifest_present": bool(manifest),
            "manifest_path": str(tc_dir / "forge_meta.json") if (tc_dir / "forge_meta.json").exists() else "",
            "catalog_count": len(catalogs),
            "projector_available": projector_run is not None,
            "projector_path": str(projector_run.relative_to(tc_dir)) if projector_run else "",
            "cli_available": bool(cli_candidates),
            "cli": cli_candidates[0] if cli_candidates else "",
            "bootstrapped": bool(cli_candidates) and venv_python.exists(),
        }
        rows.append(row)
    return rows


def _merge_inventory(
    discovered: list[dict[str, Any]],
    configured: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}

    for row in discovered:
        merged[str(row.get("name") or "")] = dict(row)

    for row in configured:
        item = dict(row or {})
        name = str(item.get("name") or item.get("domain") or "").strip()
        if not name:
            continue
        base = dict(merged.get(name, {}))
        base.update(item)
        merged[name] = base

    return [merged[name] for name in sorted(merged)]


def load_domain_inventory() -> list[dict[str, Any]]:
    if _CanonicalDomainRegistry is not None:
        rows: list[dict[str, Any]] = []
        _search_roots = [SKG_HOME / "packages" / "skg-domains", SKG_HOME]
        for domain in _CanonicalDomainRegistry.discover(search_roots=_search_roots).list_domains():
            projector_path = ""
            projector_available = False
            if domain.projectors_dir.exists():
                run_root = domain.projectors_dir / "run.py"
                if run_root.exists():
                    projector_available = True
                    projector_path = str(run_root.relative_to(domain.root_dir))
                else:
                    nested = sorted(domain.projectors_dir.glob("*/run.py"))
                    if nested:
                        projector_available = True
                        projector_path = str(nested[0].relative_to(domain.root_dir))

            metadata = dict(domain.manifest.metadata or {})
            default_path = str(
                metadata.get("default_path")
                or metadata.get("default_attack_path")
                or ""
            ).strip()
            if not default_path:
                default_path = _infer_default_path(domain.root_dir, {})
            project_sub = metadata.get("project_sub") or []
            if not isinstance(project_sub, list):
                project_sub = []

            rows.append(
                {
                    "name": domain.name,
                    "runtime": domain.manifest.runtime,
                    "daemon_native": bool(metadata.get("daemon_native", False)),
                    "dir": domain.root_dir,
                    "root_dir": domain.root_dir,
                    "toolchain": domain.root_dir.name,
                    "description": str(metadata.get("description") or ""),
                    "default_path": default_path,
                    "project_sub": [str(part) for part in project_sub],
                    "interp_type": str(metadata.get("interp_type") or ""),
                    "manifest_present": domain.manifest_path.exists(),
                    "manifest_path": str(domain.manifest_path),
                    "catalog_count": len(list(domain.catalogs_dir.glob("*.json"))) if domain.catalogs_dir.exists() else 0,
                    "projector_available": projector_available,
                    "projector_path": projector_path,
                    "cli_available": bool(metadata.get("cli")),
                    "cli": str(metadata.get("cli") or ""),
                    "bootstrapped": bool(metadata.get("bootstrapped", False)),
                }
            )
        # Merge operator config (daemon_domains.yaml) onto discovered rows.
        config_payload = _load_registry_payload()
        config_by_name: dict[str, dict[str, Any]] = {}
        for item in config_payload.get("domains", []) or []:
            n = str(item.get("name") or item.get("domain") or "").strip()
            if n:
                config_by_name[n] = dict(item)
        merged: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            name = str(row.get("name") or "").strip()
            seen.add(name)
            cfg = config_by_name.get(name, {})
            if cfg:
                merged_row = dict(row)
                for k, v in cfg.items():
                    if k == "dir":
                        # Resolve relative dir from config against SKG_HOME.
                        dv = v if isinstance(v, Path) else Path(str(v or "").strip())
                        if dv and not dv.is_absolute():
                            dv = SKG_HOME / dv
                        if dv:
                            merged_row["dir"] = dv
                    elif k not in ("name",):
                        if v is not None:
                            merged_row[k] = v
                merged.append(merged_row)
            else:
                merged.append(row)
        # Add config-only entries (domains in config but not discovered on disk).
        for name, cfg in config_by_name.items():
            if name in seen:
                continue
            item = dict(cfg)
            item["name"] = name
            dir_value = item.get("dir")
            if dir_value:
                dir_path = dir_value if isinstance(dir_value, Path) else Path(str(dir_value).strip())
                if not dir_path.is_absolute():
                    dir_path = SKG_HOME / dir_path
                item["dir"] = dir_path
                item.setdefault("root_dir", dir_path)
                item.setdefault("manifest_present", (dir_path / "forge_meta.json").exists())
                item.setdefault("projector_available", _discover_projector_run(dir_path) is not None)
                proj = _discover_projector_run(dir_path)
                item.setdefault("projector_path", str(proj.relative_to(dir_path)) if proj else "")
                item.setdefault("default_path", _infer_default_path(dir_path, _load_manifest(dir_path)))
            item.setdefault("daemon_native", False)
            merged.append(item)
        return merged

    inventory: list[dict[str, Any]] = []
    payload = _load_registry_payload()
    rows = _merge_inventory(
        _discover_toolchain_rows(),
        list(payload.get("domains", []) or []),
    )
    for row in rows:
        item = dict(row or {})
        name = str(item.get("name") or item.get("domain") or "").strip()
        if not name:
            continue
        item["name"] = name
        item["daemon_native"] = bool(item.get("daemon_native", False))
        project_sub = item.get("project_sub") or []
        item["project_sub"] = [str(part) for part in project_sub]
        dir_value = item.get("dir")
        if dir_value:
            dir_path = dir_value if isinstance(dir_value, Path) else Path(str(dir_value).strip())
            if not dir_path.is_absolute():
                dir_path = SKG_HOME / dir_path
            item["dir"] = dir_path
            if not item.get("toolchain"):
                item["toolchain"] = dir_path.name
            if "manifest_present" not in item:
                item["manifest_present"] = bool((dir_path / "forge_meta.json").exists())
            if "manifest_path" not in item:
                item["manifest_path"] = str(dir_path / "forge_meta.json") if (dir_path / "forge_meta.json").exists() else ""
            if "catalog_count" not in item:
                item["catalog_count"] = len(list((dir_path / "contracts" / "catalogs").glob("*.json")))
            if "projector_available" not in item:
                item["projector_available"] = _discover_projector_run(dir_path) is not None
            if "projector_path" not in item:
                proj = _discover_projector_run(dir_path)
                item["projector_path"] = str(proj.relative_to(dir_path)) if proj else ""
            if "cli_available" not in item:
                item["cli_available"] = bool(item.get("cli"))
            if "bootstrapped" not in item:
                cli_name = str(item.get("cli") or "").strip()
                item["bootstrapped"] = bool(cli_name) and (dir_path / ".venv" / "bin" / "python").exists()
            if not item.get("default_path"):
                item["default_path"] = _infer_default_path(dir_path, _load_manifest(dir_path))
        inventory.append(item)
    return inventory


def load_daemon_domains() -> dict[str, dict[str, Any]]:
    if _service_load_daemon_domains_from_inventory is not None:
        return _service_load_daemon_domains_from_inventory(load_domain_inventory())

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
            "manifest_present": bool(row.get("manifest_present", False)),
            "catalog_count": int(row.get("catalog_count", 0) or 0),
            "projector_available": bool(row.get("projector_available", False)),
            "projector_path": row.get("projector_path", ""),
            "cli_available": bool(row.get("cli_available", False)),
            "bootstrapped": bool(row.get("bootstrapped", False)),
        }
        for row in rows
    ]
