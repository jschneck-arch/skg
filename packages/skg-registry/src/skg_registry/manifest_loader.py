from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from skg_protocol.contracts.manifest import DomainManifest, normalize_manifest


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {}


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    return {}


def load_domain_manifest(path: Path) -> DomainManifest:
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        payload = _load_yaml(path)
    elif suffix == ".json":
        payload = _load_json(path)
    else:
        raise ValueError(f"Unsupported manifest format: {path}")

    return normalize_manifest(payload, source=str(path))


def infer_legacy_manifest(toolchain_dir: Path) -> tuple[Path, DomainManifest]:
    forge_meta = toolchain_dir / "forge_meta.json"
    if forge_meta.exists():
        manifest = load_domain_manifest(forge_meta)
        if not manifest.name:
            manifest.name = _domain_name_from_toolchain(toolchain_dir.name)
        # Legacy toolchains use "projections/" not "projectors/" — fix default when unspecified.
        if manifest.components.projectors == "projectors" and (toolchain_dir / "projections").exists():
            manifest.components.projectors = "projections"
        return forge_meta, manifest

    payload: dict[str, Any] = {
        "name": _domain_name_from_toolchain(toolchain_dir.name),
        "runtime": "legacy-toolchain",
        "status": "legacy",
        "version": "0.0.0",
        "protocol": "1.0",
        "components": {
            "adapters": "adapters",
            "projectors": "projections",
            "policies": "policies",
        },
        "contracts": {
            "catalogs": "contracts/catalogs",
        },
        "metadata": {
            "legacy_toolchain": toolchain_dir.name,
        },
    }
    manifest = normalize_manifest(payload, source=str(toolchain_dir))
    return toolchain_dir, manifest


def _domain_name_from_toolchain(dirname: str) -> str:
    text = dirname
    if text.startswith("skg-"):
        text = text[len("skg-") :]
    if text.endswith("-toolchain"):
        text = text[: -len("-toolchain")]
    return text.replace("-", "_")
