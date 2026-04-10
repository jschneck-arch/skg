from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(slots=True)
class ManifestComponents:
    adapters: str = "adapters"
    projectors: str = "projectors"
    policies: str = "policies"
    contracts_catalogs: str = "contracts/catalogs"


@dataclass(slots=True)
class DomainManifest:
    name: str
    runtime: str = "domain-pack"
    status: str = "active"
    version: str = "1.0.0"
    protocol_version: str = "1.0"
    compatibility: dict[str, Any] = field(default_factory=dict)
    components: ManifestComponents = field(default_factory=ManifestComponents)
    metadata: dict[str, Any] = field(default_factory=dict)


def _component_paths(data: Mapping[str, Any]) -> ManifestComponents:
    components_raw = data.get("components")
    contracts_raw = data.get("contracts")

    adapters = "adapters"
    projectors = "projectors"
    policies = "policies"
    catalogs = "contracts/catalogs"

    if isinstance(components_raw, Mapping):
        adapters = str(components_raw.get("adapters") or adapters)
        projectors = str(components_raw.get("projectors") or projectors)
        policies = str(components_raw.get("policies") or policies)

    if isinstance(contracts_raw, Mapping):
        catalogs = str(contracts_raw.get("catalogs") or catalogs)

    return ManifestComponents(
        adapters=adapters,
        projectors=projectors,
        policies=policies,
        contracts_catalogs=catalogs,
    )


def normalize_manifest(data: Mapping[str, Any], *, source: str = "") -> DomainManifest:
    """Normalize domain manifests from new packs and legacy toolchains."""

    name = str(
        data.get("name")
        or data.get("domain")
        or data.get("toolchain")
        or ""
    ).strip()

    compatibility = data.get("compatibility") if isinstance(data.get("compatibility"), Mapping) else {}

    protocol_version = str(
        compatibility.get("protocol")
        or compatibility.get("protocol_version")
        or data.get("protocol")
        or data.get("protocol_version")
        or "1.0"
    )

    metadata = {
        "source": source,
        "description": str(data.get("description") or "").strip(),
    }

    if isinstance(data.get("metadata"), Mapping):
        metadata.update(dict(data["metadata"]))

    return DomainManifest(
        name=name,
        runtime=str(data.get("runtime") or "domain-pack"),
        status=str(data.get("status") or "active"),
        version=str(data.get("version") or data.get("manifest_version") or "1.0.0"),
        protocol_version=protocol_version,
        compatibility=dict(compatibility),
        components=_component_paths(data),
        metadata=metadata,
    )
