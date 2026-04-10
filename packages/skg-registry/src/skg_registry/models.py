from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from skg_protocol.contracts.manifest import DomainManifest


@dataclass(slots=True)
class DomainRecord:
    """Resolved domain entry used by services to consume public contracts."""

    name: str
    root_dir: Path
    manifest_path: Path
    manifest_kind: str
    manifest: DomainManifest

    adapters_dir: Path
    projectors_dir: Path
    policies_dir: Path
    catalogs_dir: Path

    def list_adapters(self) -> list[str]:
        if not self.adapters_dir.exists():
            return []
        return sorted(path.name for path in self.adapters_dir.iterdir() if path.is_dir())

    def list_projectors(self) -> list[str]:
        if not self.projectors_dir.exists():
            return []
        return sorted(path.name for path in self.projectors_dir.iterdir() if path.is_dir())

    def list_policies(self) -> list[str]:
        if not self.policies_dir.exists():
            return []
        return sorted(path.name for path in self.policies_dir.iterdir() if path.is_dir())
