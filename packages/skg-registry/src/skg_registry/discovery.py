from __future__ import annotations

from pathlib import Path
from typing import Iterable

from skg_registry.manifest_loader import infer_legacy_manifest, load_domain_manifest
from skg_registry.models import DomainRecord


def _find_repo_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "packages" / "skg-domains").exists():
            return candidate
        if (candidate / ".git").exists():
            return candidate
    return current


def default_search_roots(start: Path | None = None) -> list[Path]:
    repo_root = _find_repo_root(start)
    return [
        repo_root / "packages" / "skg-domains",
        repo_root,
    ]


def _domain_pack_manifest_path(domain_dir: Path) -> Path | None:
    """
    Resolve manifest authority for a domain pack.

    Authority order:
    1. In-package manifest: src/skg_domain_<name>/manifest.{yaml,yml,json}
    2. Legacy compatibility manifest: domain.{yaml,yml,json}
    """

    domain_key = domain_dir.name.replace("-", "_")
    canonical_dir = domain_dir / "src" / f"skg_domain_{domain_key}"
    canonical_candidates = [
        canonical_dir / "manifest.yaml",
        canonical_dir / "manifest.yml",
        canonical_dir / "manifest.json",
    ]
    for candidate in canonical_candidates:
        if candidate.exists():
            return candidate

    src_root = domain_dir / "src"
    if src_root.exists():
        for pattern in ("skg_domain_*/manifest.yaml", "skg_domain_*/manifest.yml", "skg_domain_*/manifest.json"):
            matches = sorted(src_root.glob(pattern))
            if matches:
                return matches[0]

    legacy_candidates = [
        domain_dir / "domain.yaml",
        domain_dir / "domain.yml",
        domain_dir / "domain.json",
    ]
    for candidate in legacy_candidates:
        if candidate.exists():
            return candidate
    return None


def _discover_domain_pack_records(domains_root: Path) -> list[DomainRecord]:
    records: list[DomainRecord] = []
    if not domains_root.exists():
        return records

    for domain_dir in sorted(domains_root.iterdir()):
        if not domain_dir.is_dir():
            continue
        manifest_path = _domain_pack_manifest_path(domain_dir)
        if manifest_path is None:
            continue

        manifest = load_domain_manifest(manifest_path)
        if not manifest.name:
            manifest.name = domain_dir.name.replace("-", "_")

        component_root = manifest_path.parent

        records.append(
            DomainRecord(
                name=manifest.name,
                root_dir=domain_dir,
                manifest_path=manifest_path,
                manifest_kind="domain-pack",
                manifest=manifest,
                adapters_dir=component_root / manifest.components.adapters,
                projectors_dir=component_root / manifest.components.projectors,
                policies_dir=component_root / manifest.components.policies,
                catalogs_dir=component_root / manifest.components.contracts_catalogs,
            )
        )
    return records


def _discover_legacy_toolchain_records(repo_root: Path) -> list[DomainRecord]:
    records: list[DomainRecord] = []
    if not repo_root.exists():
        return records

    for entry in sorted(repo_root.iterdir()):
        if not entry.is_dir():
            continue
        name = entry.name
        if not (name.startswith("skg-") and name.endswith("-toolchain")):
            continue
        if name.endswith(".backup"):
            continue

        manifest_path, manifest = infer_legacy_manifest(entry)
        if not manifest.name:
            continue

        records.append(
            DomainRecord(
                name=manifest.name,
                root_dir=entry,
                manifest_path=manifest_path,
                manifest_kind="legacy-toolchain",
                manifest=manifest,
                adapters_dir=entry / manifest.components.adapters,
                projectors_dir=entry / manifest.components.projectors,
                policies_dir=entry / manifest.components.policies,
                catalogs_dir=entry / manifest.components.contracts_catalogs,
            )
        )

    return records


def discover_domain_records(search_roots: Iterable[Path] | None = None) -> list[DomainRecord]:
    """Discover domain packs and legacy toolchains without service imports."""

    roots = list(search_roots or default_search_roots())
    if not roots:
        return []

    domains_root = roots[0]
    repo_root = roots[1] if len(roots) > 1 else _find_repo_root(domains_root)

    records: dict[str, DomainRecord] = {}

    # Canonical domain packs override legacy toolchain entries by name.
    for record in _discover_legacy_toolchain_records(repo_root):
        records[record.name] = record
    for record in _discover_domain_pack_records(domains_root):
        records[record.name] = record

    return [records[name] for name in sorted(records)]
