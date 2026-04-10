from pathlib import Path

from skg_registry.discovery import discover_domain_records
from skg_registry.registry import DomainRegistry


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_discovery_prefers_domain_pack_over_legacy(tmp_path: Path) -> None:
    domains_root = tmp_path / "packages" / "skg-domains"
    repo_root = tmp_path

    _write(
        domains_root / "web" / "domain.yaml",
        """
name: web
status: active
runtime: domain-pack
compatibility:
  protocol: "1.0"
components:
  adapters: adapters
  projectors: projectors
  policies: policies
contracts:
  catalogs: contracts/catalogs
""".strip(),
    )
    (domains_root / "web" / "adapters" / "http_collect").mkdir(parents=True, exist_ok=True)

    _write(
        repo_root / "skg-web-toolchain" / "forge_meta.json",
        '{"domain": "web", "description": "legacy web", "protocol": "1.0"}',
    )

    records = discover_domain_records([domains_root, repo_root])

    assert [r.name for r in records] == ["web"]
    assert records[0].manifest_kind == "domain-pack"


def test_registry_resolve_adapter(tmp_path: Path) -> None:
    domains_root = tmp_path / "packages" / "skg-domains"
    repo_root = tmp_path

    _write(
        domains_root / "host" / "domain.yaml",
        """
name: host
runtime: domain-pack
compatibility:
  protocol: "1.0"
components:
  adapters: adapters
  projectors: projectors
  policies: policies
contracts:
  catalogs: contracts/catalogs
""".strip(),
    )
    adapter_dir = domains_root / "host" / "adapters" / "ssh_collect"
    adapter_dir.mkdir(parents=True, exist_ok=True)

    registry = DomainRegistry(discover_domain_records([domains_root, repo_root]))

    resolved = registry.resolve_adapter("host", "ssh_collect")

    assert resolved == adapter_dir


def test_discovery_prefers_in_package_manifest_authority(tmp_path: Path) -> None:
    domains_root = tmp_path / "packages" / "skg-domains"
    repo_root = tmp_path

    _write(
        domains_root / "web" / "domain.yaml",
        """
name: web
runtime: domain-pack
compatibility:
  protocol: "1.0"
components:
  adapters: adapters_legacy
  projectors: projectors_legacy
  policies: policies_legacy
contracts:
  catalogs: catalogs_legacy
""".strip(),
    )
    _write(
        domains_root / "web" / "src" / "skg_domain_web" / "manifest.yaml",
        """
name: web
runtime: domain-pack
compatibility:
  protocol: "1.0"
components:
  adapters: adapters
  projectors: projectors
  policies: policies
contracts:
  catalogs: ontology/catalogs
""".strip(),
    )
    canonical_adapter = domains_root / "web" / "src" / "skg_domain_web" / "adapters" / "surface"
    canonical_adapter.mkdir(parents=True, exist_ok=True)

    records = discover_domain_records([domains_root, repo_root])

    assert [r.name for r in records] == ["web"]
    assert records[0].manifest_path == domains_root / "web" / "src" / "skg_domain_web" / "manifest.yaml"
    assert records[0].adapters_dir == domains_root / "web" / "src" / "skg_domain_web" / "adapters"
