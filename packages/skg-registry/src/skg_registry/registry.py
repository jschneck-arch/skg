from __future__ import annotations

from pathlib import Path

from skg_protocol.contracts.compatibility import is_protocol_compatible
from skg_registry.discovery import default_search_roots, discover_domain_records
from skg_registry.models import DomainRecord


class DomainRegistry:
    """Public registry API used by services to resolve domain components."""

    def __init__(self, domains: list[DomainRecord]):
        self._domains: dict[str, DomainRecord] = {domain.name: domain for domain in domains}

    @classmethod
    def discover(cls, search_roots: list[Path] | None = None) -> "DomainRegistry":
        return cls(discover_domain_records(search_roots or default_search_roots()))

    def list_domains(self) -> list[DomainRecord]:
        return [self._domains[name] for name in sorted(self._domains)]

    def names(self) -> list[str]:
        return sorted(self._domains)

    def get(self, name: str) -> DomainRecord | None:
        return self._domains.get(name)

    def compatible_with(self, protocol_version: str) -> list[DomainRecord]:
        return [
            domain
            for domain in self.list_domains()
            if is_protocol_compatible(domain.manifest.protocol_version, protocol_version)
        ]

    def resolve_adapter(self, domain_name: str, adapter_name: str) -> Path:
        domain = self._require(domain_name)
        path = domain.adapters_dir / adapter_name
        if path.exists():
            return path
        raise KeyError(f"Adapter not found: domain={domain_name} adapter={adapter_name}")

    def resolve_projector(self, domain_name: str, projector_name: str) -> Path:
        domain = self._require(domain_name)
        path = domain.projectors_dir / projector_name
        if path.exists():
            return path
        raise KeyError(f"Projector not found: domain={domain_name} projector={projector_name}")

    def resolve_policy(self, domain_name: str, policy_name: str) -> Path:
        domain = self._require(domain_name)
        path = domain.policies_dir / policy_name
        if path.exists():
            return path
        raise KeyError(f"Policy not found: domain={domain_name} policy={policy_name}")

    def _require(self, name: str) -> DomainRecord:
        domain = self.get(name)
        if domain is None:
            raise KeyError(f"Unknown domain: {name}")
        return domain
