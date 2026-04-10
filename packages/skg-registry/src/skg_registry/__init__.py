"""Canonical registry for domain/adapters/projectors/policies discovery."""

from skg_registry.discovery import default_search_roots, discover_domain_records
from skg_registry.models import DomainRecord
from skg_registry.registry import DomainRegistry

__all__ = [
    "DomainRecord",
    "DomainRegistry",
    "default_search_roots",
    "discover_domain_records",
]
