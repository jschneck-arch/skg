"""
skg.resonance.memory
====================
Record types for the resonance engine memory store.
Three types, each backed by a JSONL file and a FAISS index.

WicketMemory   — a single atomic precondition extracted from any catalog
AdapterMemory  — an adapter's evidence sources and wickets covered
DomainMemory   — a full domain's shape: paths, wicket count, attack surface
"""

from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class WicketMemory:
    """
    One wicket extracted from a domain catalog.
    The embedding is derived from: label + description + evidence_hint.
    """
    record_id:      str          # e.g. "aprs::AP-L4"
    domain:         str          # "aprs" | "container_escape" | "ad_lateral"
    wicket_id:      str          # "AP-L4"
    label:          str          # "log4j_vulnerable_version_present"
    description:    str
    evidence_hint:  str
    attack_paths:   list[str]    # which paths require this wicket
    embed_text:     str          # the string that was embedded

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "WicketMemory":
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def make_embed_text(label: str, description: str, evidence_hint: str) -> str:
        return f"{label}. {description} Evidence: {evidence_hint}"


@dataclass
class AdapterMemory:
    """
    One adapter extracted from a domain toolchain.
    The embedding is derived from: domain + adapter_name + evidence_sources joined.
    """
    record_id:        str        # e.g. "aprs::config_effective"
    domain:           str
    adapter_name:     str        # "config_effective"
    evidence_sources: list[str]  # human-readable list of what it reads
    wickets_covered:  list[str]  # wicket IDs this adapter can populate
    evidence_ranks:   list[int]  # ranks used by this adapter
    embed_text:       str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AdapterMemory":
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def make_embed_text(domain: str, adapter_name: str,
                        evidence_sources: list[str]) -> str:
        sources = "; ".join(evidence_sources)
        return f"{domain} adapter {adapter_name}. Evidence sources: {sources}"


@dataclass
class DomainMemory:
    """
    Full shape of a domain — used when the drafter needs to understand
    how existing domains are structured before proposing a new one.
    """
    record_id:      str          # domain name
    domain:         str
    description:    str
    wicket_count:   int
    attack_paths:   list[str]
    adapters:       list[str]
    catalog_version: str
    embed_text:     str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DomainMemory":
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def make_embed_text(domain: str, description: str,
                        attack_paths: list[str]) -> str:
        paths = "; ".join(attack_paths)
        return f"{domain}: {description} Attack paths: {paths}"


# Registry of record types for generic serialization
RECORD_TYPES = {
    "wicket":  WicketMemory,
    "adapter": AdapterMemory,
    "domain":  DomainMemory,
}
