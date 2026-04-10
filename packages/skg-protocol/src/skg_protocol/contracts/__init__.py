"""Protocol contracts for manifests, adapters, projectors, and checkpoints."""

from skg_protocol.contracts.adapter import AdapterCheckpoint, AdapterContract, AdapterHealth
from skg_protocol.contracts.ad_delegation_input import (
    AD_DELEGATION_INPUT_FILENAME,
    AD_DELEGATION_INPUT_SCHEMA,
    AD_DELEGATION_INPUT_WICKET_IDS,
    is_ad_delegation_input,
    validate_ad_delegation_input,
)
from skg_protocol.contracts.ad_delegation_context import (
    AD_DELEGATION_CONTEXT_FILENAME,
    AD_DELEGATION_CONTEXT_SCHEMA,
    AD_DELEGATION_CONTEXT_WICKET_ID,
    is_ad_delegation_context,
    validate_ad_delegation_context,
)
from skg_protocol.contracts.ad_tiering_input import (
    AD_TIERING_INPUT_FILENAME,
    AD_TIERING_INPUT_SCHEMA,
    AD_TIERING_INPUT_WICKET_ID,
    is_ad_tiering_input,
    validate_ad_tiering_input,
)
from skg_protocol.contracts.checkpoint import CheckpointRecord
from skg_protocol.contracts.compatibility import is_protocol_compatible
from skg_protocol.contracts.manifest import DomainManifest, ManifestComponents, normalize_manifest
from skg_protocol.contracts.projector import ProjectorContract, ProjectorHealth

__all__ = [
    "AD_DELEGATION_INPUT_FILENAME",
    "AD_DELEGATION_INPUT_SCHEMA",
    "AD_DELEGATION_INPUT_WICKET_IDS",
    "AD_DELEGATION_CONTEXT_FILENAME",
    "AD_DELEGATION_CONTEXT_SCHEMA",
    "AD_DELEGATION_CONTEXT_WICKET_ID",
    "AD_TIERING_INPUT_FILENAME",
    "AD_TIERING_INPUT_SCHEMA",
    "AD_TIERING_INPUT_WICKET_ID",
    "AdapterCheckpoint",
    "AdapterContract",
    "AdapterHealth",
    "CheckpointRecord",
    "DomainManifest",
    "ManifestComponents",
    "ProjectorContract",
    "ProjectorHealth",
    "is_ad_delegation_context",
    "is_ad_delegation_input",
    "is_ad_tiering_input",
    "is_protocol_compatible",
    "normalize_manifest",
    "validate_ad_delegation_context",
    "validate_ad_delegation_input",
    "validate_ad_tiering_input",
]
