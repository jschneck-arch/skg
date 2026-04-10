from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CheckpointRecord:
    """Protocol-level checkpoint payload for adapters/projectors/services."""

    component: str
    token: str
    created_at: str
    state_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
