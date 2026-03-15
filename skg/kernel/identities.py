from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List
from uuid import uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Identity:
    canonical_key: str
    identity_type: str = "generic"
    attributes: Dict[str, str] = field(default_factory=dict)
    source_observations: List[str] = field(default_factory=list)
    created_time: datetime = field(default_factory=utcnow)
    updated_time: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: str(uuid4()))


class IdentityRegistry:
    def __init__(self) -> None:
        self._by_key: Dict[str, Identity] = {}

    def get_or_create(self, canonical_key: str, identity_type: str = "generic") -> Identity:
        if canonical_key not in self._by_key:
            self._by_key[canonical_key] = Identity(canonical_key=canonical_key, identity_type=identity_type)
        return self._by_key[canonical_key]

    def all(self) -> List[Identity]:
        return list(self._by_key.values())
