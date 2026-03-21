from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from skg.identity import parse_workload_ref


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def enrich_pearl_identity(pearl: "Pearl") -> "Pearl":
    """
    Add compatibility identity metadata to pearl snapshots without changing
    the append-only structure that existing code already expects.
    """
    energy = dict(pearl.energy_snapshot or {})
    target = dict(pearl.target_snapshot or {})

    workload_id = (
        energy.get("workload_id")
        or target.get("workload_id")
        or f"gravity::{energy.get('target_ip', '')}".rstrip(":")
    )
    parsed = parse_workload_ref(workload_id)

    if workload_id and "workload_id" not in energy:
        energy["workload_id"] = workload_id
    if workload_id and "workload_id" not in target:
        target["workload_id"] = workload_id

    energy.setdefault("identity_key", parsed["identity_key"])
    energy.setdefault("manifestation_key", parsed["manifestation_key"])
    target.setdefault("identity_key", parsed["identity_key"])
    target.setdefault("manifestation_key", parsed["manifestation_key"])

    pearl.energy_snapshot = energy
    pearl.target_snapshot = target
    return pearl


@dataclass(slots=True)
class Pearl:
    state_changes: List[Dict[str, Any]] = field(default_factory=list)
    observation_confirms: List[Dict[str, Any]] = field(default_factory=list)
    projection_changes: List[Dict[str, Any]] = field(default_factory=list)
    reason_changes: List[Dict[str, Any]] = field(default_factory=list)
    observation_refs: List[str] = field(default_factory=list)
    energy_snapshot: Dict[str, Any] = field(default_factory=dict)
    target_snapshot: Dict[str, Any] = field(default_factory=dict)
    fold_context: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "state_changes": self.state_changes,
            "observation_confirms": self.observation_confirms,
            "projection_changes": self.projection_changes,
            "reason_changes": self.reason_changes,
            "observation_refs": self.observation_refs,
            "energy_snapshot": self.energy_snapshot,
            "target_snapshot": self.target_snapshot,
            "fold_context": self.fold_context,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Pearl":
        ts = data.get("timestamp")
        try:
            parsed_ts = datetime.fromisoformat(ts) if ts else utcnow()
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
        except Exception:
            parsed_ts = utcnow()
        return enrich_pearl_identity(cls(
            state_changes=list(data.get("state_changes", [])),
            observation_confirms=list(data.get("observation_confirms", [])),
            projection_changes=list(data.get("projection_changes", [])),
            reason_changes=list(data.get("reason_changes", [])),
            observation_refs=list(data.get("observation_refs", [])),
            energy_snapshot=dict(data.get("energy_snapshot", {})),
            target_snapshot=dict(data.get("target_snapshot", {})),
            fold_context=list(data.get("fold_context", [])),
            timestamp=parsed_ts,
            id=data.get("id") or str(uuid4()),
        ))


class PearlLedger:
    def __init__(self, path: str | Path | None = None) -> None:
        self._pearls: List[Pearl] = []
        self._path = Path(path) if path else None
        if self._path:
            self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            for line in self._path.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                self._pearls.append(Pearl.from_dict(json.loads(line)))
        except Exception:
            self._pearls = []

    def _append(self, pearl: Pearl) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a") as fh:
            fh.write(json.dumps(pearl.to_dict()) + "\n")

    def record(self, pearl: Pearl) -> None:
        pearl = enrich_pearl_identity(pearl)
        self._pearls.append(pearl)
        self._append(pearl)

    def all(self) -> List[Pearl]:
        return list(self._pearls)

    def count(self) -> int:
        return len(self._pearls)
