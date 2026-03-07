"""
skg.identity
============
Append-only self-knowledge journal.
Same immutability principle as the toolchain observation store.

Each record is a full snapshot. Nothing overwrites.
Locked read-only in ANCHOR mode.
"""
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class IdentitySnapshot:
    name:      str   = "SKG"
    version:   str   = "1.0.0"
    mode:      str   = "kernel"
    coherence: float = 1.0
    sessions:  int   = 0
    notes:     str   = ""
    timestamp: str   = field(default_factory=_now)
    source:    str   = "system.init"

    def to_dict(self) -> dict:
        return asdict(self)

    def to_envelope(self) -> dict:
        """Emit as a formal SKG envelope event, compatible with toolchain schema."""
        return {
            "id": str(uuid.uuid4()),
            "ts": self.timestamp,
            "type": "obs.skg.identity",
            "source": {
                "source_id": self.source,
                "toolchain": "skg-daemon",
                "version": self.version,
            },
            "payload": self.to_dict(),
            "provenance": {
                "evidence_rank": 1,
                "evidence": {
                    "source_kind": "daemon",
                    "pointer": f"identity://skg/{self.timestamp}",
                    "collected_at": self.timestamp,
                    "confidence": 1.0,
                },
            },
        }


class Identity:
    def __init__(self, journal_path: Path):
        self._path = journal_path
        self._current: Optional[IdentitySnapshot] = None
        self._read_only = False

    def load(self) -> IdentitySnapshot:
        if self._path.exists():
            lines = [l.strip() for l in self._path.read_text().splitlines() if l.strip()]
            if lines:
                d = json.loads(lines[-1])
                self._current = IdentitySnapshot(**{
                    k: v for k, v in d.items()
                    if k in IdentitySnapshot.__dataclass_fields__
                })
                return self._current
        self._current = IdentitySnapshot()
        self._append(self._current)
        return self._current

    def update(self, changes: dict, source: str = "system") -> IdentitySnapshot:
        if self._read_only:
            raise PermissionError(
                "Identity is read-only in ANCHOR mode. "
                "Restore coherence before modifying."
            )
        if self._current is None:
            self.load()
        d = asdict(self._current)
        d.update(changes)
        d["timestamp"] = _now()
        d["source"] = source
        snap = IdentitySnapshot(**{k: v for k, v in d.items()
                                   if k in IdentitySnapshot.__dataclass_fields__})
        self._current = snap
        self._append(snap)
        return snap

    def lock(self, locked: bool) -> None:
        self._read_only = locked

    def history(self) -> list[dict]:
        if not self._path.exists():
            return []
        return [json.loads(l) for l in self._path.read_text().splitlines() if l.strip()]

    @property
    def current(self) -> Optional[IdentitySnapshot]:
        return self._current

    def _append(self, snap: IdentitySnapshot) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a") as f:
            f.write(json.dumps(snap.to_dict()) + "\n")
