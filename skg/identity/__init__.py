"""
skg.identity
============
Append-only self-knowledge journal.
Same immutability principle as the toolchain observation store.

Each record is a full snapshot. Nothing overwrites.
Locked read-only in ANCHOR mode.
"""
import json
import ipaddress
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from .workload import canonical_workload_id  # noqa: F401  re-exported
from typing import Optional
from urllib.parse import urlparse


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_from_locator(locator: str) -> str:
    text = str(locator or "").strip()
    if not text:
        return ""

    if "://" in text:
        try:
            parsed = urlparse(text)
            return parsed.hostname or text
        except Exception:
            return text

    base = text.split("/", 1)[0]
    if "::" in base:
        base = base.split("::", 1)[0]
    if base.count(":") == 1 and "." in base:
        return base.split(":", 1)[0]
    return base


def _looks_like_ip_address(text: str) -> bool:
    candidate = str(text or "").strip()
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def parse_workload_ref(workload_id: str) -> dict:
    """
    Compatibility parser for workload identifiers.

    Existing runtime behavior is preserved: workload_id remains the manifestation key.
    This helper exposes the likely stable identity underneath it so callers can stop
    treating every workload string as the identity itself.
    """
    raw = str(workload_id or "")
    if "::" in raw:
        domain, locator = raw.split("::", 1)
    else:
        domain, locator = "", raw

    host = _host_from_locator(locator)
    identity_key = host or locator or raw or "unknown"
    manifestation_key = raw or identity_key

    return {
        "workload_id": raw,
        "domain_hint": domain,
        "locator": locator or raw,
        "host": host,
        "identity_key": identity_key,
        "manifestation_key": manifestation_key,
    }


def canonical_observation_subject(
    payload: dict | None = None,
    *,
    workload_id: str = "",
    target_ip: str = "",
) -> dict:
    """
    Resolve the canonical substrate subject for an observation payload.

    The canonical subject is the stable identity anchor for the workload,
    not the trailing token of a workload locator like
    ``binary::192.168.254.5::ssh-keysign``.
    """
    payload = dict(payload or {})
    raw_workload = str(payload.get("workload_id") or workload_id or "").strip()
    parsed = parse_workload_ref(raw_workload)

    explicit_identity = str(payload.get("identity_key") or "").strip()
    explicit_manifestation = str(payload.get("manifestation_key") or "").strip()
    explicit_target_ip = str(payload.get("target_ip") or target_ip or "").strip()

    identity_key = (
        explicit_identity
        or explicit_target_ip
        or parsed.get("identity_key", "")
        or raw_workload
        or "unknown"
    )
    manifestation_key = (
        explicit_manifestation
        or raw_workload
        or parsed.get("manifestation_key", "")
        or identity_key
    )
    host = explicit_target_ip or str(parsed.get("host") or "").strip() or identity_key
    canonical_target_ip = explicit_target_ip
    if not canonical_target_ip and _looks_like_ip_address(host):
        canonical_target_ip = host

    return {
        "workload_id": raw_workload,
        "host": host,
        "target_ip": canonical_target_ip,
        "identity_key": identity_key,
        "manifestation_key": manifestation_key,
        "subject_key": identity_key,
    }


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
