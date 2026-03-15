"""
skg.modes
=========
Four operational modes defining SKG's relationship with its environment.

KERNEL    : Focused inward. Self-auditing. Toolchain runs off.
RESONANCE : Actively sensing. Toolchain ingests on schedule.
UNIFIED   : Full coherence. Ingest + projection run together.
ANCHOR    : Stabilizing. Identity locked. No toolchain runs.
"""
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class Mode(str, Enum):
    KERNEL    = "kernel"
    RESONANCE = "resonance"
    UNIFIED   = "unified"
    ANCHOR    = "anchor"


MODE_BEHAVIOR = {
    Mode.KERNEL: {
        "description": "Focused inward. Self-auditing, consolidating identity.",
        "identity_writes": True,
        "toolchain_runs": False,
        "sensor_interval_s": 60,
    },
    Mode.RESONANCE: {
        "description": "Actively sensing and adapting to environment.",
        "identity_writes": True,
        "toolchain_runs": True,
        "sensor_interval_s": 15,
    },
    Mode.UNIFIED: {
        "description": "Full coherence. Ingest and projection running together.",
        "identity_writes": True,
        "toolchain_runs": True,
        "sensor_interval_s": 30,
    },
    Mode.ANCHOR: {
        "description": "Stabilizing against drift. All state read-only.",
        "identity_writes": False,
        "toolchain_runs": False,
        "sensor_interval_s": 10,
    },
}


@dataclass
class ModeTransition:
    from_mode: Mode
    to_mode:   Mode
    reason:    str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "event":     "mode_transition",
            "from":      self.from_mode.value,
            "to":        self.to_mode.value,
            "reason":    self.reason,
            "timestamp": self.timestamp,
        }


def valid_transition(from_mode: Mode, to_mode: Mode) -> tuple[bool, str]:
    if from_mode == to_mode:
        return False, f"Already in {to_mode.value} mode."
    return True, ""
