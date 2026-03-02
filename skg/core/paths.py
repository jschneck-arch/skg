"""
skg.core.paths
==============
Single source of truth for all SKG filesystem paths.
Nothing hardcodes a path — everything derives from here.

System install : /opt/skg
Runtime state  : /var/lib/skg  (or $SKG_STATE_DIR)
Config         : /etc/skg      (or $SKG_CONFIG_DIR)
"""
import os
from pathlib import Path

SKG_HOME         = Path(os.getenv("SKG_HOME",       "/opt/skg"))
TOOLCHAIN_DIR    = SKG_HOME / "skg-aprs-toolchain"
CE_TOOLCHAIN_DIR = SKG_HOME / "skg-container-escape-toolchain"
AD_TOOLCHAIN_DIR = SKG_HOME / "skg-ad-lateral-toolchain"
RESONANCE_DIR    = SKG_HOME / "resonance"
RESONANCE_INDEX  = RESONANCE_DIR / "index"
RESONANCE_RECORDS = RESONANCE_DIR / "records"
RESONANCE_DRAFTS  = RESONANCE_DIR / "drafts"
SKG_STATE_DIR    = Path(os.getenv("SKG_STATE_DIR",  "/var/lib/skg"))
SKG_CONFIG_DIR = Path(os.getenv("SKG_CONFIG_DIR", "/etc/skg"))

BRAIN_DIR     = SKG_STATE_DIR / "brain"
IDENTITY_FILE = BRAIN_DIR / "identity.jsonl"
EVOLUTION_DIR = BRAIN_DIR / "evolution"
EVENTS_DIR    = SKG_STATE_DIR / "events"
INTERP_DIR    = SKG_STATE_DIR / "interp"
LOG_DIR       = SKG_STATE_DIR / "logs"
LOG_FILE      = LOG_DIR / "skg.log"
PID_FILE      = SKG_STATE_DIR / "skg.pid"


def ensure_runtime_dirs() -> None:
    for d in [BRAIN_DIR, EVOLUTION_DIR, EVENTS_DIR, INTERP_DIR, LOG_DIR,
              RESONANCE_INDEX, RESONANCE_RECORDS, RESONANCE_DRAFTS]:
        d.mkdir(parents=True, exist_ok=True)
