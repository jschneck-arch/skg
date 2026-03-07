"""
skg.core.paths
==============
Single source of truth for all SKG filesystem paths.

System install : /opt/skg           ($SKG_HOME)
Runtime state  : /var/lib/skg       ($SKG_STATE_DIR)
Config         : /etc/skg           ($SKG_CONFIG_DIR)
Metasploit     : /opt/msf           ($MSF_DIR)
BloodHound CE  : /opt/BloodHound    ($BH_DIR)
"""
import os
from pathlib import Path

# Base directories — define these first, everything derives from them
SKG_HOME       = Path(os.getenv("SKG_HOME",       "/opt/skg"))
SKG_STATE_DIR  = Path(os.getenv("SKG_STATE_DIR",  "/var/lib/skg"))
SKG_CONFIG_DIR = Path(os.getenv("SKG_CONFIG_DIR", "/etc/skg"))
MSF_DIR        = Path(os.getenv("MSF_DIR",        "/opt/msf"))
BH_DIR         = Path(os.getenv("BH_DIR",         "/opt/BloodHound"))

# Toolchain directories
TOOLCHAIN_DIR      = SKG_HOME / "skg-aprs-toolchain"
CE_TOOLCHAIN_DIR   = SKG_HOME / "skg-container-escape-toolchain"
AD_TOOLCHAIN_DIR   = SKG_HOME / "skg-ad-lateral-toolchain"
HOST_TOOLCHAIN_DIR = SKG_HOME / "skg-host-toolchain"
WEB_TOOLCHAIN_DIR  = SKG_HOME / "skg-web-toolchain"

# Resonance memory (state-backed)
RESONANCE_DIR     = SKG_STATE_DIR / "resonance"
RESONANCE_INDEX   = RESONANCE_DIR / "index"
RESONANCE_RECORDS = RESONANCE_DIR / "records"
RESONANCE_DRAFTS  = RESONANCE_DIR / "drafts"

# Forge staging
FORGE_STAGING = SKG_STATE_DIR / "forge_staging"

# Runtime state directories
BRAIN_DIR     = SKG_STATE_DIR / "brain"
IDENTITY_FILE = BRAIN_DIR / "identity.jsonl"
EVOLUTION_DIR = BRAIN_DIR / "evolution"
EVENTS_DIR    = SKG_STATE_DIR / "events"
INTERP_DIR    = SKG_STATE_DIR / "interp"
DELTA_DIR     = SKG_STATE_DIR / "delta"
GRAPH_DIR     = SKG_STATE_DIR / "graph"

# Logs
LOG_DIR  = SKG_STATE_DIR / "logs"
LOG_FILE = LOG_DIR / "skg.log"
PID_FILE = SKG_STATE_DIR / "skg.pid"


def ensure_runtime_dirs() -> None:
    for d in [
        BRAIN_DIR, EVOLUTION_DIR, EVENTS_DIR, INTERP_DIR, LOG_DIR,
        DELTA_DIR / "snapshots", DELTA_DIR / "transitions",
        GRAPH_DIR,
        RESONANCE_INDEX, RESONANCE_RECORDS, RESONANCE_DRAFTS,
        FORGE_STAGING,
        SKG_STATE_DIR / "proposals",
        SKG_STATE_DIR / "bh_cache",
    ]:
        d.mkdir(parents=True, exist_ok=True)
