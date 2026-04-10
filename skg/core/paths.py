"""
skg.core.paths
==============
Legacy compatibility path module.

This module is a compatibility shim only.

Canonical package-neutral primitives live in `skg_core.config.paths`.
Service path policy lives in `skg_services.gravity.path_policy`.
"""
from __future__ import annotations

from pathlib import Path

from skg_core.config.paths import (
    DELTA_DIR,
    DISCOVERY_DIR,
    EVENTS_DIR,
    GRAPH_DIR,
    INTERP_DIR,
    PROPOSALS_DIR,
    SKG_CONFIG_DIR,
    SKG_HOME,
    SKG_STATE_DIR,
    ensure_runtime_dirs as ensure_core_runtime_dirs,
)
from skg_services.gravity.path_policy import (
    AD_TOOLCHAIN_DIR,
    BH_DIR,
    CE_TOOLCHAIN_DIR,
    CVE_DIR,
    FORGE_STAGING,
    HOST_TOOLCHAIN_DIR,
    IDENTITY_FILE,
    LOG_FILE,
    MSF_DIR,
    PID_FILE,
    RESONANCE_DIR,
    RESONANCE_DRAFTS,
    RESONANCE_INDEX,
    RESONANCE_RECORDS,
    TOOLCHAIN_DIR,
    WEB_TOOLCHAIN_DIR,
    ensure_service_runtime_dirs,
)

BRAIN_DIR = IDENTITY_FILE.parent
EVOLUTION_DIR = BRAIN_DIR / "evolution"
LOG_DIR = LOG_FILE.parent


def ensure_runtime_dirs() -> None:
    ensure_core_runtime_dirs()
    ensure_service_runtime_dirs()
    for directory in (EVOLUTION_DIR,):
        directory.mkdir(parents=True, exist_ok=True)
