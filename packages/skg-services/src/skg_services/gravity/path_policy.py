from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from skg_core.config.paths import SKGPaths, resolve_paths


@dataclass(frozen=True, slots=True)
class ServicePathPolicy:
    core_paths: SKGPaths
    root_dir: Path
    state_dir: Path
    config_dir: Path
    events_dir: Path
    interp_dir: Path
    discovery_dir: Path
    graph_dir: Path
    proposals_dir: Path
    delta_dir: Path
    cve_dir: Path
    resonance_dir: Path
    resonance_index_dir: Path
    resonance_records_dir: Path
    resonance_drafts_dir: Path
    forge_staging_dir: Path
    brain_dir: Path
    identity_file: Path
    log_dir: Path
    log_file: Path
    pid_file: Path
    msf_dir: Path
    bloodhound_dir: Path
    toolchain_dir: Path
    ce_toolchain_dir: Path
    ad_toolchain_dir: Path
    host_toolchain_dir: Path
    web_toolchain_dir: Path


def _resolve_path(env: Mapping[str, str], key: str, default: Path) -> Path:
    explicit = str(env.get(key, "")).strip()
    if not explicit:
        return default
    return Path(explicit).expanduser().resolve()


def build_service_path_policy(env: Mapping[str, str] | None = None, cwd: Path | None = None) -> ServicePathPolicy:
    """Service-owned path policy without hardcoded host-install assumptions."""

    env = env or os.environ
    core_paths = resolve_paths(env=env, cwd=cwd)

    root = core_paths.root_dir
    state = core_paths.state_dir
    config = core_paths.config_dir
    events = core_paths.events_dir
    interp = core_paths.interp_dir
    discovery = core_paths.discovery_dir
    graph = core_paths.graph_dir
    proposals = core_paths.proposals_dir
    delta = core_paths.delta_dir

    cve = _resolve_path(env, "SKG_CVE_DIR", state / "cve")
    resonance = _resolve_path(env, "SKG_RESONANCE_DIR", state / "resonance")
    forge_staging = _resolve_path(env, "SKG_FORGE_STAGING", state / "forge_staging")
    brain = _resolve_path(env, "SKG_BRAIN_DIR", state / "brain")
    identity = _resolve_path(env, "SKG_IDENTITY_FILE", brain / "identity.jsonl")
    log_dir = _resolve_path(env, "SKG_LOG_DIR", state / "logs")
    log_file = _resolve_path(env, "SKG_LOG_FILE", log_dir / "skg.log")
    pid_file = _resolve_path(env, "SKG_PID_FILE", state / "skg.pid")

    msf = _resolve_path(env, "MSF_DIR", root / "tools" / "msf")
    bloodhound = _resolve_path(env, "BH_DIR", root / "tools" / "bloodhound")
    toolchain = _resolve_path(env, "SKG_TOOLCHAIN_DIR", root / "skg-aprs-toolchain")
    ce_toolchain = _resolve_path(env, "SKG_CE_TOOLCHAIN_DIR", root / "skg-container-escape-toolchain")
    ad_toolchain = _resolve_path(env, "SKG_AD_TOOLCHAIN_DIR", root / "skg-ad-lateral-toolchain")
    host_toolchain = _resolve_path(env, "SKG_HOST_TOOLCHAIN_DIR", root / "skg-host-toolchain")
    web_toolchain = _resolve_path(env, "SKG_WEB_TOOLCHAIN_DIR", root / "skg-web-toolchain")

    return ServicePathPolicy(
        core_paths=core_paths,
        root_dir=root,
        state_dir=state,
        config_dir=config,
        events_dir=events,
        interp_dir=interp,
        discovery_dir=discovery,
        graph_dir=graph,
        proposals_dir=proposals,
        delta_dir=delta,
        cve_dir=cve,
        resonance_dir=resonance,
        resonance_index_dir=resonance / "index",
        resonance_records_dir=resonance / "records",
        resonance_drafts_dir=resonance / "drafts",
        forge_staging_dir=forge_staging,
        brain_dir=brain,
        identity_file=identity,
        log_dir=log_dir,
        log_file=log_file,
        pid_file=pid_file,
        msf_dir=msf,
        bloodhound_dir=bloodhound,
        toolchain_dir=toolchain,
        ce_toolchain_dir=ce_toolchain,
        ad_toolchain_dir=ad_toolchain,
        host_toolchain_dir=host_toolchain,
        web_toolchain_dir=web_toolchain,
    )


DEFAULT_SERVICE_PATHS = build_service_path_policy()

# Service-owned canonical runtime constants.
FORGE_STAGING = DEFAULT_SERVICE_PATHS.forge_staging_dir
RESONANCE_DIR = DEFAULT_SERVICE_PATHS.resonance_dir
RESONANCE_INDEX = DEFAULT_SERVICE_PATHS.resonance_index_dir
RESONANCE_RECORDS = DEFAULT_SERVICE_PATHS.resonance_records_dir
RESONANCE_DRAFTS = DEFAULT_SERVICE_PATHS.resonance_drafts_dir
CVE_DIR = DEFAULT_SERVICE_PATHS.cve_dir
IDENTITY_FILE = DEFAULT_SERVICE_PATHS.identity_file
LOG_FILE = DEFAULT_SERVICE_PATHS.log_file
PID_FILE = DEFAULT_SERVICE_PATHS.pid_file
MSF_DIR = DEFAULT_SERVICE_PATHS.msf_dir
BH_DIR = DEFAULT_SERVICE_PATHS.bloodhound_dir
TOOLCHAIN_DIR = DEFAULT_SERVICE_PATHS.toolchain_dir
CE_TOOLCHAIN_DIR = DEFAULT_SERVICE_PATHS.ce_toolchain_dir
AD_TOOLCHAIN_DIR = DEFAULT_SERVICE_PATHS.ad_toolchain_dir
HOST_TOOLCHAIN_DIR = DEFAULT_SERVICE_PATHS.host_toolchain_dir
WEB_TOOLCHAIN_DIR = DEFAULT_SERVICE_PATHS.web_toolchain_dir


def ensure_service_runtime_dirs(policy: ServicePathPolicy | None = None) -> None:
    resolved = policy or DEFAULT_SERVICE_PATHS
    for directory in (
        resolved.state_dir,
        resolved.events_dir,
        resolved.interp_dir,
        resolved.discovery_dir,
        resolved.graph_dir,
        resolved.proposals_dir,
        resolved.delta_dir / "snapshots",
        resolved.delta_dir / "transitions",
        resolved.cve_dir,
        resolved.resonance_index_dir,
        resolved.resonance_records_dir,
        resolved.resonance_drafts_dir,
        resolved.forge_staging_dir,
        resolved.log_dir,
        resolved.brain_dir,
        resolved.state_dir / "bh_cache",
    ):
        directory.mkdir(parents=True, exist_ok=True)


def ensure_runtime_dirs(policy: ServicePathPolicy | None = None) -> None:
    """Compatibility helper for legacy runtime callsites."""

    ensure_service_runtime_dirs(policy=policy)


__all__ = [
    "AD_TOOLCHAIN_DIR",
    "BH_DIR",
    "CE_TOOLCHAIN_DIR",
    "CVE_DIR",
    "FORGE_STAGING",
    "HOST_TOOLCHAIN_DIR",
    "IDENTITY_FILE",
    "LOG_FILE",
    "MSF_DIR",
    "PID_FILE",
    "RESONANCE_DIR",
    "RESONANCE_DRAFTS",
    "RESONANCE_INDEX",
    "RESONANCE_RECORDS",
    "ServicePathPolicy",
    "TOOLCHAIN_DIR",
    "WEB_TOOLCHAIN_DIR",
    "build_service_path_policy",
    "ensure_runtime_dirs",
    "ensure_service_runtime_dirs",
]
