from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True, slots=True)
class SKGPaths:
    """Protocol-neutral filesystem primitives for SKG runtime state."""

    root_dir: Path
    state_dir: Path
    config_dir: Path
    events_dir: Path
    interp_dir: Path
    discovery_dir: Path
    graph_dir: Path
    proposals_dir: Path
    delta_dir: Path


def _resolve_root(env: Mapping[str, str], cwd: Path | None) -> Path:
    explicit = str(env.get("SKG_HOME", "") or env.get("SKG_ROOT", "")).strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    return (cwd or Path.cwd()).resolve()


def _resolve_path(env: Mapping[str, str], key: str, default: Path) -> Path:
    explicit = str(env.get(key, "")).strip()
    if not explicit:
        return default
    return Path(explicit).expanduser().resolve()


def resolve_paths(
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> SKGPaths:
    """
    Resolve canonical paths without hardcoding host-specific install locations.

    Defaults:
    - root_dir: current working directory
    - state_dir: <root>/.skg/state
    - config_dir: <root>/config
    """

    env = env or os.environ
    root_dir = _resolve_root(env, cwd)

    state_dir = _resolve_path(env, "SKG_STATE_DIR", root_dir / ".skg" / "state")
    config_dir = _resolve_path(env, "SKG_CONFIG_DIR", root_dir / "config")

    return SKGPaths(
        root_dir=root_dir,
        state_dir=state_dir,
        config_dir=config_dir,
        events_dir=state_dir / "events",
        interp_dir=state_dir / "interp",
        discovery_dir=state_dir / "discovery",
        graph_dir=state_dir / "graph",
        proposals_dir=state_dir / "proposals",
        delta_dir=state_dir / "delta",
    )


DEFAULT_PATHS = resolve_paths()

# Canonical module-level path primitives for import-based callers.
SKG_HOME = DEFAULT_PATHS.root_dir
SKG_ROOT = DEFAULT_PATHS.root_dir
SKG_STATE_DIR = DEFAULT_PATHS.state_dir
SKG_CONFIG_DIR = DEFAULT_PATHS.config_dir
EVENTS_DIR = DEFAULT_PATHS.events_dir
INTERP_DIR = DEFAULT_PATHS.interp_dir
DISCOVERY_DIR = DEFAULT_PATHS.discovery_dir
GRAPH_DIR = DEFAULT_PATHS.graph_dir
PROPOSALS_DIR = DEFAULT_PATHS.proposals_dir
DELTA_DIR = DEFAULT_PATHS.delta_dir


def ensure_runtime_dirs(paths: SKGPaths | None = None) -> None:
    """Create runtime directories from canonical path primitives."""

    resolved = paths or DEFAULT_PATHS

    for directory in (
        resolved.state_dir,
        resolved.events_dir,
        resolved.interp_dir,
        resolved.discovery_dir,
        resolved.graph_dir,
        resolved.proposals_dir,
        resolved.delta_dir / "snapshots",
        resolved.delta_dir / "transitions",
    ):
        directory.mkdir(parents=True, exist_ok=True)
