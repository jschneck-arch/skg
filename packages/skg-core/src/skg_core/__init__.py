"""Canonical SKG substrate primitives."""

from skg_core.config.paths import (
    DELTA_DIR,
    DISCOVERY_DIR,
    EVENTS_DIR,
    GRAPH_DIR,
    INTERP_DIR,
    PROPOSALS_DIR,
    SKGPaths,
    SKG_CONFIG_DIR,
    SKG_HOME,
    SKG_ROOT,
    SKG_STATE_DIR,
    ensure_runtime_dirs,
    resolve_paths,
)
from skg_core.identity.subject import canonical_observation_subject, parse_workload_ref
from skg_core.substrate.node import Node, NodeState, TriState
from skg_core.substrate.path import Path, PathScore
from skg_core.substrate.projection import classify, project_path
from skg_core.substrate.state import SKGState

__all__ = [
    "SKGPaths",
    "Node",
    "NodeState",
    "Path",
    "PathScore",
    "DELTA_DIR",
    "DISCOVERY_DIR",
    "EVENTS_DIR",
    "GRAPH_DIR",
    "INTERP_DIR",
    "PROPOSALS_DIR",
    "SKG_CONFIG_DIR",
    "SKG_HOME",
    "SKG_ROOT",
    "SKG_STATE_DIR",
    "SKGState",
    "TriState",
    "canonical_observation_subject",
    "classify",
    "ensure_runtime_dirs",
    "parse_workload_ref",
    "project_path",
    "resolve_paths",
]
