"""
skg.substrate
=============
Domain-agnostic substrate for SKG — the λ–κ–π core.

λ = collection manifold  (Sensor base classes)
κ = constraint surface   (Node preconditions, Path definitions)
π = projection           (Tri-state scoring engine)

E = H(projection | telemetry)

This layer knows nothing about security, supply chains, or any
specific domain. It defines the information-theoretic substrate
that all domain skins inherit from.

A wave is a cross-section of a sphere.
"""

from skg.substrate.node import Node, NodeState, TriState
from skg.substrate.path import Path, PathScore
from skg.substrate.projection import project_path, classify

__all__ = [
    "Node", "NodeState", "TriState",
    "Path", "PathScore",
    "project_path", "classify",
]
