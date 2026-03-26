"""
skg.core.daemon_registry
========================
Thin registry that exposes the two daemon functions needed by the topology
layer without importing the full daemon (which pulls in uvicorn/FastAPI).

daemon.py populates _all_targets_index and _identity_world at startup.
Tests can mock this module directly without needing a running daemon.
"""
from __future__ import annotations
from typing import Any, Callable, Optional

_all_targets_index: Optional[Callable[[], list[dict[str, Any]]]] = None
_identity_world:    Optional[Callable[[str, Optional[dict]], dict[str, Any]]] = None
