"""
skg.kernel.energy
=================
EnergyEngine — computes field energy E.

The scalar form is still available:

  E = |unknown nodes| + fold_weight

But the canonical runtime now uses a weighted unresolved form:

  E = Σ(local unresolved mass + contradiction + decoherence) + Σ fold.gravity_weight()

This keeps Work 3 honesty while making unresolved structure first-class.
Raw fold count understates the impact of high-probability folds, and a flat
unknown count understates stale, single-basis, or contradictory measurements.
"""
from __future__ import annotations
from typing import Any, Iterable

from .state import TriState
from .folds import Fold


class EnergyEngine:
    def compute(self, node_states: Iterable[TriState],
                folds: Iterable[Fold]) -> float:
        """
        Compute field energy E.

          E = |unknown node states| + Σ fold.gravity_weight()

        Returns float (not int) because fold weights are continuous.
        """
        unknown = sum(1 for s in node_states if s == TriState.UNKNOWN)
        fold_weight = sum(f.gravity_weight() for f in folds)
        return unknown + fold_weight

    def compute_weighted(self, node_states: Iterable[Any], folds: Iterable[Fold]) -> float:
        """
        Compute weighted field energy for richer node-state representations.
        """
        unresolved = 0.0
        for item in node_states:
            if isinstance(item, TriState):
                unresolved += 1.0 if item == TriState.UNKNOWN else 0.0
                continue
            if isinstance(item, dict):
                status = str(item.get("status", "unknown"))
                phi_u = float(item.get("phi_u", 0.0) or 0.0)
                contradiction = float(item.get("contradiction", 0.0) or 0.0)
                decoherence = float(item.get("decoherence", 0.0) or 0.0)
                local_energy = float(item.get("local_energy", 0.0) or 0.0)
                base = max(phi_u, local_energy, 1.0 if status == TriState.UNKNOWN.value else 0.0)
                unresolved += base + contradiction + decoherence
        fold_weight = sum(f.gravity_weight() for f in folds)
        return unresolved + fold_weight
