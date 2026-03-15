"""
skg.kernel.energy
=================
EnergyEngine — computes field energy E.

E = |unknown nodes| + fold_weight

Where fold_weight is the sum of Fold.gravity_weight() for all active folds.
This is the operationally correct implementation of:

  E(S, A) = |{n ∈ A : Σ(n) = U}| + |folds|   (Work 3 Section 3.2 extended)

Raw fold count understates the impact of high-probability folds.
A structural fold for redis with RCE attack surface contributes more
to E than a temporal fold for a low-confidence operational observation.
"""
from __future__ import annotations
from typing import Iterable

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
