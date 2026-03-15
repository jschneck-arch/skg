from __future__ import annotations
from typing import Iterable, List, Dict, Any


class GravityScheduler:
    def rank(self, proposals: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def score(p: Dict[str, Any]) -> float:
            gain = float(p.get("expected_energy_reduction", 0.0))
            cost = max(float(p.get("cost", 1.0)), 1e-9)
            penalty = float(p.get("failure_penalty", 1.0))
            approval = 0.9 if p.get("requires_operator_approval", False) else 1.0
            return (gain / cost) * penalty * approval

        return sorted(proposals, key=score, reverse=True)
