"""
skg.kernel.engine
=================
KernelStateEngine — unified interface for gravity_field.py.

Replaces the three parallel implementations in gravity_field.py:
  - load_wicket_states()         → kernel_states()
  - field_entropy()              → kernel_energy()
  - entropy_reduction_potential() → kernel_instrument_potential()

All three now route through the kernel:
  SupportEngine → aggregate support vectors per wicket
  StateEngine   → collapse aggregated support to {R, B, U}
  EnergyEngine  → count unknowns + fold weights
  GravityScheduler → rank instruments by expected E reduction / cost

The gravity_field.py changes are surgical:
  1. Import KernelStateEngine at top
  2. Replace load_wicket_states() body with kernel call
  3. Replace field_entropy() body with kernel call
  4. Replace entropy_reduction_potential() body with kernel call

Nothing else in gravity_field.py changes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from .adapters import load_observations_for_target
from .energy import EnergyEngine
from .folds import Fold
from .gravity import GravityScheduler
from .observations import Observation
from .state import CollapseThresholds, StateEngine
from .support import SupportEngine
from ..substrate.node import TriState

log = logging.getLogger("skg.kernel.engine")

# Collapse thresholds — tuned for security telemetry.
# A single high-confidence instrument observation (≥0.95) realizes immediately.
# Two moderate observations (0.7 each = 1.4) also realize.
# Conflicts keep the state UNKNOWN.
DEFAULT_THRESHOLDS = CollapseThresholds(realized=0.5, blocked=0.5)


class KernelStateEngine:
    """
    Drop-in kernel integration for gravity_field.py.

    Usage in gravity_field.py:
        _kernel = KernelStateEngine(DISCOVERY_DIR, EVENTS_DIR, CVE_DIR)

        # Replace load_wicket_states(ip)
        states = _kernel.states(ip)           # {wicket_id: TriState}

        # Replace field_entropy(states, applicable_wickets)
        E = _kernel.energy(ip, applicable_wickets, folds)

        # Replace entropy_reduction_potential(instrument, ip, states, applicable_wickets)
        potential = _kernel.instrument_potential(instrument, ip, applicable_wickets, folds)
    """

    def __init__(
        self,
        discovery_dir: Path,
        events_dir: Path,
        cve_dir: Optional[Path] = None,
        thresholds: CollapseThresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        self.discovery_dir = discovery_dir
        self.events_dir = events_dir
        self.cve_dir = cve_dir
        self._support = SupportEngine()
        self._state = StateEngine(thresholds)
        self._energy = EnergyEngine()
        self._gravity = GravityScheduler()
        self._now = lambda: datetime.now(timezone.utc)

    def observations(self, target_ip: str) -> List[Observation]:
        """Load all observations for a target from event files."""
        return load_observations_for_target(
            target_ip, self.discovery_dir, self.events_dir, self.cve_dir
        )

    def states(self, target_ip: str) -> Dict[str, TriState]:
        """
        Compute kernel-aggregated wicket states for a target.

        Returns {wicket_id: TriState} using support vector aggregation,
        not last-write-wins. Replaces load_wicket_states().
        """
        observations = self.observations(target_ip)
        if not observations:
            return {}

        # Group observations by context (wicket_id)
        wickets: Set[str] = {obs.context for obs in observations}
        now = self._now()

        result: Dict[str, TriState] = {}
        for wicket_id in wickets:
            contrib = self._support.aggregate(
                observations, target_ip, wicket_id, now
            )
            result[wicket_id] = self._state.collapse(contrib)

        return result

    def states_with_detail(self, target_ip: str) -> Dict[str, dict]:
        """
        Like states() but returns full detail dict compatible with
        the existing gravity_field.py callers that expect:
          {wicket_id: {"status": str, "detail": str, "ts": str}}
        """
        observations = self.observations(target_ip)
        if not observations:
            return {}

        wickets: Set[str] = {obs.context for obs in observations}
        now = self._now()

        result: Dict[str, dict] = {}
        for wicket_id in wickets:
            # Find most recent observation for detail/ts
            wk_obs = [o for o in observations if o.context == wicket_id]
            contrib = self._support.aggregate(observations, target_ip, wicket_id, now)
            state = self._state.collapse(contrib)

            # Get detail from the highest-confidence observation
            best = max(
                wk_obs,
                key=lambda o: o.support_mapping.get(target_ip, {}).get("R", 0)
                              + o.support_mapping.get(target_ip, {}).get("B", 0),
                default=wk_obs[0] if wk_obs else None,
            )
            detail = best.payload.get("detail", "") if best else ""
            ts = best.event_time.isoformat() if best else now.isoformat()

            result[wicket_id] = {
                "status": state.value,
                "detail": detail,
                "ts": ts,
                # Include support values for FeedbackIngester and paper metrics
                "phi_r": contrib.realized,
                "phi_b": contrib.blocked,
            }

        return result

    def energy(
        self,
        target_ip: str,
        applicable_wickets: Set[str],
        folds: Optional[List[Fold]] = None,
    ) -> float:
        """
        Compute field energy E for a target.
        E = |unknown wickets in applicable set| + fold weights.
        Replaces field_entropy().
        """
        if not applicable_wickets:
            return 0.0

        states = self.states(target_ip)
        node_states = []
        for wid in applicable_wickets:
            state = states.get(wid, TriState.UNKNOWN)
            node_states.append(state)

        return self._energy.compute(node_states, folds or [])

    def instrument_potential(
        self,
        instrument_name: str,
        instrument_wavelength: List[str],
        instrument_cost: float,
        target_ip: str,
        applicable_wickets: Set[str],
        folds: Optional[List[Fold]] = None,
        failure_penalty: float = 1.0,
    ) -> float:
        """
        Compute expected energy reduction potential for an instrument on a target.
        Replaces entropy_reduction_potential().

        potential = (unknowns_in_wavelength / cost) * failure_penalty
                  + escalation_boost if high-value preconditions confirmed

        Routes through GravityScheduler.rank() for formal correctness.
        """
        if not applicable_wickets:
            return 0.0

        states = self.states(target_ip)

        # Unknowns in instrument wavelength that are also applicable
        wave_applicable = set(instrument_wavelength) & applicable_wickets
        unknowns_in_reach = sum(
            1 for wid in wave_applicable
            if states.get(wid, TriState.UNKNOWN) == TriState.UNKNOWN
        )

        if unknowns_in_reach == 0:
            return 0.0

        # Build proposal for GravityScheduler
        proposal = {
            "expected_energy_reduction": float(unknowns_in_reach),
            "cost": max(instrument_cost, 1e-9),
            "failure_penalty": failure_penalty,
            "requires_operator_approval": False,
        }

        # MSF escalation: when high-value preconditions (CMDI, SQLi extraction,
        # webshell, CE privileged) are confirmed, MSF can collapse ALL remaining
        # unknowns across all domains on the target — not just its wavelength.
        # This is the correct formal interpretation: a successful exploit delivers
        # total E reduction for the target, which is unknown_count (all domains).
        if instrument_name == "metasploit":
            HIGH_VALUE = {"WB-14", "WB-10", "WB-20", "WB-21",
                          "CE-01", "CE-02", "CE-03"}
            realized_preconditions = [
                wid for wid in wave_applicable
                if states.get(wid) == TriState.REALIZED
            ]
            high_value_confirmed = [w for w in realized_preconditions if w in HIGH_VALUE]
            if high_value_confirmed:
                # Expected E reduction = all remaining unknowns in applicable set
                # (exploit success collapses the entire target's information deficit)
                all_unknowns = sum(
                    1 for wid in applicable_wickets
                    if states.get(wid, TriState.UNKNOWN) == TriState.UNKNOWN
                )
                proposal["expected_energy_reduction"] = float(max(
                    all_unknowns, proposal["expected_energy_reduction"]
                ))

        # GravityScheduler.rank() computes: score = (gain/cost) * failure_penalty * approval
        # Sort the single proposal and return its score directly.
        ranked = self._gravity.rank([proposal])
        # GravityScheduler returns proposals sorted by score; score = gain/cost * penalty
        gain = ranked[0]["expected_energy_reduction"]
        cost = max(ranked[0].get("cost", instrument_cost), 1e-9)
        penalty = ranked[0].get("failure_penalty", 1.0)
        return (gain / cost) * penalty
