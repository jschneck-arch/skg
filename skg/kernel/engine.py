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

# Wicket-prefix to domain mapping for _infer_domain_wickets()
_WICKET_PREFIX_DOMAIN: Dict[str, str] = {
    "WB-": "web",
    "HO-": "host",
    "DA-": "data",
    "CE-": "container",
    "LA-": "lateral",
    "BI-": "binary",
    "AI-": "ai_target",
    "SC-": "supply_chain",
    "IO-": "iot_firmware",
    "AP-": "aprs",
}


def _infer_domain_wickets(wicket_ids: Set[str]) -> Dict[str, Set[str]]:
    """Infer {domain: {wicket_id}} from wicket ID prefixes when no catalog is available."""
    result: Dict[str, Set[str]] = {}
    for wid in wicket_ids:
        domain = "unknown"
        for prefix, d in _WICKET_PREFIX_DOMAIN.items():
            if wid.startswith(prefix):
                domain = d
                break
        result.setdefault(domain, set()).add(wid)
    return result

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
            unresolved_reason = "unmeasured"
            if contrib.contradiction > 0.0:
                unresolved_reason = "conflicted"
            elif contrib.decoherence > 0.0 and contrib.unresolved > 0.0:
                unresolved_reason = "decohered"
            elif contrib.unresolved > 0.0 and contrib.realized == 0.0 and contrib.blocked == 0.0:
                unresolved_reason = "inconclusive"
            elif contrib.realized > 0.0 or contrib.blocked > 0.0:
                unresolved_reason = "insufficient_support"
            if contrib.compatibility_span <= 1 and contrib.unresolved > 0.0:
                unresolved_reason = "single_basis"
            if any(bool(o.payload.get("is_latent", False)) for o in wk_obs):
                unresolved_reason = "latent"
            local_energy = contrib.unresolved + contrib.contradiction + contrib.decoherence

            result[wicket_id] = {
                "status": state.value,
                "detail": detail,
                "ts": ts,
                # Include support values for FeedbackIngester and paper metrics
                "phi_r": contrib.realized,
                "phi_b": contrib.blocked,
                "phi_u": contrib.unresolved,
                "contradiction": contrib.contradiction,
                "decoherence": contrib.decoherence,
                "compatibility_score": contrib.compatibility_score,
                "compatibility_span": contrib.compatibility_span,
                "local_energy": local_energy,
                "unresolved_reason": unresolved_reason,
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

        states = self.states_with_detail(target_ip)
        node_states = []
        for wid in applicable_wickets:
            state = states.get(
                wid,
                {
                    "status": TriState.UNKNOWN.value,
                    "phi_u": 1.0,
                    "decoherence": 0.0,
                    "compatibility_score": 0.0,
                    "compatibility_span": 0,
                    "unresolved_reason": "unmeasured",
                },
            )
            node_states.append(state)

        return self._energy.compute_weighted(node_states, folds or [])

    def instrument_potential(
        self,
        instrument_name: str,
        instrument_wavelength: List[str],
        instrument_cost: float,
        target_ip: str,
        applicable_wickets: Set[str],
        folds: Optional[List[Fold]] = None,
        failure_penalty: float = 1.0,
        domain_wickets: Optional[Dict] = None,
    ) -> float:
        """
        Compute expected energy reduction potential for an instrument on a target.
        Replaces entropy_reduction_potential().

        Paper 4 Section 4: Φ_effective(I, t) combines:
          1. Base potential (Work 3 flat-space limit): unknowns_in_wavelength / cost
          2. Fiber-driven gravity Φ_fiber: three-term formula over FieldLocals
          3. MSF escalation boost for high-value confirmed preconditions

        Φ_effective = base + α × Φ_fiber   (α=0.35 balancing terms)

        Routes through GravityScheduler.rank() for formal correctness.
        """
        if not applicable_wickets:
            return 0.0

        states = self.states_with_detail(target_ip)

        # Unknowns in instrument wavelength that are also applicable
        wave_applicable = set(instrument_wavelength) & applicable_wickets
        unresolved_in_reach = 0.0
        for wid in wave_applicable:
            item = states.get(
                wid,
                {"status": TriState.UNKNOWN.value, "phi_u": 1.0, "decoherence": 0.0, "compatibility_score": 0.0},
            )
            if item.get("status", TriState.UNKNOWN.value) != TriState.UNKNOWN.value:
                continue
            unresolved_in_reach += max(
                float(item.get("phi_u", 0.0) or 0.0),
                float(item.get("local_energy", 0.0) or 0.0),
                1.0,
            ) + float(item.get("contradiction", 0.0) or 0.0) + float(item.get("decoherence", 0.0) or 0.0)

        if unresolved_in_reach <= 0.0:
            return 0.0

        # ── Paper 4 Section 4: Fiber-driven gravity Φ_fiber ─────────────────
        # Build FieldLocals for this target and compute the three-term formula.
        # Skip protected locals (Proposition 4: stable local minimum — no benefit
        # from re-observing). This is the formal decoherence criterion in action.
        phi_fiber_score = 0.0
        try:
            from .field_local import build_field_locals, phi_fiber as _phi_fiber
            _domain_wickets = domain_wickets or {}
            # Build applicable domain_wickets subset from applicable_wickets
            if not _domain_wickets:
                # Fallback: infer domain from wicket prefix
                _domain_wickets = _infer_domain_wickets(applicable_wickets)
            locals_ = build_field_locals(target_ip, states, _domain_wickets)
            # Filter out fully protected locals — Proposition 4
            active_locals = [loc for loc in locals_ if not loc.is_protected()]
            if active_locals:
                phi_fiber_score = _phi_fiber(
                    instrument_wavelength=list(instrument_wavelength),
                    instrument_cost=instrument_cost,
                    locals_=active_locals,
                )
        except Exception:
            phi_fiber_score = 0.0

        # ── Build base proposal ──────────────────────────────────────────────
        # α = 0.35: fiber-driven term supplements but does not dominate base potential
        alpha = 0.35
        combined_gain = unresolved_in_reach + alpha * phi_fiber_score
        proposal = {
            "expected_energy_reduction": float(combined_gain),
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
                if states.get(wid, {}).get("status") == TriState.REALIZED.value
            ]
            high_value_confirmed = [w for w in realized_preconditions if w in HIGH_VALUE]
            if high_value_confirmed:
                # Expected E reduction = all remaining unknowns in applicable set
                # (exploit success collapses the entire target's information deficit)
                all_unknowns = 0.0
                for wid in applicable_wickets:
                    item = states.get(
                        wid,
                        {"status": TriState.UNKNOWN.value, "phi_u": 1.0, "decoherence": 0.0, "compatibility_score": 0.0},
                    )
                    if item.get("status", TriState.UNKNOWN.value) != TriState.UNKNOWN.value:
                        continue
                    all_unknowns += max(
                        float(item.get("phi_u", 0.0) or 0.0),
                        float(item.get("local_energy", 0.0) or 0.0),
                        1.0,
                    ) + float(item.get("contradiction", 0.0) or 0.0) + float(item.get("decoherence", 0.0) or 0.0)
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

    def field_locals(
        self,
        target_ip: str,
        domain_wickets: Optional[Dict] = None,
    ):
        """
        Paper 4 Section 2.2: Build first-class FieldLocal objects for a target.

        Returns List[FieldLocal] — one per domain with known wickets.
        Exposed for UI, reporting, and field_functional() computation.
        """
        from .field_local import build_field_locals
        states = self.states_with_detail(target_ip)
        _domain_wickets = domain_wickets or _infer_domain_wickets(
            set(states.keys())
        )
        return build_field_locals(target_ip, states, _domain_wickets)

    def L_field_functional(
        self,
        target_ip: str,
        domain_wickets: Optional[Dict] = None,
    ) -> float:
        """
        Paper 4 Eq: L(F) = Σ_i E_self(L_i) + Σ_{i<j} E_couple(L_i, L_j) + D(F).

        Returns the full unified field functional value for this target.
        """
        from .field_local import field_functional
        locals_ = self.field_locals(target_ip, domain_wickets)
        return field_functional(locals_)
