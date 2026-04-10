"""
skg.kernel.field_local
======================
Paper 4 Section 2.2–2.3: Field Local L_i and Field Coupling K(L_i, L_j).

Field Local: persistent localized concentration of measured structure at
region (workload_id, domain) of the state space.

    L_i = grouping of observations by (workload_id, domain)
    E_self(L_i) = U_m(L_i) + E_local(L_i) + E_latent(L_i)

Field Coupling: inter-local influence when one local's structure informs another.

    E_couple(L_i, L_j) = K(L_i, L_j) × (E_local(L_j) + U_m(L_j))

Decoherence Criterion (Section 5): a field local is *protected* when all four
conditions hold simultaneously across its unresolved wickets:

    1. C ≥ 0.7          (compatibility_score — minimum in interior of stable basin)
    2. φ_contradiction < 0.15   (< 15% contradictory mass)
    3. φ_decoherence < 0.20     (< 20% decayed mass)
    4. n ≥ 2            (compatibility_span — at least two independent observation bases)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from skg.core.coupling import coupling_value

from .support import SupportContribution


# ---------------------------------------------------------------------------
# Paper 4 Table 1: Inter-local coupling constants K(L_i, L_j)
# ---------------------------------------------------------------------------
# Key: (domain_i, domain_j) — ordered by structural influence direction.
#
# Derivation rationale (Paper 4 §3.2 and §7):
#   K values are not arbitrary tuning parameters. They encode how much of
#   domain_i's realized structure is load-bearing evidence for domain_j's
#   unresolved wickets.  The scale is:
#
#     K = 0.90–0.95  —  direct structural dependency: domain_j *cannot* be
#                       realized without domain_i (e.g. cred→SSH auth, SMB→vuln).
#     K = 0.80–0.89  —  strong implication: domain_j is very likely to be
#                       reachable once domain_i is confirmed (host→SMB, web→CMDI).
#     K = 0.65–0.79  —  moderate: domain_j is enabled but not entailed
#                       (host→data, lateral→host back-coupling).
#     K = 0.50–0.64  —  weak lateral influence: discovery context only.
#     K = 0.10       —  default (no coupling data) — effectively decoupled.
#
#   Empirical calibration: values were adjusted after the EternalBlue and DVWA
#   runs (Paper 4 §7) so that the coupling energy term E_couple weighted the
#   host→smb→vuln chain above the web→data chain — matching observed instrument
#   selection order.  The credential row at 0.95 reflects that a recovered
#   credential *is* the precondition for SSH/web auth, so coupling is maximal.
#
#   Reverse-direction lookups (domain_j, domain_i) are computed with a 0.8×
#   discount by coupling_constant() below — structure flows downstream.
# Decoherence criterion thresholds (Paper 4 Section 5)
_DECOHERENCE_CRITERION = {
    "compatibility_score_min": 0.70,   # C ≥ 0.7
    "contradiction_max": 0.15,          # φ_contradiction < 0.15
    "decoherence_max": 0.20,            # φ_decoherence < 0.20
    "span_min": 2,                      # n ≥ 2
}


def coupling_constant(domain_i: str, domain_j: str) -> float:
    """
    Return K(L_i, L_j) for the given domain pair.
    Reads the active config-backed coupling table and applies reverse-direction
    discounting when only the opposite edge is defined.
    """
    return coupling_value(domain_i, domain_j, table="inter_local")


@dataclass
class FieldLocal:
    """
    Paper 4 Section 2.2: Field Local L_i.

    Persistent localized concentration of measured structure at (workload_id, domain).
    Groups observations by (workload_id, domain) and exposes the three self-energy
    components and the formal decoherence (protected-state) criterion.
    """
    local_id: str                              # f"{workload_id}::{domain}"
    workload_id: str                           # target IP or workload identifier
    domain: str                                # domain sphere: "web", "host", "data", etc.
    wicket_states: Dict[str, SupportContribution] = field(default_factory=dict)

    # ── Self-energy components ──────────────────────────────────────────────

    @property
    def U_m(self) -> float:
        """
        Unresolved mass: Σ φ_U over all wickets in this local.
        Measures how much of the local is still in superposition.
        """
        return sum(s.unresolved for s in self.wicket_states.values())

    @property
    def E_local(self) -> float:
        """
        Local energy: contradiction + decoherence load per wicket.
        Measures structural conflict and decay within this local.
        """
        return sum(
            s.contradiction + s.decoherence
            for s in self.wicket_states.values()
        )

    @property
    def E_latent(self) -> float:
        """
        Latent energy from single-basis (unconfirmed) observations.
        Each unresolved wicket with compatibility_span ≤ 1 contributes 0.5.
        """
        return sum(
            0.5
            for s in self.wicket_states.values()
            if s.compatibility_span <= 1 and s.unresolved > 0.0
        )

    @property
    def E_self(self) -> float:
        """
        Paper 4 Eq: E_self(L_i) = U_m(L_i) + E_local(L_i) + E_latent(L_i).
        Total self-energy of this field local.
        """
        return self.U_m + self.E_local + self.E_latent

    # ── Decoherence criterion ───────────────────────────────────────────────

    def wicket_is_protected(self, contrib: SupportContribution) -> bool:
        """
        Paper 4 Section 5: test whether a single wicket's support contribution
        satisfies all four decoherence criterion conditions.
        """
        c = _DECOHERENCE_CRITERION
        return (
            contrib.compatibility_score >= c["compatibility_score_min"]
            and contrib.contradiction < c["contradiction_max"]
            and contrib.decoherence < c["decoherence_max"]
            and contrib.compatibility_span >= c["span_min"]
        )

    def is_protected(self) -> bool:
        """
        Paper 4 Section 5: Decoherence Criterion.

        A field local Σ(L_i) is *protected* — a stable local minimum — iff
        ALL unresolved wickets within it satisfy the four-condition criterion.

        Protected locals are not re-observed: fresh instruments directed elsewhere
        (Proposition 4: protected = stable under any single instrument perturbation).
        """
        for contrib in self.wicket_states.values():
            if contrib.unresolved <= 0.0:
                continue  # already resolved, no protection check needed
            if not self.wicket_is_protected(contrib):
                return False
        return True

    def protection_fraction(self) -> float:
        """
        Fraction of unresolved wickets that are individually protected.
        0.0 = none protected, 1.0 = fully protected local.
        """
        unresolved = [s for s in self.wicket_states.values() if s.unresolved > 0.0]
        if not unresolved:
            return 1.0
        protected = sum(1 for s in unresolved if self.wicket_is_protected(s))
        return protected / len(unresolved)

    # ── Coupling ────────────────────────────────────────────────────────────

    def coupling_energy(self, other: "FieldLocal", K: Optional[float] = None) -> float:
        """
        Paper 4 Eq: E_couple(L_i, L_j) = K(L_i, L_j) × (E_local(L_j) + U_m(L_j)).

        K is the inter-local coupling constant. If not supplied, looks up from
        the canonical coupling table using (self.domain, other.domain).
        """
        k = K if K is not None else coupling_constant(self.domain, other.domain)
        return k * (other.E_local + other.U_m)

    # ── Fiber-driven gravity terms ──────────────────────────────────────────

    def decoherence_load(self) -> float:
        """
        Paper 4 Section 4, Term 3: D(L_i) — total decoherence load.
        Used in Φ_decoherence to route instruments toward contradictory locals.
        """
        return sum(
            s.decoherence + s.contradiction
            for s in self.wicket_states.values()
        )

    def tension_times_coherence(self) -> float:
        """
        Paper 4 Section 4, Term 1 proxy: tension × coherence for this local.
        Approximates Σ_ν tension(F_ν) × coherence(F_ν) using support-derived values.
        """
        # coherence proxy: mean compatibility_score across unresolved wickets
        unresolved = [s for s in self.wicket_states.values() if s.unresolved > 0.0]
        if not unresolved:
            return 0.0
        mean_coherence = sum(s.compatibility_score for s in unresolved) / len(unresolved)
        # tension proxy: mean phi_u (unresolved mass)
        mean_tension = sum(s.unresolved for s in unresolved) / len(unresolved)
        return mean_tension * mean_coherence

    # ── Serialization ───────────────────────────────────────────────────────

    def as_dict(self) -> dict:
        return {
            "local_id": self.local_id,
            "workload_id": self.workload_id,
            "domain": self.domain,
            "n_wickets": len(self.wicket_states),
            "U_m": round(self.U_m, 6),
            "E_local": round(self.E_local, 6),
            "E_latent": round(self.E_latent, 6),
            "E_self": round(self.E_self, 6),
            "is_protected": self.is_protected(),
            "protection_fraction": round(self.protection_fraction(), 4),
            "decoherence_load": round(self.decoherence_load(), 6),
        }


# ---------------------------------------------------------------------------
# Factory — build FieldLocal objects from kernel states_with_detail output
# ---------------------------------------------------------------------------

def build_field_locals(
    node_key: str,
    states_detail: Dict[str, dict],
    domain_wickets: Dict[str, set],
) -> List[FieldLocal]:
    """
    Construct one FieldLocal per domain from kernel states_with_detail() output.

    Args:
        node_key:       Stable identity anchor (identity_key) for the node.
        states_detail:  Output of KernelStateEngine.states_with_detail(node_key).
        domain_wickets: {domain: set of wicket_ids} from load_all_wicket_ids().

    Returns:
        List of FieldLocal, one per domain that has at least one known wicket.
    """
    # Invert domain_wickets to get wicket → domain mapping
    wicket_to_domain: Dict[str, str] = {}
    for domain, wickets in domain_wickets.items():
        for wid in wickets:
            wicket_to_domain[wid] = domain

    # Group support contributions by domain
    by_domain: Dict[str, Dict[str, SupportContribution]] = {}
    for wicket_id, state_info in states_detail.items():
        domain = wicket_to_domain.get(wicket_id, "unknown")
        contrib = _state_info_to_contrib(state_info)
        by_domain.setdefault(domain, {})[wicket_id] = contrib

    # Also create FieldLocals for domains with no observed wickets (pure unknowns)
    for domain, wickets in domain_wickets.items():
        if domain not in by_domain:
            # All wickets unknown — maximum tension
            by_domain[domain] = {
                wid: SupportContribution(unresolved=1.0, compatibility_span=0)
                for wid in wickets
            }

    return [
        FieldLocal(
            local_id=f"{node_key}::{domain}",
            workload_id=node_key,
            domain=domain,
            wicket_states=wicket_states,
        )
        for domain, wicket_states in by_domain.items()
        if wicket_states
    ]


def _state_info_to_contrib(info: dict) -> SupportContribution:
    """Convert a states_with_detail dict entry to SupportContribution."""
    return SupportContribution(
        realized=float(info.get("phi_r", 0.0) or 0.0),
        blocked=float(info.get("phi_b", 0.0) or 0.0),
        unresolved=float(info.get("phi_u", 0.0) or 0.0),
        contradiction=float(info.get("contradiction", 0.0) or 0.0),
        decoherence=float(info.get("decoherence", 0.0) or 0.0),
        compatibility_score=float(info.get("compatibility_score", 0.0) or 0.0),
        compatibility_span=int(info.get("compatibility_span", 0) or 0),
    )


# ---------------------------------------------------------------------------
# Field functional L(F)
# ---------------------------------------------------------------------------

def field_functional(locals_: List[FieldLocal]) -> float:
    """
    Paper 4 Eq: L(F) = Σ_i E_self(L_i) + Σ_{i<j} E_couple(L_i, L_j) + D(F)

    D(F) = total dissipation = Σ_i D(L_i) (decoherence + contradiction loads).
    Curvature κ(F) omitted here (handled by pearl manifold).

    Proposition 1 (Boundedness): L(F) ≥ 0.
    Proposition 3 (Monotone Reduction): new observations reduce L(F).
    """
    from .field_functional import field_functional as _canonical_field_functional

    return _canonical_field_functional(locals_)


def phi_fiber(
    instrument_wavelength: List[str],
    instrument_cost: float,
    locals_: List[FieldLocal],
    other_locals: Optional[List[FieldLocal]] = None,
) -> float:
    """
    Paper 4 Section 4: Full fiber-driven gravity selection potential.

    Φ_fiber(I, t) = [
        Σ_ν tension(F_ν) × coherence(F_ν) × 𝟙[W(I) ∩ F_ν ≠ ∅]   (Term 1)
      + Σ_j K(·, L_j) × U_m(L_j) × 𝟙[W(I) ∩ L_j ≠ ∅]            (Term 2)
      + Σ_i D(L_i) × 𝟙[W(I) ∩ L_i ≠ ∅]                           (Term 3)
    ] / c(I)

    Args:
        instrument_wavelength: List of wicket IDs in instrument reach W(I).
        instrument_cost:       c(I) — instrument cost scalar.
        locals_:               FieldLocals for the primary target.
        other_locals:          FieldLocals for coupled targets (cross-target coupling).
    """
    from .field_functional import phi_fiber as _canonical_phi_fiber

    return _canonical_phi_fiber(
        instrument_wavelength,
        instrument_cost,
        locals_,
        other_locals=other_locals,
    )
