"""
skg.substrate.bond
==================
BondState — canonical representation of a bond between two nodes/workloads.

Bonds are directional field couplings discovered from topology.
They propagate priors across the gravity web: a realization on one
end increases gravitational pull on the same condition at the other end.

Bond types (Work 3 Section 7.2, in descending strength):
  same_host     1.00  — same physical or logical host
  docker_host   0.90  — container gateway relationship
  same_compose  0.80  — same Docker Compose network
  shared_cred   0.70  — shared credential material observed
  same_domain   0.60  — same AD/LDAP domain
  same_subnet   0.40  — same /24 subnet

  Data pipeline bonds:
  upstream_of   1.00  — A is the direct upstream source for B
  derived_from  0.90  — B is a transformation of A
  same_batch    0.80  — co-scheduled in same ETL run
  shared_schema 0.70  — share a schema contract
  same_database 0.60  — same database instance
  same_pipeline 0.40  — stages in the same declared pipeline

The strength s_ij is the edge weight in the weighted Kuramoto coupling graph.
In the Kuramoto layer it is the coupling coefficient w_ij.

Prior propagation formula (Work 3 Section 7.4):
  P_B(n, t) = s_ij × SW(t)

  where s_ij ∈ BOND_STRENGTHS is the static structural coupling strength
  and SW(t) is the signal_weight of the triggering transition.

  This is NOT a Bayesian update. It is a discrete-time approximation of
  the Kuramoto coupling contribution that a phase transition at node i
  exerts on the natural frequency of node j:

    Δω_j ≈ (K/N) × w_ij × A_i × sin(φ_i - φ_j)

  At the moment of realization (φ_i → 0), sin(φ_i - φ_j) is maximised
  when φ_j = π/2 (unknown). The adjustment is therefore bounded by
  (K/N) × w_ij × A_i ≤ w_ij × A_i when K = N.

  We approximate A_i by signal_weight (the confidence of the observation
  that triggered the transition) and drop the K/N factor (absorbed into
  the MAX_PRIOR = 0.85 ceiling in WorkloadGraph). The result:

    P_B(n) = s_ij × SW(t)

  This is an honest approximation, not a derivation. The formula captures
  the correct monotone relationship (stronger bond → larger prior boost;
  higher-confidence observation → larger prior boost) while remaining
  computationally tractable for the discrete engagement loop.

  The approximation deteriorates when the graph is highly asymmetric (most
  bonds are same_subnet = 0.40) or when SW is poorly calibrated. Both are
  acknowledged limitations in the paper.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

BOND_STRENGTHS: dict[str, float] = {
    # Network/host topology bonds
    "same_host":    1.00,
    "docker_host":  0.90,
    "same_compose": 0.80,
    "shared_cred":  0.70,
    "same_domain":  0.60,
    "same_subnet":  0.40,
    # Data pipeline topology bonds
    "upstream_of":   1.00,
    "derived_from":  0.90,
    "same_batch":    0.80,
    "shared_schema": 0.70,
    "same_database": 0.60,
    "same_pipeline": 0.40,
}

PRIOR_ALPHA: float = 1.0
# Prior propagation: P_B(n) = strength × signal_weight.
# PRIOR_ALPHA = 1.0 reflects that the full bond strength is applied —
# attenuation comes from the signal_weight of the triggering observation
# (0.0–1.0) rather than from a separate constant.
# See module docstring and WorkloadGraph.propagate_transition for the
# full derivation and the MAX_PRIOR ceiling that bounds accumulation.


@dataclass
class BondState:
    """
    A bond between two workloads/targets in the gravity web.

    ip1, ip2    — the two endpoints (canonical key: sorted tuple)
    bond_type   — one of BOND_STRENGTHS keys
    strength    — coupling coefficient [0, 1]
    established_at — ISO timestamp when bond was first detected
    source      — how the bond was detected (auto_topology / manual / inference)
    metadata    — arbitrary extra context (subnet, domain name, etc.)
    """
    ip1: str
    ip2: str
    bond_type: str
    strength: float
    established_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str = "auto_topology"
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Canonical key is always (smaller, larger) for deduplication
        if self.ip1 > self.ip2:
            self.ip1, self.ip2 = self.ip2, self.ip1
        # Clamp strength
        self.strength = max(0.0, min(1.0, float(self.strength)))

    @property
    def key(self) -> tuple[str, str]:
        return (self.ip1, self.ip2)

    @property
    def prior_influence(self) -> float:
        """
        P_B(n) at unit signal weight.
        Full formula: P_B(n, t) = strength × SW(t).
        This returns the bond's contribution assuming SW = 1.0.
        WorkloadGraph.propagate_transition scales by the actual SW.
        """
        return round(self.strength * PRIOR_ALPHA, 6)

    @classmethod
    def from_type(
        cls,
        ip1: str,
        ip2: str,
        bond_type: str,
        source: str = "auto_topology",
        metadata: Optional[dict] = None,
    ) -> "BondState":
        """Construct a BondState with the canonical strength for bond_type."""
        strength = BOND_STRENGTHS.get(bond_type, 0.3)
        return cls(
            ip1=ip1,
            ip2=ip2,
            bond_type=bond_type,
            strength=strength,
            source=source,
            metadata=metadata or {},
        )

    def as_dict(self) -> dict:
        return {
            "ip1":            self.ip1,
            "ip2":            self.ip2,
            "bond_type":      self.bond_type,
            "strength":       round(self.strength, 4),
            "prior_influence": self.prior_influence,
            "established_at": self.established_at,
            "source":         self.source,
            "metadata":       self.metadata,
        }
