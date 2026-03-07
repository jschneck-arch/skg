"""
skg.graph
=========
Cross-workload relationship model for SKG.

The WorkloadGraph models how targets relate to each other and
propagates state priors across those relationships.

Why this matters
----------------
Attack paths don't respect workload boundaries. If AD-08 (kerberoastable
hash captured) is confirmed on workload A, and workload B shares a domain
with A, the prior for AD-08 on workload B just went up — not to 1.0, but
meaningfully higher than baseline. The graph makes this explicit.

Relationship types
------------------
  same_domain       — same AD domain (strong propagation for AD wickets)
  same_subnet       — same /24 (propagation for network-observable wickets)
  trust_relationship — domain trust (weaker propagation, direction-aware)
  credential_overlap — credential reuse observed (strong for auth wickets)
  network_adjacent   — reachable from each other (egress wickets)

Propagation model
-----------------
When a wicket transitions to "realized" on workload A:
  For each neighbor B with relationship type R:
    prior_adjustment(B, wicket) += PROPAGATION_WEIGHT[R] * signal_weight

The prior adjustment is stored as a float per (workload_id, wicket_id).
It does NOT change the wicket's state — it adjusts the confidence on the
*next observation*. The sensor reads this prior and factors it into the
confidence field of the envelope event it emits.

This preserves append-only and determinism: the projection engine still
sees raw evidence. The graph enriches the evidence, not the projection.

Persistence
-----------
  graph/edges.jsonl          — relationship edges (append-only)
  graph/priors.jsonl         — current prior adjustments per workload+wicket
  graph/propagation_log.jsonl — every propagation event (audit trail)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("skg.graph")

# Propagation weights by relationship type
# How much a realized wicket on A raises the prior for the same wicket on B
PROPAGATION_WEIGHT = {
    "same_domain":         0.35,
    "credential_overlap":  0.45,
    "same_subnet":         0.20,
    "network_adjacent":    0.15,
    "trust_relationship":  0.25,
}

# Which domains/wicket patterns propagate across which relationship types
# Only propagate wickets that make sense for the relationship
PROPAGATION_SCOPE = {
    "same_domain":        {"domains": ["ad_lateral"], "prefix": ["AD-"]},
    "credential_overlap": {"domains": ["ad_lateral", "aprs"], "prefix": ["AD-", "AP-"]},
    "same_subnet":        {"domains": ["aprs", "container_escape"], "prefix": ["AP-L7", "CE-"]},
    "network_adjacent":   {"domains": ["aprs"], "prefix": ["AP-L7", "AP-L8"]},
    "trust_relationship": {"domains": ["ad_lateral"], "prefix": ["AD-"]},
}

MAX_PRIOR = 0.85   # cap on propagated prior (never reaches 1.0 from graph alone)
DECAY_PER_PROJECTION = 0.05  # priors decay if not reinforced


@dataclass
class WorkloadEdge:
    """A directed relationship between two workloads."""
    source_workload:  str
    target_workload:  str
    relationship:     str       # same_domain | same_subnet | etc.
    weight:           float     # custom weight override (0.0 = use default)
    metadata:         dict      # domain name, subnet, credential hash, etc.
    observed_at:      str
    source:           str       # what produced this edge (sensor, manual, etc.)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "WorkloadEdge":
        return cls(**d)


@dataclass
class WicketPrior:
    """
    A prior probability adjustment for a wicket on a specific workload.
    Accumulated from graph propagation, decays over time without reinforcement.
    """
    workload_id:   str
    wicket_id:     str
    domain:        str
    prior:         float       # 0.0 → MAX_PRIOR
    sources:       list[str]   # workload_ids that contributed to this prior
    last_updated:  str
    projection_count: int      # how many projections since last reinforcement

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "WicketPrior":
        return cls(**d)


class WorkloadGraph:
    """
    Manages workload relationships and propagates state priors.

    Consumed by:
      - Sensors (read priors before emitting events — adjust confidence)
      - DeltaStore (after transitions — trigger propagation)
      - Daemon status endpoint
    """

    def __init__(self, graph_dir: Path):
        self.graph_dir     = graph_dir
        self.edges_path    = graph_dir / "edges.jsonl"
        self.priors_path   = graph_dir / "priors.jsonl"
        self.prop_log_path = graph_dir / "propagation_log.jsonl"
        self._edges: list[WorkloadEdge] = []
        self._priors: dict[str, WicketPrior] = {}  # key: workload::wicket
        graph_dir.mkdir(parents=True, exist_ok=True)

    def load(self):
        """Load edges and priors from disk."""
        self._edges = []
        if self.edges_path.exists():
            for line in self.edges_path.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    self._edges.append(WorkloadEdge.from_dict(json.loads(line)))
                except Exception:
                    pass

        self._priors = {}
        if self.priors_path.exists():
            for line in self.priors_path.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    p = WicketPrior.from_dict(json.loads(line))
                    key = f"{p.workload_id}::{p.wicket_id}"
                    # Last write wins on load (most recent prior for each key)
                    self._priors[key] = p
                except Exception:
                    pass

        log.info(f"WorkloadGraph: {len(self._edges)} edges, {len(self._priors)} priors loaded")

    # ── Edge management ───────────────────────────────────────────────────────

    def add_edge(
        self,
        source: str,
        target: str,
        relationship: str,
        metadata: dict | None = None,
        weight: float = 0.0,
        edge_source: str = "manual",
    ) -> WorkloadEdge:
        """
        Add a relationship edge. Bidirectional edges require two calls.
        Idempotent — duplicate edges are allowed (they reinforce).
        """
        edge = WorkloadEdge(
            source_workload=source,
            target_workload=target,
            relationship=relationship,
            weight=weight or PROPAGATION_WEIGHT.get(relationship, 0.1),
            metadata=metadata or {},
            observed_at=datetime.now(timezone.utc).isoformat(),
            source=edge_source,
        )
        self._edges.append(edge)
        with self.edges_path.open("a") as fh:
            fh.write(edge.to_json() + "\n")
        log.info(f"[graph] edge: {source} --[{relationship}]--> {target}")
        return edge

    def neighbors(self, workload_id: str, relationship: str | None = None) -> list[tuple[str, str, float]]:
        """
        Return (neighbor_workload_id, relationship, weight) for all neighbors.
        Both directions for undirected relationships.
        """
        results = []
        seen = set()
        for edge in self._edges:
            rel = edge.relationship
            if relationship and rel != relationship:
                continue
            w = edge.weight
            if edge.source_workload == workload_id:
                key = (edge.target_workload, rel)
                if key not in seen:
                    results.append((edge.target_workload, rel, w))
                    seen.add(key)
            elif edge.target_workload == workload_id:
                key = (edge.source_workload, rel)
                if key not in seen:
                    results.append((edge.source_workload, rel, w))
                    seen.add(key)
        return results

    # ── Prior management ──────────────────────────────────────────────────────

    def get_prior(self, workload_id: str, wicket_id: str) -> float:
        """
        Return the current prior adjustment for a wicket on a workload.
        0.0 if no prior exists. Decayed by projection count.
        """
        key = f"{workload_id}::{wicket_id}"
        p = self._priors.get(key)
        if p is None:
            return 0.0
        # Apply decay
        decay = p.projection_count * DECAY_PER_PROJECTION
        return max(0.0, p.prior - decay)

    def propagate_transition(
        self,
        source_workload: str,
        wicket_id: str,
        domain: str,
        to_state: str,
        signal_weight: float,
    ):
        """
        After a wicket transitions on source_workload, propagate priors
        to neighbors. Only propagates for meaningful transitions.
        Called by the feedback ingester after DeltaStore.ingest_projection().
        """
        if to_state not in ("realized",):
            # Only propagate positive realizations for now
            # (blocking on one workload doesn't mean blocking on neighbors)
            return

        neighbors = self.neighbors(source_workload)
        now = datetime.now(timezone.utc).isoformat()

        for (neighbor, relationship, edge_weight) in neighbors:
            # Check if this wicket type is in scope for this relationship
            scope = PROPAGATION_SCOPE.get(relationship, {})
            scope_domains = scope.get("domains", [])
            scope_prefixes = scope.get("prefix", [])

            in_scope = (
                domain in scope_domains and
                any(wicket_id.startswith(p) for p in scope_prefixes)
            )
            if not in_scope:
                continue

            # Compute adjustment
            adjustment = edge_weight * signal_weight
            key = f"{neighbor}::{wicket_id}"
            existing = self._priors.get(key)

            if existing:
                new_prior = min(MAX_PRIOR, existing.prior + adjustment)
                sources = list(set(existing.sources + [source_workload]))
                prior = WicketPrior(
                    workload_id=neighbor,
                    wicket_id=wicket_id,
                    domain=domain,
                    prior=new_prior,
                    sources=sources,
                    last_updated=now,
                    projection_count=0,  # reset decay on update
                )
            else:
                prior = WicketPrior(
                    workload_id=neighbor,
                    wicket_id=wicket_id,
                    domain=domain,
                    prior=min(MAX_PRIOR, adjustment),
                    sources=[source_workload],
                    last_updated=now,
                    projection_count=0,
                )

            self._priors[key] = prior
            with self.priors_path.open("a") as fh:
                fh.write(prior.to_json() + "\n")

            # Audit log
            prop_entry = {
                "ts": now,
                "source": source_workload,
                "target": neighbor,
                "wicket_id": wicket_id,
                "relationship": relationship,
                "adjustment": round(adjustment, 4),
                "new_prior": round(prior.prior, 4),
            }
            with self.prop_log_path.open("a") as fh:
                fh.write(json.dumps(prop_entry) + "\n")

            log.info(
                f"[graph] propagated {wicket_id} {source_workload}→{neighbor} "
                f"via {relationship}: prior={prior.prior:.3f}"
            )

    def decay_priors(self, workload_id: str):
        """
        Increment projection_count for all priors on this workload.
        Called after each projection run — priors decay if not reinforced.
        """
        now = datetime.now(timezone.utc).isoformat()
        updated = []
        for key, p in self._priors.items():
            if p.workload_id == workload_id:
                p.projection_count += 1
                p.last_updated = now
                updated.append(p)

        if updated:
            # Rewrite priors file with updated decay counts
            # (We append; last entry per key wins on load)
            with self.priors_path.open("a") as fh:
                for p in updated:
                    fh.write(p.to_json() + "\n")

    def infer_edges_from_events(self, events: list[dict]):
        """
        Auto-discover relationships from sensor events.
        Looks for:
          - Same domain membership (AD events with domain field)
          - Same subnet (IP prefix matching)
          - BloodHound trust data
        """
        # Group workloads by domain
        by_domain: dict[str, list[str]] = {}
        by_subnet: dict[str, list[str]] = {}

        for ev in events:
            if ev.get("type") != "obs.attack.precondition":
                continue
            payload = ev.get("payload", {})
            wid = payload.get("workload_id", "")
            domain = payload.get("domain", "")
            if not wid:
                continue

            # AD domain membership from host_meta or payload
            meta = payload.get("host_meta", {})
            ad_domain = meta.get("ad_domain", "")
            if ad_domain:
                by_domain.setdefault(ad_domain, [])
                if wid not in by_domain[ad_domain]:
                    by_domain[ad_domain].append(wid)

            # Subnet from IP in workload_id or host_meta
            ip = meta.get("hostname", "") or wid.split("::")[-1]
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = ".".join(parts[:3])
                by_subnet.setdefault(subnet, [])
                if wid not in by_subnet[subnet]:
                    by_subnet[subnet].append(wid)

        # Add same_domain edges
        for ad_domain, workloads in by_domain.items():
            for i, w1 in enumerate(workloads):
                for w2 in workloads[i+1:]:
                    self.add_edge(w1, w2, "same_domain",
                                  metadata={"ad_domain": ad_domain},
                                  edge_source="auto_inference")

        # Add same_subnet edges
        for subnet, workloads in by_subnet.items():
            for i, w1 in enumerate(workloads):
                for w2 in workloads[i+1:]:
                    self.add_edge(w1, w2, "same_subnet",
                                  metadata={"subnet": subnet},
                                  edge_source="auto_inference")

    def status(self) -> dict:
        return {
            "edge_count":  len(self._edges),
            "prior_count": len(self._priors),
            "workloads":   len(set(
                e.source_workload for e in self._edges
            ) | set(
                e.target_workload for e in self._edges
            )),
        }
