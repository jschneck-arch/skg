"""
skg.graph
=========
Cross-workload relationship model for SKG.

The WorkloadGraph models how targets relate to each other and
propagates state priors across those relationships.

Important boundary:
- The graph does NOT change node/wicket truth directly.
- It adjusts priors for the next observation on neighboring workloads.

Conceptual note:
A wicket here is treated as a security-domain condition identifier.
This module remains backward-compatible with wicket_id while also
supporting node-compatible aliases.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("skg.graph")

# Propagation weights by relationship type
PROPAGATION_WEIGHT = {
    "same_domain":         0.35,
    "credential_overlap":  0.45,
    "same_subnet":         0.20,
    "network_adjacent":    0.15,
    "trust_relationship":  0.25,
}

# Which domains/condition patterns propagate across which relationship types
PROPAGATION_SCOPE = {
    "same_domain":        {"domains": ["ad_lateral"], "prefix": ["AD-"]},
    "credential_overlap": {"domains": ["ad_lateral", "aprs"], "prefix": ["AD-", "AP-"]},
    "same_subnet":        {"domains": ["aprs", "container_escape"], "prefix": ["AP-L7", "CE-"]},
    "network_adjacent":   {"domains": ["aprs"], "prefix": ["AP-L7", "AP-L8"]},
    "trust_relationship": {"domains": ["ad_lateral"], "prefix": ["AD-"]},
}

MAX_PRIOR = 0.85
DECAY_PER_PROJECTION = 0.05


def _safe_condition_id(wicket_id: str | None = None, node_id: str | None = None) -> str:
    """
    Backward-compatible condition identifier helper.
    """
    return node_id or wicket_id or ""


def _in_scope(condition_id: str, domain: str, relationship: str) -> bool:
    scope = PROPAGATION_SCOPE.get(relationship, {})
    scope_domains = scope.get("domains", [])
    scope_prefixes = scope.get("prefix", [])

    return (
        domain in scope_domains and
        any(condition_id.startswith(prefix) for prefix in scope_prefixes)
    )


@dataclass
class WorkloadEdge:
    """A directed relationship between two workloads."""
    source_workload: str
    target_workload: str
    relationship: str
    weight: float
    metadata: dict
    observed_at: str
    source: str

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
    A prior probability adjustment for a condition on a specific workload.
    Backward-compatible name retained.
    """
    workload_id: str
    wicket_id: str
    domain: str
    prior: float
    sources: list[str]
    last_updated: str
    projection_count: int

    def to_dict(self) -> dict:
        d = asdict(self)
        d["node_id"] = self.wicket_id
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "WicketPrior":
        if "wicket_id" not in d and "node_id" in d:
            d = dict(d)
            d["wicket_id"] = d["node_id"]
        return cls(**{k: v for k, v in d.items() if k != "node_id"})

    @property
    def node_id(self) -> str:
        return self.wicket_id


class WorkloadGraph:
    """
    Manages workload relationships and propagates state priors.

    Consumed by:
      - sensors (read priors before emitting events)
      - temporal feedback (after transitions)
      - status / CLI surfaces
    """

    def __init__(self, graph_dir: Path):
        self.graph_dir = graph_dir
        self.edges_path = graph_dir / "edges.jsonl"
        self.priors_path = graph_dir / "priors.jsonl"
        self.prop_log_path = graph_dir / "propagation_log.jsonl"

        self._edges: list[WorkloadEdge] = []
        self._priors: dict[str, WicketPrior] = {}  # key: workload::condition

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
        Add a relationship edge.
        Bidirectional edges require two calls if direction matters.
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

    def get_prior(self, workload_id: str, wicket_id: str | None = None, node_id: str | None = None) -> float:
        """
        Return the current prior adjustment for a condition on a workload.
        0.0 if no prior exists. Decayed by projection count.
        """
        condition_id = _safe_condition_id(wicket_id=wicket_id, node_id=node_id)
        key = f"{workload_id}::{condition_id}"
        p = self._priors.get(key)
        if p is None:
            return 0.0

        decay = p.projection_count * DECAY_PER_PROJECTION
        return max(0.0, p.prior - decay)

    def propagate_transition(
        self,
        source_workload: str,
        wicket_id: str | None = None,
        domain: str = "",
        to_state: str = "",
        signal_weight: float = 0.0,
        node_id: str | None = None,
        transition_metadata: dict | None = None,
    ):
        """
        After a condition transitions on source_workload, propagate priors
        to neighbors. Only propagates for meaningful positive realizations.

        Backward-compatible:
        - existing callers can still pass wicket_id
        - newer callers may pass node_id
        """
        condition_id = _safe_condition_id(wicket_id=wicket_id, node_id=node_id)
        if not condition_id:
            return

        if to_state not in ("realized",):
            return

        neighbors = self.neighbors(source_workload)
        now = datetime.now(timezone.utc).isoformat()
        transition_metadata = transition_metadata or {}

        for (neighbor, relationship, edge_weight) in neighbors:
            if not _in_scope(condition_id, domain, relationship):
                continue

            adjustment = edge_weight * signal_weight
            key = f"{neighbor}::{condition_id}"
            existing = self._priors.get(key)

            if existing:
                new_prior = min(MAX_PRIOR, existing.prior + adjustment)
                sources = list(set(existing.sources + [source_workload]))
                prior = WicketPrior(
                    workload_id=neighbor,
                    wicket_id=condition_id,
                    domain=domain,
                    prior=new_prior,
                    sources=sources,
                    last_updated=now,
                    projection_count=0,
                )
            else:
                prior = WicketPrior(
                    workload_id=neighbor,
                    wicket_id=condition_id,
                    domain=domain,
                    prior=min(MAX_PRIOR, adjustment),
                    sources=[source_workload],
                    last_updated=now,
                    projection_count=0,
                )

            self._priors[key] = prior
            with self.priors_path.open("a") as fh:
                fh.write(prior.to_json() + "\n")

            prop_entry = {
                "ts": now,
                "source": source_workload,
                "target": neighbor,
                "wicket_id": condition_id,
                "node_id": condition_id,
                "relationship": relationship,
                "adjustment": round(adjustment, 4),
                "new_prior": round(prior.prior, 4),
                "signal_weight": round(signal_weight, 4),
                "edge_weight": round(edge_weight, 4),
                "domain": domain,
                "transition_metadata": transition_metadata,
            }
            with self.prop_log_path.open("a") as fh:
                fh.write(json.dumps(prop_entry) + "\n")

            log.info(
                f"[graph] propagated {condition_id} {source_workload}→{neighbor} "
                f"via {relationship}: prior={prior.prior:.3f}"
            )

    def decay_priors(self, workload_id: str):
        """
        Increment projection_count for all priors on this workload.
        Called after each projection run.
        """
        now = datetime.now(timezone.utc).isoformat()
        updated = []

        for key, p in self._priors.items():
            if p.workload_id == workload_id:
                p.projection_count += 1
                p.last_updated = now
                updated.append(p)

        if updated:
            with self.priors_path.open("a") as fh:
                for p in updated:
                    fh.write(p.to_json() + "\n")

    def infer_edges_from_events(self, events: list[dict]):
        """
        Auto-discover relationships from sensor events.

        Looks for:
          - same AD domain
          - same subnet
        """
        by_domain: dict[str, list[str]] = {}
        by_subnet: dict[str, list[str]] = {}

        for ev in events:
            if ev.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
                continue

            payload = ev.get("payload", {})
            wid = payload.get("workload_id", "")
            domain = payload.get("domain", "")
            if not wid:
                continue

            meta = payload.get("host_meta", {})

            ad_domain = meta.get("ad_domain", "") or domain
            if ad_domain:
                by_domain.setdefault(ad_domain, [])
                if wid not in by_domain[ad_domain]:
                    by_domain[ad_domain].append(wid)

            ip = meta.get("hostname", "") or wid.split("::")[-1]
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = ".".join(parts[:3])
                by_subnet.setdefault(subnet, [])
                if wid not in by_subnet[subnet]:
                    by_subnet[subnet].append(wid)

        for ad_domain, workloads in by_domain.items():
            for i, w1 in enumerate(workloads):
                for w2 in workloads[i + 1:]:
                    self.add_edge(
                        w1,
                        w2,
                        "same_domain",
                        metadata={"ad_domain": ad_domain},
                        edge_source="auto_inference",
                    )

        for subnet, workloads in by_subnet.items():
            for i, w1 in enumerate(workloads):
                for w2 in workloads[i + 1:]:
                    self.add_edge(
                        w1,
                        w2,
                        "same_subnet",
                        metadata={"subnet": subnet},
                        edge_source="auto_inference",
                    )

    def status(self) -> dict:
        return {
            "edge_count": len(self._edges),
            "prior_count": len(self._priors),
            "workloads": len(
                set(e.source_workload for e in self._edges) |
                set(e.target_workload for e in self._edges)
            ),
        }
