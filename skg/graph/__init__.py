"""
skg.graph
=========
Cross-workload relationship model. Propagates state priors across target
relationships using a formula derived from the Kuramoto synchronisation model.

Prior propagation derivation
─────────────────────────────
The Kuramoto model for N weakly-coupled oscillators:

    dθᵢ/dt = ωᵢ + (K/N) Σⱼ sin(θⱼ - θᵢ)

In the small-angle regime |θⱼ - θᵢ| ≪ 1, sin(θⱼ - θᵢ) ≈ θⱼ - θᵢ, so:

    dθᵢ/dt ≈ ωᵢ + (K/N) Σⱼ (θⱼ - θᵢ)

Map to the SKG discrete setting:
  - Phase θᵢ → prior p(wᵢ) ∈ [0, MAX_PRIOR], the probability adjustment
    that a condition is realized on workload i
  - Coupling K/N → edge_weight × (1/|neighbours|), the structural coupling
    between two workloads
  - θⱼ - θᵢ → signal_weight, the magnitude of the realized transition on j
    (how confidently wⱼ was observed to transition U→R)
  - ωᵢ → 0 (no intrinsic drift; priors decay via DECAY_PER_PROJECTION)

The discrete update for a single propagation step from workload j to i:

    Δp(wᵢ) = edge_weight × signal_weight

This is the first-order Euler discretisation of the continuous coupling term.
It is bounded by MAX_PRIOR = 0.85 to prevent prior collapse to certainty —
the prior adjusts the gravity field's instrument selection but never
overrides live observation.

Key properties preserved from the continuous model:
  1. Coupling scales with edge strength (structural coupling K/N)
  2. Coupling scales with signal magnitude (θⱼ - θᵢ analogue)
  3. Priors decay to zero without repeated reinforcement (ωᵢ = 0)
  4. Direction: only U→R realizations propagate (positive coupling only)
     — blocked conditions do not propagate priors because the constraint
       surface is domain-specific and non-transferable

Note on the small-angle approximation:
  The sin linearisation holds when edge_weight × signal_weight ≪ 1.
  Edge weights are ≤ 1.0 and signal_weight ≤ 1.0, so Δp ≤ 1.0.
  In practice edge weights are 0.2–0.45 and signal_weight is capped at 1.0,
  giving Δp ≤ 0.45 per step — well within the linearisation regime.

The full prior after k propagation steps accumulates as:

    p(wᵢ, k) = min(MAX_PRIOR, Σₖ edge_weight × signal_weightₖ)

Priors decay by DECAY_PER_PROJECTION per projection cycle on the target
workload, modelling the loss of synchronisation when no new reinforcing
signal arrives. This corresponds to the ωᵢ = 0 case returning to the
unsynchronised state after the forcing term stops.

Boundary:
  The graph does NOT change node/wicket truth directly.
  It adjusts priors for the next observation cycle on neighbouring workloads.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from skg.identity import parse_workload_ref

log = logging.getLogger("skg.graph")

# Propagation weights by relationship type
PROPAGATION_WEIGHT = {
    "same_identity":       0.85,
    "same_domain":         0.35,
    "credential_overlap":  0.45,
    "same_subnet":         0.20,
    "network_adjacent":    0.15,
    "trust_relationship":  0.25,
}

# Which domains/condition patterns propagate across which relationship types
PROPAGATION_SCOPE = {
    "same_identity":      {"domains": ["host", "web", "container_escape", "data", "data_pipeline", "ad_lateral", "supply_chain", "binary", "ai_target", "iot_firmware"], "prefix": ["HO-", "WB-", "CE-", "DP-", "AD-", "SC-", "BA-", "AI-", "IF-"]},
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


def _identity_key(workload_id: str) -> str:
    return parse_workload_ref(workload_id).get("identity_key", workload_id)


def _same_identity(left: str, right: str) -> bool:
    return bool(left and right and _identity_key(left) == _identity_key(right))


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

        if relationship in (None, "same_identity"):
            for candidate in self._workload_index().keys():
                if candidate == workload_id:
                    continue
                if not _same_identity(candidate, workload_id):
                    continue
                key = (candidate, "same_identity")
                if key not in seen:
                    results.append((candidate, "same_identity", PROPAGATION_WEIGHT["same_identity"]))
                    seen.add(key)

        for edge in self._edges:
            rel = edge.relationship
            if relationship and rel != relationship:
                continue

            w = edge.weight
            if edge.source_workload == workload_id or _same_identity(edge.source_workload, workload_id):
                key = (edge.target_workload, rel)
                if key not in seen:
                    results.append((edge.target_workload, rel, w))
                    seen.add(key)
            elif edge.target_workload == workload_id or _same_identity(edge.target_workload, workload_id):
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
            candidates = [
                prior for prior in self._priors.values()
                if prior.wicket_id == condition_id and _same_identity(prior.workload_id, workload_id)
            ]
            if not candidates:
                return 0.0
            p = max(candidates, key=lambda prior: prior.prior)

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

    # Cross-domain intra-target coupling map.
    # When domain A achieves a significant realization on a target,
    # it elevates priors for domain B on the SAME target by this weight.
    # The intuition: a realized web attack on a host makes host privesc
    # more likely (attacker already has a foothold); a realized container
    # escape makes AD lateral movement more likely (escaped to domain host).
    # These are same-target relationships, not cross-target bond propagation.
    INTRA_TARGET_COUPLING = {
        # (source_domain, target_domain): coupling_weight
        ("web",               "data_pipeline"):    0.65,
        ("web",               "host"):             0.60,
        ("web",               "container_escape"): 0.50,
        ("host",              "web"):              0.45,
        ("host",              "container_escape"): 0.70,
        ("host",              "ad_lateral"):        0.55,
        ("host",              "data_pipeline"):    0.40,
        ("container_escape",  "host"):              0.75,
        ("container_escape",  "web"):               0.45,
        ("container_escape",  "ad_lateral"):        0.65,
        ("ad_lateral",        "host"):              0.60,
        ("aprs",              "host"):              0.70,
        ("aprs",              "container_escape"): 0.50,
        ("binary_analysis",   "host"):              0.55,
        ("sysaudit",          "host"):              0.50,
        ("data_pipeline",     "host"):              0.30,
        ("data_pipeline",     "web"):               0.55,
    }

    # Which wickets carry the cross-domain signal
    # When these are realized in source domain, trigger intra-target coupling
    INTRA_TARGET_TRIGGER_WICKETS = {
        "web":              {"WB-01", "WB-02", "WB-09", "WB-10", "WB-21", "WB-22"},  # surface + exploit + webshell
        "host":             {"HO-03", "HO-10", "HO-06", "HO-07"},  # cred, root, sudo, suid
        "container_escape": {"CE-01", "CE-09", "CE-14"},           # code_exec, host_fs, escape
        "ad_lateral":       {"AD-01", "AD-14", "AD-15"},           # domain_user, dcsync, da
        "aprs":             {"AP-L7-07", "AP-L8-11"},              # rce realized
        "binary_analysis":  {"BA-05", "BA-06"},                    # exploitable
        "sysaudit":         {"FI-07", "PI-05"},                    # backdoor, rce_indicator
        "data_pipeline":    {"DP-01", "DP-02", "DP-10"},           # source reachable, source auth, live data
    }

    def propagate_intra_target(
        self,
        source_workload: str,
        source_domain: str,
        wicket_id: str,
        signal_weight: float = 1.0,
    ):
        """
        Cross-domain prior propagation within the SAME target.

        When domain A achieves a significant realization on a target,
        other domains on the same target receive elevated priors — because
        a foothold in one domain makes exploitation in adjacent domains
        more likely.

        This is distinct from propagate_transition() which handles
        cross-TARGET propagation through bond relationships.

        Calling convention: called by FeedbackIngester after any high-signal
        realization, alongside the existing propagate_transition() call.
        """
        # Only fire for trigger wickets in the source domain
        trigger_set = self.INTRA_TARGET_TRIGGER_WICKETS.get(source_domain, set())
        if wicket_id not in trigger_set:
            return

        # Extract the target IP from workload_id
        # Convention: workload_id is "domain::target_ip" or just "target_ip"
        target_ip = parse_workload_ref(source_workload).get("identity_key", source_workload)

        now = datetime.now(timezone.utc).isoformat()
        coupled = 0

        for (src_d, tgt_d), coupling_weight in self.INTRA_TARGET_COUPLING.items():
            if src_d != source_domain:
                continue

            # Find workloads for target_domain on same target
            for wl_key, priors_list in self._workload_index().items():
                # Match workloads on the same target IP in the target domain
                if not _same_identity(wl_key, source_workload):
                    continue
                if not (wl_key.startswith(tgt_d) or f"::{target_ip}" in wl_key):
                    continue
                if wl_key == source_workload:
                    continue

                # Apply coupling: boost priors for relevant wickets in target domain
                adjustment = coupling_weight * signal_weight * 0.5  # halved for intra-target
                key = f"{wl_key}::intra_target_from_{wicket_id}"
                prior_key = f"{wl_key}::__intra__{wicket_id}"

                existing = self._priors.get(prior_key)
                new_prior_val = min(MAX_PRIOR,
                                    (existing.prior if existing else 0.0) + adjustment)

                prior = WicketPrior(
                    workload_id=wl_key,
                    wicket_id=f"__intra__{wicket_id}",
                    domain=tgt_d,
                    prior=new_prior_val,
                    sources=[source_workload],
                    last_updated=now,
                    projection_count=0,
                )
                self._priors[prior_key] = prior

                log.info(
                    f"[graph] intra-target coupling {source_domain}→{tgt_d} "
                    f"on {target_ip} via {wicket_id}: "
                    f"prior boost +{adjustment:.3f}"
                )
                coupled += 1

        return coupled

    def _workload_index(self) -> dict:
        """Return current known workload IDs from priors and edges."""
        wids: set[str] = set()
        # Get full workload_id from the WicketPrior objects themselves,
        # not from the key (which is workload_id::condition_id and splits wrong
        # when workload_id contains "::" like "web::172.17.0.2")
        for prior in self._priors.values():
            wids.add(prior.workload_id)
        for edge in self._edges:          # _edges is a list[WorkloadEdge]
            wids.add(edge.source_workload)
            wids.add(edge.target_workload)
        return {wid: [] for wid in wids}

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

    def clear_prior(self, workload_id: str, condition_id: str):
        """
        Zero the prior for a specific condition on a workload.
        Called when a node transitions to R or B — gravity should not
        continue pulling toward already-resolved nodes.
        """
        key = f"{workload_id}::{condition_id}"
        if key not in self._priors:
            return
        now = datetime.now(timezone.utc).isoformat()
        p = self._priors[key]
        p.prior = 0.0
        p.last_updated = now
        with self.priors_path.open("a") as fh:
            fh.write(p.to_json() + "\n")
        log.debug(f"[graph] cleared prior {condition_id} on {workload_id}")

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
