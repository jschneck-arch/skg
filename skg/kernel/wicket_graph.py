"""
skg.kernel.wicket_graph
=======================
Wicket knowledge graph with Kuramoto phase dynamics.

The wicket graph is a lightweight operational substrate — no pearls, no history.
It maps the *semantic space* of security knowledge, not the network topology.
Same physics as the main field, applied one level deeper: to the wicket space itself.

Architecture
------------
Wickets → oscillators with phase θ ∈ [0, 2π]
Edges   → Kuramoto coupling constants K
Phase encodes epistemic state:
    unknown  : π/2   (maximum uncertainty, midpoint)
    realized : 0.0   (synchronized, collapsed to confirmed)
    blocked  : π     (anti-phase, collapsed to denied)

When a wicket collapses in the main SKG, the graph runs Kuramoto steps.
The resulting phase gradient IS the gravity signal: |torque_i| tells the
main engine where information pressure is highest across the knowledge space.

Entanglement
------------
Two wickets are entangled when K_ij ≥ K_ENTANGLE. They are non-separable:
you cannot measure one without driving the other toward its phase.
Physically: realizing HO-04 (WinRM exposed) immediately torques HO-05
(valid credential) — they cannot exist in independent epistemic states
when K is above threshold.

K-Topology
----------
The coupling matrix K defines a weighted directed graph.
Communities at K ≥ K_SYNC are attack path families — wickets that
synchronize together into a confirmed chain. The order parameter R
per community is the fraction of each attack family confirmed.

Domain Expansion
----------------
When the wicket graph's phase gradient shows high torque on wickets
outside the current target's domain scope, those domains are signalled
for expansion. This is how port 5985 (WinRM) on Win2022 correctly pulls
in the 'host' domain — HO-04 lives in 'host', and its high torque tells
the gravity engine to look there.
"""
from __future__ import annotations

import json
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("skg.kernel.wicket_graph")

# ── Phase encoding ────────────────────────────────────────────────────────────
PHASE = {
    "realized": 0.0,
    "unknown":  math.pi / 2,
    "blocked":  math.pi,
}
PHASE_INV = {v: k for k, v in PHASE.items()}

# ── Coupling constants by edge type ───────────────────────────────────────────
K_BY_TYPE: Dict[str, float] = {
    "requires":   0.90,  # attack path hard dependency — strongest pull
    "enables":    0.70,  # realization of A makes B highly likely
    "co_occurs":  0.50,  # observed together in engagement history
    "excludes":  -0.40,  # anti-correlated — realizing A suggests B blocked
}

# ── Threshold constants ───────────────────────────────────────────────────────
K_ENTANGLE  = 0.80   # above this: non-separable (entangled) pair
K_SYNC      = 0.60   # above this: wickets synchronize into clusters
TORQUE_SIGNAL = 0.25  # minimum torque to be a meaningful gravity signal

# ── Natural frequency by decay_class ─────────────────────────────────────────
OMEGA_BY_DECAY: Dict[str, float] = {
    "ephemeral":   0.80,  # fast-changing: services, reachability
    "operational": 0.40,  # stable: credentials, configs
    "structural":  0.15,  # very stable: domain membership, OS type
}
OMEGA_DEFAULT = 0.50

# ── Kuramoto integration ──────────────────────────────────────────────────────
DT_DEFAULT = 0.05
STEPS_COLLAPSE = 10   # steps to run after a collapse event


# ── Core data structures ──────────────────────────────────────────────────────

@dataclass
class WicketNode:
    wicket_id:   str
    phase:       float        # current θ ∈ [0, 2π]
    omega:       float        # natural frequency ω
    domain:      str          # host | web | ad_lateral | container | ...
    decay_class: str          # ephemeral | operational | structural
    label:       str = ""
    amplitude:   float = 1.0  # confidence-derived weight A ∈ [0, 1]

    @property
    def phasor(self) -> complex:
        return self.amplitude * complex(math.cos(self.phase), math.sin(self.phase))

    @property
    def state(self) -> str:
        """Nearest named state for this phase."""
        dist = {s: abs(self.phase - p) for s, p in PHASE.items()}
        return min(dist, key=dist.get)


@dataclass
class WicketEdge:
    from_id:    str
    to_id:      str
    coupling_K: float         # Kuramoto K for this edge
    edge_type:  str           # requires | enables | co_occurs | excludes
    directed:   bool = True   # undirected edges are stored both ways internally


# ── Main graph ────────────────────────────────────────────────────────────────

class WicketGraph:
    """
    Wicket knowledge graph with Kuramoto phase dynamics.

    Lifecycle:
        graph = WicketGraph()
        graph.seed_from_catalogs(catalog_paths)
        graph.seed_from_exploit_map(EXPLOIT_MAP)
        graph.sync_phases(states)       ← call each gravity cycle
        graph.collapse("HO-04", "realized")
        boosts = graph.gravity_boosts() ← inject into main field
        topology = graph.topology_report()
    """

    def __init__(self):
        self._nodes: Dict[str, WicketNode] = {}
        self._adj:   Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        self._edges: List[WicketEdge] = []
        self._seeded = False

    # ── Seeding ───────────────────────────────────────────────────────────────

    def seed_from_catalogs(self, catalog_paths: List[Path]) -> int:
        """
        Build nodes from attack_preconditions_catalog.*.json files.
        Returns count of nodes added.
        """
        added = 0
        for path in catalog_paths:
            try:
                data = json.loads(path.read_text())
                wickets = data.get("wickets", {})
                for wid, w in wickets.items():
                    if wid not in self._nodes:
                        decay = w.get("decay_class", "operational")
                        domain = _domain_from_wicket_id(wid)
                        self._nodes[wid] = WicketNode(
                            wicket_id=wid,
                            phase=PHASE["unknown"],
                            omega=OMEGA_BY_DECAY.get(decay, OMEGA_DEFAULT),
                            domain=domain,
                            decay_class=decay,
                            label=w.get("label", ""),
                        )
                        added += 1
            except Exception as exc:
                log.debug(f"[wicket_graph] catalog {path}: {exc}")
        log.info(f"[wicket_graph] seeded {added} nodes from {len(catalog_paths)} catalogs")
        return added

    def seed_from_exploit_map(self, exploit_map: Dict) -> int:
        """
        Build edges from EXPLOIT_MAP attack path structure.

        For each path's requires[]:
          - Consecutive pairs (i→i+1) → 'enables' edge (K=0.70)
          - All pairs                  → 'co_occurs' edge (K=0.50)
        Returns count of edges added.
        """
        added = 0
        for path_id, candidates in exploit_map.items():
            for candidate in candidates:
                requires = candidate.get("requires", [])
                if len(requires) < 2:
                    continue

                # Ensure all nodes exist (may not be in catalogs)
                for wid in requires:
                    if wid not in self._nodes:
                        self._nodes[wid] = WicketNode(
                            wicket_id=wid,
                            phase=PHASE["unknown"],
                            omega=OMEGA_DEFAULT,
                            domain=_domain_from_wicket_id(wid),
                            decay_class="operational",
                        )

                # Consecutive pairs → enables edges
                for i in range(len(requires) - 1):
                    if self._add_edge(requires[i], requires[i + 1],
                                      "enables", K_BY_TYPE["enables"]):
                        added += 1

                # All pairs → co_occurs edges (don't override stronger edges)
                for i in range(len(requires)):
                    for j in range(i + 1, len(requires)):
                        a, b = requires[i], requires[j]
                        existing_K = self._edge_K(a, b)
                        if existing_K < K_BY_TYPE["co_occurs"]:
                            if self._add_edge(a, b, "co_occurs",
                                              K_BY_TYPE["co_occurs"],
                                              directed=False):
                                added += 1

        log.info(f"[wicket_graph] seeded {added} edges from exploit map "
                 f"({len(self._nodes)} total nodes)")
        self._seeded = True
        return added

    def register_instruments(self, instruments: Dict[str, List[str]]) -> None:
        """
        Register instrument wavelengths as observed_by metadata on nodes.
        instruments: {instrument_name: [wicket_id_or_glob, ...]}

        Glob patterns (HO-*, WB-*) are expanded against known nodes.
        This is what closes the loop: the graph now knows which instruments
        can confirm which wickets, enabling hypothesis generation.
        """
        import fnmatch
        self._observed_by: Dict[str, List[str]] = {}   # wicket_id → [instrument_names]

        for inst_name, wavelength in instruments.items():
            for pattern in wavelength:
                if "*" in pattern or "?" in pattern:
                    matches = [wid for wid in self._nodes
                               if fnmatch.fnmatch(wid, pattern)]
                else:
                    matches = [pattern] if pattern in self._nodes else []
                for wid in matches:
                    self._observed_by.setdefault(wid, []).append(inst_name)

    def hypotheses(
        self,
        available_instruments: Optional[Set[str]] = None,
        min_torque: float = TORQUE_SIGNAL,
    ) -> List[Dict]:
        """
        Generate hypothesis entries for all high-torque unknown wickets.

        Each hypothesis is one of:
          confirmed_path  — instrument exists and is available → dispatch it
          dark            — no instrument can observe this wicket → hypothesis fold

        Returns list of dicts ordered by torque descending:
          {wicket_id, torque, domain, state, instruments, is_dark, label}

        This is SKG's true ability: the physics generates predictions about
        what should exist; the graph classifies each as observable or dark.
        Dark hypotheses become folds — the system knows it's blind here.
        """
        observed_by = getattr(self, "_observed_by", {})
        gradient    = self.phase_gradient()
        available   = available_instruments or set()

        results = []
        for wid, torque in sorted(gradient.items(), key=lambda x: -x[1]):
            if torque < min_torque:
                break
            node = self._nodes.get(wid)
            if not node:
                continue

            capable = observed_by.get(wid, [])
            reachable = [i for i in capable if i in available] if available else capable
            is_dark = len(reachable) == 0

            results.append({
                "wicket_id":   wid,
                "torque":      round(torque, 4),
                "domain":      node.domain,
                "state":       node.state,
                "label":       node.label,
                "instruments": reachable,
                "all_capable": capable,
                "is_dark":     is_dark,
            })

        return results

    def instrument_boosts(
        self,
        available_instruments: Set[str],
        min_torque: float = TORQUE_SIGNAL,
    ) -> Dict[str, float]:
        """
        Return {instrument_name: boost} for instruments that can observe
        high-torque wickets. Boost magnitude = sum of torques for wickets
        that instrument can cover.

        Used by the gravity cycle to directly elevate instrument potential
        for confirmed hypotheses — not just add to target E.
        """
        observed_by = getattr(self, "_observed_by", {})
        gradient    = self.phase_gradient()
        boosts: Dict[str, float] = {}

        for wid, torque in gradient.items():
            if torque < min_torque:
                continue
            for inst in observed_by.get(wid, []):
                if inst in available_instruments:
                    boosts[inst] = boosts.get(inst, 0.0) + torque

        return boosts

    def add_semantic_edges(self) -> int:
        """
        Add well-known semantic edges not derivable from attack path structure.
        These encode security domain knowledge as coupling constants.
        """
        KNOWN_EDGES = [
            # WinRM chain
            ("HO-04", "HO-05", "enables",   0.85),  # WinRM exposed → cred likely
            ("HO-05", "HO-10", "enables",   0.80),  # valid cred → admin
            ("HO-05", "HO-19", "enables",   0.70),  # valid cred → SMB accessible
            ("HO-10", "HO-23", "co_occurs", 0.65),  # admin → AV absent or bypassable
            # SSH chain
            ("HO-02", "HO-03", "enables",   0.75),  # SSH exposed → cred possible
            ("HO-03", "HO-06", "co_occurs", 0.55),  # SSH cred → sudo check
            ("HO-03", "HO-07", "co_occurs", 0.50),  # SSH cred → SUID scan
            # Lateral
            ("HO-10", "HO-22", "enables",   0.60),  # admin → password reuse
            ("HO-19", "HO-22", "co_occurs", 0.55),  # SMB open → reuse likely
            ("HO-05", "HO-24", "co_occurs", 0.45),  # WinRM cred → domain join possible
            # Pass-the-hash chain
            ("HO-10", "HO-18", "enables",   0.85),  # admin → hash harvestable
            ("HO-18", "HO-22", "enables",   0.90),  # hash → reuse
            # Web chain
            ("WB-01", "WB-05", "enables",   0.65),  # service reachable → paths exposed
            ("WB-09", "WB-10", "enables",   0.80),  # SQLi → OS command exec possible
            ("WB-14", "WB-10", "enables",   0.75),  # CMDI → OS exec
            # Container
            ("CE-01", "CE-02", "co_occurs", 0.55),  # code exec → privileged check
            ("CE-03", "CE-01", "enables",   0.80),  # socket present → exec possible
        ]
        added = 0
        for from_id, to_id, etype, K in KNOWN_EDGES:
            for wid in (from_id, to_id):
                if wid not in self._nodes:
                    self._nodes[wid] = WicketNode(
                        wicket_id=wid,
                        phase=PHASE["unknown"],
                        omega=OMEGA_DEFAULT,
                        domain=_domain_from_wicket_id(wid),
                        decay_class="operational",
                    )
            if self._add_edge(from_id, to_id, etype, K):
                added += 1
        log.info(f"[wicket_graph] added {added} semantic edges")
        return added

    # ── Phase synchronization with main SKG ───────────────────────────────────

    def sync_phases(self, states: Dict[str, dict]) -> None:
        """
        Update node phases from current SKG wicket states.
        Called at the start of each gravity cycle.

        states: {wicket_id: {"status": str, "phi_r": float, ...}}
        """
        for wid, node in self._nodes.items():
            state = states.get(wid, {})
            status = state.get("status", "unknown")
            if status in PHASE:
                node.phase = PHASE[status]
                # Modulate amplitude by confidence
                phi_r = float(state.get("phi_r", 0.0) or 0.0)
                phi_b = float(state.get("phi_b", 0.0) or 0.0)
                node.amplitude = max(0.1, min(1.0, phi_r + phi_b + 0.4))

    def collapse(self, wicket_id: str, state: str,
                 steps: int = STEPS_COLLAPSE) -> Dict[str, float]:
        """
        Apply a collapse event: set phase for wicket_id, run Kuramoto steps,
        return {wicket_id: delta_theta} for all wickets that shifted significantly.

        This is the primary integration point with the main SKG:
            delta_map = graph.collapse("HO-04", "realized")
            # delta_map[wid] = magnitude of phase change
            # High values → gravity boost signal
        """
        node = self._nodes.get(wicket_id)
        if not node:
            return {}

        phases_before = {wid: n.phase for wid, n in self._nodes.items()}
        node.phase = PHASE.get(state, PHASE["unknown"])
        node.amplitude = 1.0  # full confidence on collapse event

        self._run_steps(steps)

        delta = {}
        for wid, n in self._nodes.items():
            if wid == wicket_id:
                continue
            if n.phase == PHASE["realized"]:
                continue  # already realized, no signal
            d = abs(n.phase - phases_before[wid])
            if d > 0.01:
                delta[wid] = round(d, 4)

        return delta

    # ── Dynamics ──────────────────────────────────────────────────────────────

    def _run_steps(self, steps: int, dt: float = DT_DEFAULT) -> None:
        """Run Kuramoto integration for N steps."""
        nodes = list(self._nodes.values())
        n = len(nodes)
        if n == 0:
            return

        for _ in range(steps):
            dphi: Dict[str, float] = {}
            for node in nodes:
                neighbors = self._adj.get(node.wicket_id, [])
                coupling = 0.0
                for nb_id, K in neighbors:
                    nb = self._nodes.get(nb_id)
                    if nb:
                        coupling += K * nb.amplitude * math.sin(nb.phase - node.phase)
                dphi[node.wicket_id] = (
                    node.omega + (1.0 / max(n, 1)) * coupling
                )
            for node in nodes:
                node.phase = (node.phase + dphi[node.wicket_id] * dt) % (2 * math.pi)

    # ── Order parameter ───────────────────────────────────────────────────────

    def order_parameter(self) -> float:
        """
        Global Kuramoto order parameter R = |Σ A·exp(iθ)| / Σ A.
        R=0 → maximally incoherent (full darkness).
        R=1 → fully synchronized (everything known).
        """
        nodes = list(self._nodes.values())
        if not nodes:
            return 0.0
        total_amp = sum(n.amplitude for n in nodes)
        if total_amp == 0:
            return 0.0
        phasor_sum = sum(n.phasor for n in nodes)
        return abs(phasor_sum) / total_amp

    def cluster_order_parameters(
        self, min_K: float = K_SYNC
    ) -> Dict[str, Dict]:
        """
        R per synchronization cluster (attack path family).

        Returns {cluster_label: {"R": float, "wickets": [...], "realized": int}}
        """
        clusters = self._synchronization_clusters(min_K)
        result = {}
        for label, members in clusters.items():
            nodes = [self._nodes[wid] for wid in members if wid in self._nodes]
            if not nodes:
                continue
            total_amp = sum(n.amplitude for n in nodes)
            phasor_sum = sum(n.phasor for n in nodes)
            R = abs(phasor_sum) / total_amp if total_amp else 0.0
            realized = sum(1 for n in nodes if abs(n.phase) < 0.3)
            result[label] = {
                "R":        round(R, 4),
                "size":     len(members),
                "realized": realized,
                "wickets":  sorted(members),
            }
        return result

    # ── Phase gradient — the gravity signal ───────────────────────────────────

    def phase_gradient(self) -> Dict[str, float]:
        """
        Torque magnitude for each unknown wicket.

        torque_i = |Σⱼ K_ij · sin(θⱼ − θᵢ)|

        High torque = neighbors are pulling hard = gravity should send
        an instrument here next. This is the bridge from the wicket graph
        to the main field's instrument selection.
        """
        gradient: Dict[str, float] = {}
        for node in self._nodes.values():
            if node.phase == PHASE["realized"] or node.phase == PHASE["blocked"]:
                continue
            neighbors = self._adj.get(node.wicket_id, [])
            torque = sum(
                K * (self._nodes[nb_id].amplitude if nb_id in self._nodes else 1.0)
                * math.sin(
                    (self._nodes[nb_id].phase if nb_id in self._nodes else PHASE["unknown"])
                    - node.phase
                )
                for nb_id, K in neighbors
                if nb_id in self._nodes
            )
            gradient[node.wicket_id] = round(abs(torque), 4)
        return gradient

    def gravity_boosts(
        self,
        top_n: int = 8,
        min_torque: float = TORQUE_SIGNAL,
    ) -> Dict[str, float]:
        """
        Return {wicket_id: boost_magnitude} for the top-N unknown wickets
        with the highest torque. Inject these into the main gravity cycle
        to expand instrument selection toward high-information-pressure nodes.
        """
        gradient = self.phase_gradient()
        sorted_g = sorted(gradient.items(), key=lambda x: x[1], reverse=True)
        return {
            wid: mag
            for wid, mag in sorted_g[:top_n]
            if mag >= min_torque
        }

    def domains_signaled(
        self,
        current_domains: Set[str],
        min_torque: float = TORQUE_SIGNAL,
    ) -> Set[str]:
        """
        Return domains not in current_domains that have high-torque wickets.
        Used to expand a target's domain scope during gravity cycles.

        This is the Win2022 fix: HO-04 torque signals 'host' domain expansion
        without any hardcoded port→domain rule.
        """
        new_domains: Set[str] = set()
        for wid, torque in self.phase_gradient().items():
            if torque >= min_torque:
                node = self._nodes.get(wid)
                if node and node.domain not in current_domains:
                    new_domains.add(node.domain)
        return new_domains

    # ── Entanglement ──────────────────────────────────────────────────────────

    def entangled_pairs(
        self, K_threshold: float = K_ENTANGLE
    ) -> List[Tuple[str, str, float]]:
        """
        Return [(wid_a, wid_b, K)] for all non-separable pairs.
        Entangled wickets cannot be independently measured:
        collapsing one immediately drives the other.
        """
        seen: Set[frozenset] = set()
        pairs = []
        for edge in self._edges:
            if abs(edge.coupling_K) >= K_threshold:
                key = frozenset({edge.from_id, edge.to_id})
                if key not in seen:
                    seen.add(key)
                    pairs.append((edge.from_id, edge.to_id, edge.coupling_K))
        return sorted(pairs, key=lambda x: -x[2])

    # ── Topology report ───────────────────────────────────────────────────────

    def topology_report(self) -> Dict:
        """
        Full topology snapshot for CLI display and UI overlay.
        """
        nodes = list(self._nodes.values())
        n_realized = sum(1 for n in nodes if abs(n.phase) < 0.3)
        n_blocked  = sum(1 for n in nodes if abs(n.phase - math.pi) < 0.3)
        n_unknown  = len(nodes) - n_realized - n_blocked

        clusters = self.cluster_order_parameters()
        entangled = self.entangled_pairs()
        gradient  = self.phase_gradient()
        top_signal = sorted(gradient.items(), key=lambda x: -x[1])[:10]

        return {
            "nodes":       len(nodes),
            "edges":       len(self._edges),
            "R_global":    round(self.order_parameter(), 4),
            "n_realized":  n_realized,
            "n_blocked":   n_blocked,
            "n_unknown":   n_unknown,
            "clusters":    clusters,
            "entangled":   [
                {"a": a, "b": b, "K": round(K, 3)}
                for a, b, K in entangled
            ],
            "top_gradient": [
                {"wicket": wid, "torque": t,
                 "domain": self._nodes[wid].domain if wid in self._nodes else "?"}
                for wid, t in top_signal
            ],
        }

    def edges_for(self, wicket_id: str) -> List[Dict]:
        """Return all edges for a given wicket, for CLI inspection."""
        result = []
        for edge in self._edges:
            if edge.from_id == wicket_id or (not edge.directed and edge.to_id == wicket_id):
                nb = edge.to_id if edge.from_id == wicket_id else edge.from_id
                nb_node = self._nodes.get(nb)
                result.append({
                    "neighbor":  nb,
                    "direction": "→" if edge.from_id == wicket_id else "←",
                    "type":      edge.edge_type,
                    "K":         round(edge.coupling_K, 3),
                    "phase":     round(nb_node.phase, 3) if nb_node else None,
                    "state":     nb_node.state if nb_node else "?",
                    "domain":    nb_node.domain if nb_node else "?",
                })
        return sorted(result, key=lambda x: -abs(x["K"]))

    # ── Internals ─────────────────────────────────────────────────────────────

    def _add_edge(self, from_id: str, to_id: str,
                  edge_type: str, K: float,
                  directed: bool = True) -> bool:
        """Add edge if it doesn't already exist with equal or higher K."""
        existing = self._edge_K(from_id, to_id)
        if abs(existing) >= abs(K):
            return False
        # Remove existing weaker edge
        self._edges = [
            e for e in self._edges
            if not (e.from_id == from_id and e.to_id == to_id)
        ]
        # Add new edge
        edge = WicketEdge(from_id, to_id, K, edge_type, directed)
        self._edges.append(edge)
        # Build adjacency list entry
        self._adj[from_id] = [
            (nb, w) for nb, w in self._adj[from_id] if nb != to_id
        ]
        self._adj[from_id].append((to_id, K))
        if not directed:
            self._adj[to_id] = [
                (nb, w) for nb, w in self._adj[to_id] if nb != from_id
            ]
            self._adj[to_id].append((from_id, K))
        return True

    def _edge_K(self, from_id: str, to_id: str) -> float:
        for nb, K in self._adj.get(from_id, []):
            if nb == to_id:
                return K
        return 0.0

    def _synchronization_clusters(
        self, min_K: float = K_SYNC
    ) -> Dict[str, Set[str]]:
        """
        Connected components at K ≥ min_K using union-find.
        Each component is a synchronization cluster (attack path family).
        """
        parent = {wid: wid for wid in self._nodes}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for edge in self._edges:
            if abs(edge.coupling_K) >= min_K:
                if edge.from_id in parent and edge.to_id in parent:
                    union(edge.from_id, edge.to_id)

        clusters: Dict[str, Set[str]] = defaultdict(set)
        for wid in self._nodes:
            root = find(wid)
            clusters[root].add(wid)

        return {
            root: members
            for root, members in clusters.items()
            if len(members) >= 2
        }


# ── Domain inference from wicket ID prefix ────────────────────────────────────

_PREFIX_DOMAIN: Dict[str, str] = {
    "HO-": "host",
    "WB-": "web",
    "AD-": "ad_lateral",
    "CE-": "container_escape",
    "DA-": "data_pipeline",
    "BA-": "binary_analysis",
    "SC-": "supply_chain",
    "IO-": "iot_firmware",
    "AI-": "ai_target",
    "AP-": "aprs",
}

def _domain_from_wicket_id(wid: str) -> str:
    for prefix, domain in _PREFIX_DOMAIN.items():
        if wid.startswith(prefix):
            return domain
    return "unknown"


# ── Module-level singleton ────────────────────────────────────────────────────

_GRAPH: Optional[WicketGraph] = None
_GRAPH_BUILT_AT: float = 0.0
_GRAPH_TTL_S = 3600.0  # rebuild from catalogs at most once per hour


def get_wicket_graph(
    catalog_paths: Optional[List[Path]] = None,
    exploit_map: Optional[Dict] = None,
    force_rebuild: bool = False,
) -> WicketGraph:
    """
    Return the module-level singleton WicketGraph, building it if needed.
    The topology (nodes, edges, K values) is rebuilt from catalogs on first
    call or after TTL expiry. Node phases are NOT cached here — the caller
    must call graph.sync_phases(states) each gravity cycle.
    """
    global _GRAPH, _GRAPH_BUILT_AT

    age = time.monotonic() - _GRAPH_BUILT_AT
    if _GRAPH is not None and not force_rebuild and age < _GRAPH_TTL_S:
        return _GRAPH

    graph = WicketGraph()

    # Seed from catalogs
    if catalog_paths is None:
        from skg.core.paths import SKG_HOME
        catalog_paths = sorted(
            SKG_HOME.rglob("attack_preconditions_catalog.*.json")
        )
    if catalog_paths:
        graph.seed_from_catalogs(catalog_paths)

    # Seed from exploit map
    if exploit_map is None:
        try:
            import sys
            skg_gravity = str(Path(__file__).resolve().parents[2] / "skg-gravity")
            if skg_gravity not in sys.path:
                sys.path.insert(0, skg_gravity)
            from exploit_dispatch import EXPLOIT_MAP
            exploit_map = EXPLOIT_MAP
        except Exception:
            exploit_map = {}
    if exploit_map:
        graph.seed_from_exploit_map(exploit_map)

    # Add semantic knowledge edges
    graph.add_semantic_edges()

    _GRAPH = graph
    _GRAPH_BUILT_AT = time.monotonic()
    log.info(f"[wicket_graph] graph built: {len(graph._nodes)} nodes, "
             f"{len(graph._edges)} edges")
    return graph
