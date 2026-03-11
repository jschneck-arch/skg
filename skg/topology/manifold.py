from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("skg.topology.manifold")


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return float(value)


def _id_from_payload(payload: dict) -> str:
    return payload.get("wicket_id") or payload.get("node_id", "")


@dataclass
class Edge:
    """A 1-simplex: causal or co-occurrence link between two wickets/nodes."""
    source: str
    target: str
    weight: float                    # coupling strength [0, 1]
    edge_type: str                   # "causal" | "co_realized" | "path_sequential"
    observed: int
    first_seen: str = ""
    last_seen: str = ""

    # richer optional bond metadata
    provenance_kind: str = ""        # "prior" | "empirical" | "mixed"
    mean_confidence: float = 0.0
    total_local_energy: float = 0.0
    cross_sphere: bool = False

    def key(self) -> str:
        a, b = sorted([self.source, self.target])
        return f"{a}→{b}"


@dataclass
class SimplicialComplex:
    """The full wicket/node graph as a simplicial complex."""
    vertices: set[str] = field(default_factory=set)
    edges: dict[str, Edge] = field(default_factory=dict)
    faces: list[tuple] = field(default_factory=list)  # 2-simplices

    def add_edge(self,
                 source: str,
                 target: str,
                 weight: float,
                 edge_type: str,
                 ts: str = "",
                 provenance_kind: str = "",
                 mean_confidence: float = 0.0,
                 total_local_energy: float = 0.0,
                 cross_sphere: bool = False) -> None:
        key = f"{min(source, target)}→{max(source, target)}"
        self.vertices.add(source)
        self.vertices.add(target)

        if key in self.edges:
            e = self.edges[key]
            e.observed += 1
            e.weight = min(1.0, e.weight + 0.05)
            e.last_seen = ts or e.last_seen

            # preserve mixed provenance if both prior and empirical touch same edge
            if provenance_kind and e.provenance_kind and provenance_kind != e.provenance_kind:
                e.provenance_kind = "mixed"
            elif provenance_kind and not e.provenance_kind:
                e.provenance_kind = provenance_kind

            if mean_confidence > 0:
                if e.mean_confidence > 0:
                    e.mean_confidence = round((e.mean_confidence + mean_confidence) / 2.0, 6)
                else:
                    e.mean_confidence = round(mean_confidence, 6)

            e.total_local_energy = round(e.total_local_energy + total_local_energy, 6)
            e.cross_sphere = e.cross_sphere or cross_sphere
        else:
            self.edges[key] = Edge(
                source=source,
                target=target,
                weight=_clamp01(weight),
                edge_type=edge_type,
                observed=1,
                first_seen=ts,
                last_seen=ts,
                provenance_kind=provenance_kind,
                mean_confidence=round(mean_confidence, 6) if mean_confidence else 0.0,
                total_local_energy=round(total_local_energy, 6),
                cross_sphere=cross_sphere,
            )

    def detect_faces(self) -> None:
        """Find triangles (2-simplices) in the edge graph."""
        verts = list(self.vertices)
        adj = defaultdict(set)
        for e in self.edges.values():
            adj[e.source].add(e.target)
            adj[e.target].add(e.source)

        faces = []
        verts_sorted = sorted(verts)
        for a in verts_sorted:
            for b in sorted(adj[a]):
                if b <= a:
                    continue
                for c in sorted(adj[a] & adj[b]):
                    if c <= b:
                        continue
                    faces.append((a, b, c))
        self.faces = faces

    def betti_0(self) -> int:
        """β₀: number of connected components."""
        if not self.vertices:
            return 0
        adj = defaultdict(set)
        for e in self.edges.values():
            adj[e.source].add(e.target)
            adj[e.target].add(e.source)

        visited = set()
        components = 0
        for v in self.vertices:
            if v not in visited:
                components += 1
                stack = [v]
                while stack:
                    node = stack.pop()
                    if node in visited:
                        continue
                    visited.add(node)
                    stack.extend(adj[node] - visited)
        return components

    def betti_1(self) -> int:
        """β₁: number of independent cycles. β₁ = |E| - |V| + β₀"""
        V = len(self.vertices)
        E = len(self.edges)
        b0 = self.betti_0()
        return max(0, E - V + b0)

    def summary(self) -> dict:
        self.detect_faces()
        edge_types = defaultdict(int)
        for e in self.edges.values():
            edge_types[e.edge_type] += 1

        return {
            "vertices": len(self.vertices),
            "edges": len(self.edges),
            "faces": len(self.faces),
            "beta_0": self.betti_0(),
            "beta_1": self.betti_1(),
            "edge_types": dict(edge_types),
        }


# ---------------------------------------------------------------------------
# Known causal structure — seeded from attack path definitions
# These are structural priors, not learned from data
# ---------------------------------------------------------------------------

CAUSAL_EDGES = [
    ("HO-15", "CE-01", 0.85, "causal"),
    ("HO-15", "CE-03", 0.90, "causal"),
    ("HO-15", "CE-14", 0.75, "causal"),

    ("HO-01", "HO-02", 0.95, "path_sequential"),
    ("HO-02", "HO-03", 0.90, "path_sequential"),
    ("HO-03", "HO-08", 0.60, "causal"),
    ("HO-03", "HO-09", 0.65, "causal"),
    ("HO-03", "HO-13", 0.70, "causal"),
    ("HO-03", "HO-15", 0.75, "causal"),

    ("CE-01", "CE-03", 0.80, "causal"),
    ("CE-03", "CE-14", 0.70, "causal"),

    ("HO-13", "HO-03", 0.55, "causal"),
]


def build_from_causal() -> SimplicialComplex:
    """Build the complex from known causal structure."""
    from skg.topology.energy import _sphere_for_wicket

    sc = SimplicialComplex()
    now = datetime.now(timezone.utc).isoformat()

    for src, tgt, weight, etype in CAUSAL_EDGES:
        cross_sphere = _sphere_for_wicket(src) != _sphere_for_wicket(tgt)
        sc.add_edge(
            src,
            tgt,
            weight,
            etype,
            ts=now,
            provenance_kind="prior",
            mean_confidence=0.0,
            total_local_energy=0.0,
            cross_sphere=cross_sphere,
        )
    return sc


def enrich_from_events(sc: SimplicialComplex,
                       events_dir: Path,
                       n_files: int = 10) -> SimplicialComplex:
    """
    Enrich the complex with empirically observed co-realizations.

    Two wickets/nodes that realize in the same sweep get a co_realized edge.
    Confidence and local_energy are incorporated when present.
    """
    from skg.topology.energy import _sphere_for_wicket

    files = sorted(events_dir.glob("*.ndjson"))[-n_files:]

    for f in files:
        realized_in_sweep: list[tuple[str, float, float]] = []

        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            if ev.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
                continue

            p = ev.get("payload", {})
            prov = ev.get("provenance", {})
            evidence = prov.get("evidence", {})

            node_id = _id_from_payload(p)
            if not node_id:
                continue

            if p.get("status") != "realized":
                continue

            try:
                confidence = float(evidence.get("confidence", 0.5))
            except Exception:
                confidence = 0.5

            try:
                local_energy = float(evidence.get("local_energy", 0.0) or 0.0)
            except Exception:
                local_energy = 0.0

            realized_in_sweep.append((node_id, confidence, local_energy))

        ts = datetime.now(timezone.utc).isoformat()

        # Add co_realized edges for all pairs
        for i, (a, conf_a, energy_a) in enumerate(realized_in_sweep):
            for b, conf_b, energy_b in realized_in_sweep[i + 1:]:
                if a == b:
                    continue

                mean_conf = (conf_a + conf_b) / 2.0
                total_energy = energy_a + energy_b
                cross_sphere = _sphere_for_wicket(a) != _sphere_for_wicket(b)

                # empirical weight starts moderate, slightly informed by confidence
                empirical_weight = min(1.0, 0.35 + 0.30 * mean_conf)

                sc.add_edge(
                    a,
                    b,
                    empirical_weight,
                    "co_realized",
                    ts=ts,
                    provenance_kind="empirical",
                    mean_confidence=mean_conf,
                    total_local_energy=total_energy,
                    cross_sphere=cross_sphere,
                )

    return sc


def build_full_complex(events_dir: Path) -> SimplicialComplex:
    """Build the full simplicial complex from causal priors + empirical data."""
    sc = build_from_causal()
    sc = enrich_from_events(sc, events_dir)
    return sc


def sphere_coupling_matrix(sc: SimplicialComplex) -> dict[str, dict[str, float]]:
    """
    Derive the inter-sphere coupling matrix from cross-sphere edges.
    C[sphere_a][sphere_b] = mean weight of edges crossing that boundary.
    """
    from skg.topology.energy import _sphere_for_wicket

    coupling: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for e in sc.edges.values():
        sa = _sphere_for_wicket(e.source)
        sb = _sphere_for_wicket(e.target)
        if sa != sb:
            coupling[sa][sb] += e.weight
            coupling[sb][sa] += e.weight
            counts[sa][sb] += 1
            counts[sb][sa] += 1

    result = {}
    for sa in coupling:
        result[sa] = {}
        for sb in coupling[sa]:
            result[sa][sb] = round(coupling[sa][sb] / counts[sa][sb], 4)

    return result
