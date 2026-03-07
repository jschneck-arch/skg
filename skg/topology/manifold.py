"""
skg.topology.manifold
=====================
Simplicial complex over the SKG wicket graph.

Vertices  = wickets (0-simplices)
Edges     = co-occurrence / causal links (1-simplices)
Faces     = closed attack triads (2-simplices)

The complex is built from two sources:
  1. Known causal structure (attack path definitions)
  2. Observed co-realization (empirical from sweep data)

Betti numbers:
  β₀ = connected components (isolated domain clusters)
  β₁ = independent cycles (circular dependencies / feedback loops)
  β₂ = enclosed voids (unreachable regions of attack surface)

The coupling matrix C[i,j] between spheres is derived from
observed cross-sphere co-realizations weighted by temporal proximity.
"""
from __future__ import annotations

import json
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("skg.topology.manifold")


@dataclass
class Edge:
    """A 1-simplex: causal or co-occurrence link between two wickets."""
    source:      str    # wicket_id
    target:      str    # wicket_id
    weight:      float  # coupling strength [0, 1]
    edge_type:   str    # "causal" | "co_realized" | "path_sequential"
    observed:    int    # number of times this edge was observed
    first_seen:  str    = ""
    last_seen:   str    = ""

    def key(self) -> str:
        a, b = sorted([self.source, self.target])
        return f"{a}→{b}"


@dataclass
class SimplicialComplex:
    """The full wicket graph as a simplicial complex."""
    vertices:  set[str]          = field(default_factory=set)
    edges:     dict[str, Edge]   = field(default_factory=dict)
    faces:     list[tuple]       = field(default_factory=list)  # 2-simplices

    def add_edge(self, source: str, target: str, weight: float,
                 edge_type: str, ts: str = "") -> None:
        key = f"{min(source,target)}→{max(source,target)}"
        self.vertices.add(source)
        self.vertices.add(target)
        if key in self.edges:
            e = self.edges[key]
            e.observed += 1
            e.weight = min(1.0, e.weight + 0.05)  # strengthen with observation
            e.last_seen = ts
        else:
            self.edges[key] = Edge(
                source=source, target=target,
                weight=weight, edge_type=edge_type,
                observed=1, first_seen=ts, last_seen=ts
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
        for i, a in enumerate(verts_sorted):
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
        return {
            "vertices":   len(self.vertices),
            "edges":      len(self.edges),
            "faces":      len(self.faces),
            "beta_0":     self.betti_0(),
            "beta_1":     self.betti_1(),
        }


# ---------------------------------------------------------------------------
# Known causal structure — seeded from attack path definitions
# These are structural priors, not learned from data
# ---------------------------------------------------------------------------

CAUSAL_EDGES = [
    # Host → Container: docker group access enables socket escape
    ("HO-15", "CE-01", 0.85, "causal"),   # docker group → container running as root
    ("HO-15", "CE-03", 0.90, "causal"),   # docker group → socket accessible
    ("HO-15", "CE-14", 0.75, "causal"),   # docker group → no userns remap relevant

    # Host path sequential dependencies
    ("HO-01", "HO-02", 0.95, "path_sequential"),  # reachable → SSH exposed
    ("HO-02", "HO-03", 0.90, "path_sequential"),  # SSH exposed → credential valid
    ("HO-03", "HO-08", 0.60, "causal"),           # auth → writable cron/service
    ("HO-03", "HO-09", 0.65, "causal"),           # auth → credential in env
    ("HO-03", "HO-13", 0.70, "causal"),           # auth → SSH keys found
    ("HO-03", "HO-15", 0.75, "causal"),           # auth → docker group membership

    # Container escape internal dependencies
    ("CE-01", "CE-03", 0.80, "causal"),   # root container → socket likely accessible
    ("CE-03", "CE-14", 0.70, "causal"),   # socket accessible → userns remap absent

    # Lateral movement seeds
    ("HO-13", "HO-03", 0.55, "causal"),  # SSH keys found → credential reuse possible
]


def build_from_causal() -> SimplicialComplex:
    """Build the complex from known causal structure."""
    sc = SimplicialComplex()
    now = datetime.now(timezone.utc).isoformat()
    for src, tgt, weight, etype in CAUSAL_EDGES:
        sc.add_edge(src, tgt, weight, etype, ts=now)
    return sc


def enrich_from_events(sc: SimplicialComplex,
                        events_dir: Path,
                        n_files: int = 10) -> SimplicialComplex:
    """
    Enrich the complex with empirically observed co-realizations.
    Two wickets that realize in the same sweep get a co_realized edge.
    """
    files = sorted(events_dir.glob("*.ndjson"))[-n_files:]

    for f in files:
        realized_in_sweep = []
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            p = ev.get("payload", {})
            if p.get("status") == "realized" and p.get("wicket_id"):
                realized_in_sweep.append(p["wicket_id"])

        ts = datetime.now(timezone.utc).isoformat()
        # Add co_realized edges for all pairs
        for i, a in enumerate(realized_in_sweep):
            for b in realized_in_sweep[i+1:]:
                if a != b:
                    sc.add_edge(a, b, 0.50, "co_realized", ts=ts)

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
    counts:   dict[str, dict[str, int]]   = defaultdict(lambda: defaultdict(int))

    for e in sc.edges.values():
        sa = _sphere_for_wicket(e.source)
        sb = _sphere_for_wicket(e.target)
        if sa != sb:
            coupling[sa][sb] += e.weight
            coupling[sb][sa] += e.weight
            counts[sa][sb]   += 1
            counts[sb][sa]   += 1

    # Normalize to mean weight
    result = {}
    for sa in coupling:
        result[sa] = {}
        for sb in coupling[sa]:
            result[sa][sb] = round(coupling[sa][sb] / counts[sa][sb], 4)

    return result
