"""
skg.topology.sheaf
==================
Sheaf structure and H¹ obstruction detection for attack-path realizability.

From Work3 Section 4:
  An attack path P ⊆ N defines an open cover of the node set.
  Global realizability — π(S, P) = ⊤ — corresponds to the existence
  of a global section σ : P → {R}.

  The cohomological obstruction H¹(X; F) measures irreducible indeterminacy.
  When H¹ is non-trivial, local realizations exist but cannot be consistently
  assembled into a global section.

  Operationally: mutually conditional preconditions.
  Example: privilege escalation requires credential access,
           credential access requires privilege escalation.
           This forms a cycle in the dependency graph.
           The cycle is an H¹ obstruction — not a measurement gap,
           not a blocked condition, but a structural impossibility
           given the current constraint surface.

This module detects H¹ obstructions from:
  1. Catalog-declared conditional dependencies between wickets
  2. Live constraint patterns observed in blocked/realized state

Two classifications for indeterminate paths:
  indeterminate          — unknowns exist but no obstruction detected
  indeterminate_h1       — cycle detected; obstruction is structural,
                           not resolvable by further observation alone
                           (constraint must change, not just measurement)

The distinction matters operationally:
  indeterminate:     more observation will likely resolve it
  indeterminate_h1:  the path is stuck regardless of measurement coverage;
                     the constraint surface must be altered
                     (e.g., a privilege boundary must be removed,
                      a configuration must change, a new vector found)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any


def detect_cycles(dependency_graph: dict[str, list[str]]) -> list[list[str]]:
    """
    Detect cycles in a dependency graph using DFS.
    Returns list of cycles (each cycle is a list of node IDs forming a loop).

    dependency_graph: {node_id: [nodes_it_depends_on]}
    """
    visited: set[str] = set()
    rec_stack: set[str] = set()
    cycles: list[list[str]] = []

    def dfs(node: str, path: list[str]) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in dependency_graph.get(node, []):
            if neighbor not in visited:
                dfs(neighbor, path)
            elif neighbor in rec_stack:
                # Found a cycle — extract it
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:]
                if cycle not in cycles:
                    cycles.append(list(cycle))

        path.pop()
        rec_stack.discard(node)

    for node in dependency_graph:
        if node not in visited:
            dfs(node, [])

    return cycles


def build_dependency_graph(
    catalog: dict,
    attack_path_id: str,
    realized: list[str],
    blocked: list[str],
    unknown: list[str],
) -> dict[str, list[str]]:
    """
    Build a dependency graph for the wickets in this path.

    Dependencies come from:
      1. Catalog 'dependencies' field on wickets (explicit declarations)
      2. Inferred from attack path structure (prerequisite chains)

    Currently the catalogs don't have explicit dependency declarations,
    so this uses the catalog's conditional_on field if present,
    plus a set of known structural dependencies for common wicket patterns.
    """
    graph: dict[str, list[str]] = defaultdict(list)

    wickets = catalog.get("wickets", {})
    paths   = catalog.get("attack_paths", {})
    ap      = paths.get(attack_path_id, {})
    required = ap.get("required_wickets", [])

    # Explicit dependencies declared in catalog
    for wid in required:
        w_data = wickets.get(wid, {})
        deps   = w_data.get("dependencies", [])  # explicit field
        cond   = w_data.get("conditional_on", []) # alternate field
        for dep in deps + cond:
            if dep in required:
                graph[wid].append(dep)

    # Structural dependency patterns from known domain semantics
    # These are the cases where H¹ is operationally meaningful:

    # Web: XSS to session hijack requires session to exist (WB-11 → WB-06)
    structural_deps = {
        # Web domain — post-auth conditions require auth
        "WB-07": ["WB-06"],   # no brute-force rate limit requires login form
        "WB-08": ["WB-06"],   # default credentials requires login form
        "WB-10": ["WB-09"],   # SQLi data extraction requires injectable param
        "WB-13": ["WB-06"],   # file upload requires authenticated access
        "WB-15": ["WB-06"],   # IDOR requires authenticated access
        "WB-20": ["WB-09", "WB-10"],   # DB privs require SQLi
        "WB-21": ["WB-13"],   # webshell requires file upload

        # Host domain — privesc requires initial access
        "HO-06": ["HO-03"],   # sudo misconfig requires credential
        "HO-07": ["HO-03"],   # SUID requires credential (to execute)
        "HO-08": ["HO-03"],   # writable cron requires credential
        "HO-09": ["HO-03"],   # cred in env requires credential
        "HO-10": ["HO-03"],   # root status requires credential
        "HO-13": ["HO-03"],   # SSH key access requires credential
        "HO-15": ["HO-03"],   # Docker requires credential

        # Container escape — requires initial code execution
        "CE-09": ["CE-01"],   # host filesystem access requires code exec
        "CE-10": ["CE-01"],   # network access to host requires code exec
        "CE-14": ["CE-01"],   # escape feasibility requires code exec

        # AD — domain user requires domain connectivity
        "AD-02": ["AD-01"],   # kerberoastable SPN requires domain user
        "AD-03": ["AD-01"],   # TGS request requires domain user
        "AD-04": ["AD-01"],   # AS-REP roast requires domain user
        "AD-14": ["AD-01"],   # DCSync rights requires domain user
        "AD-15": ["AD-01"],   # domain admin requires domain user
    }

    for wid, deps in structural_deps.items():
        if wid in required:
            for dep in deps:
                if dep in required:
                    graph[wid].append(dep)

    return dict(graph)


def compute_h1_obstruction(
    catalog: dict,
    attack_path_id: str,
    realized: list[str],
    blocked: list[str],
    unknown: list[str],
) -> dict:
    """
    Compute the H¹ sheaf obstruction for a path projection.

    Mathematical background:
    ──────────────────────
    Model the dependency graph on unknown wickets as a simplicial
    1-complex G = (V, E) where:
      V = unknown wickets in the required set
      E = declared and inferred dependency edges between them

    The first Betti number β₁ = dim H¹(G; ℤ) is the cycle rank:

        β₁ = |E| - |V| + |connected components(G)|

    β₁ counts independent cycles in G. Each cycle is a mutual
    dependency that prevents any observation ordering from resolving
    the indeterminacy. The obstruction is non-trivial when β₁ ≥ 1.

    Relation to sheaf cohomology:
    This uses the graph cycle rank as a computationally tractable
    lower bound on the Cech cohomology obstruction H¹(U; F) of the
    realizability sheaf F over the nerve of the open cover defined
    by the attack path. When the dependency graph is a tree (β₁ = 0)
    the approximation is exact. When cycles exist, β₁ ≥ 1 correctly
    signals structural obstruction. This is stated explicitly in the
    paper as an approximation, not a full sheaf calculation.

    Returns dict with:
      has_obstruction:  bool  (β₁ > 0)
      cycles:           list of cycles detected (for display)
      affected_wickets: wickets involved in cycles
      interpretation:   human-readable description
      h1:               β₁ = |E| - |V| + |C|
      V:                number of unknown wickets
      E:                number of undirected dependency edges
      C:                number of connected components
    """
    if blocked or not unknown:
        return {
            "has_obstruction": False, "cycles": [], "affected_wickets": [],
            "interpretation": "Path is not indeterminate — H¹ check not applicable",
            "h1": 0, "V": 0, "E": 0, "C": 0,
        }

    dep_graph = build_dependency_graph(
        catalog, attack_path_id, realized, blocked, unknown
    )

    unknown_set = set(unknown)
    unknown_graph: dict[str, list[str]] = {
        node: [d for d in deps if d in unknown_set]
        for node, deps in dep_graph.items()
        if node in unknown_set
    }
    for u in unknown_set:
        if u not in unknown_graph:
            unknown_graph[u] = []

    # β₁ = |E| - |V| + |C|
    V = len(unknown_graph)
    undirected: set[frozenset] = set()
    for node, deps in unknown_graph.items():
        for dep in deps:
            undirected.add(frozenset([node, dep]))
    E = len(undirected)

    # Connected components via union-find
    parent = {u: u for u in unknown_set}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x

    for edge in undirected:
        ns = list(edge)
        if len(ns) == 2:
            parent[find(ns[0])] = find(ns[1])

    C  = len({find(u) for u in unknown_set})
    h1 = max(0, E - V + C)

    cycles   = detect_cycles(unknown_graph)
    affected: set[str] = set()
    for cyc in cycles:
        affected.update(cyc)

    if h1 > 0:
        cycle_desc = "; ".join(" → ".join(c + [c[0]]) for c in cycles[:3])
        interpretation = (
            f"H¹ obstruction: β₁ = {h1} (|E|={E} − |V|={V} + |C|={C}). "
            f"Affected wickets: {sorted(affected)}. "
            + (f"Cycles: {cycle_desc}. " if cycles else "")
            + "Mutual dependency — the constraint surface must change, "
            "not just measurement coverage."
        )
    else:
        interpretation = (
            f"No H¹ obstruction: β₁ = {h1} (|E|={E} − |V|={V} + |C|={C}). "
            "Indeterminacy is from unmeasured conditions; further observation "
            "is expected to reduce it."
        )

    return {
        "has_obstruction":  h1 > 0,
        "cycles":           cycles,
        "affected_wickets": sorted(affected),
        "interpretation":   interpretation,
        "h1":               h1,
        "V":                V,
        "E":                E,
        "C":                C,
    }



def classify_with_sheaf(
    classification: str,
    catalog: dict,
    attack_path_id: str,
    realized: list[str],
    blocked: list[str],
    unknown: list[str],
) -> tuple[str, dict]:
    """
    Refine the projection classification using H¹ obstruction analysis.

    Returns (refined_classification, sheaf_data) where:
      refined_classification is one of:
        realized         — all conditions confirmed
        not_realized     — at least one condition blocked
        indeterminate    — unknowns but no structural obstruction
        indeterminate_h1 — unknowns AND structural cycle detected
                           (more observation won't help; constraint must change)

    sheaf_data contains the full H¹ analysis.
    """
    sheaf = compute_h1_obstruction(
        catalog, attack_path_id, realized, blocked, unknown
    )

    if classification == "indeterminate" and sheaf["has_obstruction"]:
        return "indeterminate_h1", sheaf

    return classification, sheaf
