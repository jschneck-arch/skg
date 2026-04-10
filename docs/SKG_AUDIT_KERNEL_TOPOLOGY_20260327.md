# SKG Kernel & Topology Audit
**Date:** 2026-03-27
**Scope:** `skg/kernel/` (18 modules) + `skg/topology/` (4 modules)

---

## 1. Kernel Module Overview

The kernel implements the core tri-state field substrate. It is the computational heart that converts raw NDJSON events into support vectors, collapses them to tri-state verdicts, computes energy, and directs gravity.

### Module Map

| Module | Purpose |
|--------|---------|
| `adapters.py` | NDJSON event → Observation conversion |
| `engine.py` | Unified interface (KernelStateEngine) |
| `support.py` | SupportEngine: aggregation + decay |
| `state.py` | StateEngine: collapse support → TriState |
| `energy.py` | EnergyEngine: E = unknowns + folds |
| `gravity.py` | GravityScheduler: rank proposals by score |
| `folds.py` | Fold detection and gravity weights |
| `observations.py` | Observation dataclass + ObservationStore |
| `wicket_graph.py` | WicketGraph: Kuramoto dynamics on wickets |
| `field_local.py` | FieldLocal: Paper 4 coupling and decoherence |
| `field_functional.py` | Field functional breakdown |
| `pearl_manifold.py` | PearlManifold: memory curvature |
| `pearls.py` | Pearl ledger: append-only state transitions |
| `projections.py` | ProjectionEngine: path feasibility |
| `reason.py` | ReasonTrace: why a state exists |
| `identities.py` | IdentityRegistry: entity tracking |
| `contexts.py` | ContextRegistry: wicket ID registry |
| `__init__.py` | Module exports |

---

## 2. Data Pipeline Through Kernel

```
NDJSON events (discovery/, events/)
  │
  ▼ adapters.py: event_to_observation()
  │
  ├─ Extracts: wicket_id, status, target, confidence, evidence_rank
  ├─ Computes: (φ_R, φ_B, φ_U) from status + confidence
  ├─ Assigns: decay_class from instrument + rank
  └─ Wraps: Observation(instrument, targets, context, payload, support_mapping, cycle_id)
  │
  ▼ ObservationStore (in-memory)
  │
  ▼ support.py: SupportEngine.aggregate(observations, target, context, as_of)
  │
  ├─ Filters: by target + wicket (context), drops expired (past TTL)
  ├─ Weights: w_i = exp(−λ × Δt/3600)
  ├─ Sums: φ_R = Σ w_i × phi_r_i
  ├─ Computes: contradiction = min(φ_R, φ_B)
  ├─ Computes: C = 1.0 − concentration + 0.1×(n−1)
  ├─ Computes: decoherence = decay_loss + 0.15 penalty if n≤1
  └─ Returns: SupportContribution(realized, blocked, unresolved, contradiction, decoherence, C, n)
  │
  ▼ state.py: StateEngine.collapse(support)
  │
  ├─ REALIZED: φ_R > threshold AND φ_R > φ_B
  ├─ BLOCKED:  φ_B > threshold AND φ_B ≥ φ_R
  └─ UNKNOWN:  otherwise
  │
  ▼ energy.py: EnergyEngine.compute_weighted()
  │
  ├─ Per unknown wicket: max(φ_U, local_energy, 1.0) + contradiction + decoherence
  └─ Plus: Σ Φ(fold)
  │
  ▼ gravity.py: GravityScheduler.rank(proposals)
  │
  └─ score = (ΔE / cost) × penalty × approval_factor
```

---

## 3. `adapters.py` — NDJSON → Observation

### Decay Class Assignment

Priority order:
1. Ephemeral instruments (pcap, net_sensor, tshark) → always ephemeral
2. Evidence rank 2 → structural (harvested data is long-lived)
3. Instrument-specific table (bloodhound → structural, auth_scanner → operational)
4. Default: operational

### Support Vector from Status

```python
realized → (confidence, 0.0, 0.0)   # φ_R = confidence
blocked  → (0.0, confidence, 0.0)   # φ_B = confidence
unknown  → (0.0, 0.0, confidence)   # φ_U = confidence
```

### File Pattern Matching

Observations loaded for a target IP from:
- `gravity_{instrument}_{ip_dot}_{hash}.ndjson`
- `gravity_{instrument}_{ip_underscore}_{hash}.ndjson`
- `msf_exec_{ip_*}.ndjson`
- `cve_events_{ip_*}.ndjson`
- Up to MAX_RECENT_BROAD_EVENT_FILES = 64 recent broad event files
- Cycle_id = file stem (gravity cycle timestamp for deduplication)

---

## 4. `support.py` — SupportEngine

### Decay Model

```python
DECAY_LAMBDAS = {
    "structural":  0.001,   # ~1000 hours to half-life
    "operational": 0.01,    # ~100 hours
    "ephemeral":   0.1,     # ~10 hours
}

weight = exp(-λ × dt_hours)
```

### Compatibility Score

```python
concentration = max(family_weight) / total_weight
C = 1.0 - concentration + 0.1 × (n - 1)
```

- C = 1.0: perfectly diverse (no dominant instrument family)
- C = 0.0: single instrument monopoly
- Penalizes single-source observations; rewards multi-basis coverage

### Decoherence

```python
decoherence = (raw_total - decayed_total) / raw_total
decoherence += 0.15 if n ≤ 1   # single-basis penalty
```

### Instrument Families (for n computation)

```
nmap        → network_scan
ssh_sensor  → host_access
http_collector, auth_scanner → web_active
bloodhound  → graph_identity
```

Distinct families observed = compatibility_span n. If cycle_ids are stamped, `n = len(observed_cycle_ids)` instead.

---

## 5. `state.py` — StateEngine

### Collapse Thresholds

Default: realized=0.5, blocked=0.5

A single high-confidence (≥0.95) observation immediately realizes a wicket. Conflicts where both φ_R and φ_B are high stay UNKNOWN (logical AND for certainty).

---

## 6. `folds.py` — Folds and Gravity Weights

### Fold Types and Φ Weights

| Type | Gravity Weight Φ | Meaning |
|------|-----------------|---------|
| structural | 1.0 + p | Service with no toolchain (dark surface) |
| projection | 0.5 + 0.5p | Uncatalogued attack path |
| contextual | p | CVE with no wicket mapping |
| temporal | p × 0.7 | Evidence decayed past TTL |

Where p = discovery_probability ∈ [0, 1].

**Ordering guarantee**: Φ_structural ≥ Φ_projection ≥ Φ_contextual (at fixed p).
Dark surfaces pull harder than uncatalogued paths which pull harder than stale evidence.

### TTL Thresholds

- EPHEMERAL_TTL_HOURS = 4
- OPERATIONAL_TTL_HOURS = 24

### Fold ID Stability

Fold IDs are stable UUIDs derived from (fold_type, location, constraint_source). Same fold never duplicated; resolving removes by ID.

---

## 7. `wicket_graph.py` — WicketGraph

### Purpose

Kuramoto phase dynamics applied to the *semantic space* of wickets. Tracks phase and torque independently of pearl memory and gives gravity signals for unexplored regions.

### Phase Encoding

```
realized → φ = 0.0    (synchronized)
unknown  → φ = π/2   (orthogonal — maximum uncertainty)
blocked  → φ = π     (anti-phase)
```

### Edge Coupling Constants

| Edge Type | K | Interpretation |
|-----------|---|----------------|
| requires | 0.90 | Hard attack path dependency |
| enables | 0.70 | High likelihood implication |
| co_occurs | 0.50 | Observed together |
| excludes | −0.40 | Anti-correlated |

### Entanglement and Synchronization

- K_ENTANGLE = 0.80 → non-separable pairs (HO-04⊗HO-05, HO-05⊗HO-10, WB-09⊗WB-10)
- K_SYNC = 0.60 → synchronization clusters (attack path families)
- TORQUE_SIGNAL = 0.25 → meaningful gravity signal threshold

### Phase Gradient (Torque)

```python
torque(i) = |Σ_j K_ij sin(φ_j − φ_i)|
```

High torque on unknown wickets = high gravity pull toward those wickets.

### Dark Hypotheses

High-torque unknown wickets with NO instrument coverage. These are structural folds: the field predicts they exist but cannot be measured with current instruments. Examples: AP-L4, AP-L7, AP-L12 (Log4Shell wickets with no JNDI probe installed).

### WicketGraph Seeding

1. From all `attack_preconditions_catalog.*.json` → nodes (187 on first boot)
2. From EXPLOIT_MAP consecutive pairs → enables edges
3. From EXPLOIT_MAP all pairs → co_occurs edges
4. Hardcoded semantic edges: WinRM chain, SSH chain, lateral movement, pass-the-hash, web, container

---

## 8. `field_local.py` — Paper 4 FieldLocal

### Self Energy

```python
E_self(L_i) = U_m(L_i) + E_local(L_i) + E_latent(L_i)

U_m      = Σ φ_U                  # unresolved mass
E_local  = Σ (φ_contradiction + φ_decoherence)   # local tension
E_latent = 0.5 per wicket with span ≤ 1          # unmanifested potential
```

### Coupling Energy

```python
E_couple(L_i → L_j) = K(L_i, L_j) × (E_local(L_j) + U_m(L_j))
```

### Inter-Local Coupling Matrix K

| Domain Pair | K |
|-------------|---|
| cred → ssh | 0.95 |
| cred → web | 0.90 |
| cred → data | 0.90 |
| host → smb | 0.80 |
| host → web | 0.89 |
| host → data | 0.65 |
| lateral → host | 0.50 |
| (default) | 0.10 |

### Decoherence Criterion (Proposition 4)

A FieldLocal is **protected** iff ALL four conditions hold:
1. C ≥ 0.70 (compatibility_score)
2. φ_contradiction < 0.15
3. φ_decoherence < 0.20
4. n ≥ 2 (compatibility_span)

Protected locals are stable minima; re-observation provides no benefit. The `instrument_potential()` function in `engine.py` skips protected locals when computing Φ_fiber.

---

## 9. `engine.py` — KernelStateEngine

### instrument_potential() — Paper 4 §4

```python
Φ_effective = Φ_base + α × Φ_fiber    (α = 0.35)

Φ_base = unresolved_in_wavelength / cost
Φ_fiber = phi_fiber() from field_functional module
```

The fiber term integrates:
- **Tension**: fiber coherence × tension weight
- **Coupling**: cross-domain K values applied to E_local
- **Decoherence load**: -log(1 + decoherence_penalty)

### states_with_detail()

Returns per-wicket dict including:
- phi_r, phi_b, phi_u, contradiction, decoherence, C, n
- local_energy
- unresolved_reason: one of {unmeasured, conflicted, decohered, inconclusive, insufficient_support, single_basis, latent}

---

## 10. `pearls.py` + `pearl_manifold.py`

### Pearl Structure

Pearls capture decision point snapshots:
- state_changes: wicket state transitions
- observation_confirms: supporting evidence
- projection_changes: attack path feasibility changes
- reason_changes: evidence rationale changes
- energy_snapshot, target_snapshot, fold_context

### PearlManifold

Groups pearls by (identity_key, domain):
- reinforced_wickets: appear ≥ 2 times → gravity boost toward those wickets
- transition_density: state_changes / pearl_count
- mean_energy: average field energy at pearl timestamps

Pearl manifold boost cap: 2.0 (base) → 10.0 (multiplicative, as of 2026-03-20 update).

---

## 11. `field_functional.py`

### Fiber Load Formula

```python
tension_load = ln(1 + Σ tension_i × coherence_i)
persistence_load = ln(1 + Σ [0.6×coherence_i + 0.4×tension_i])
```

Log scale prevents unbounded accumulation. Topology curvature derived from FieldTopology per relevant sphere.

### Field Functional Total

```python
L(F) = E_self + E_coupling - curvature + dissipation
```

Dissipation opposes field formation (represents friction cost of measurement).

---

## 12. Topology Module Overview

### `topology/energy.py`

**G(t) coherence observable:**

```python
G(sphere) = Σ_ij A_i A_j cos(φ_i − φ_j) / n²
G_norm    = G / G_max    where G_max = Σ A_i² / n
```

This is NOT the full energy functional — it is the phase/coherence observable within a sphere.

**unknown_mass** per sphere:
```python
unknown_mass = Σ (amplitude + 0.5×local_energy + 0.5×decoherence + 0.25×(1 − C))
```

**Fiber and FiberCluster:**
- `Fiber`: anchor × domain × members × coherence × tension × rho × tau
- `FiberCluster.G_cluster()` = Σ tension×coherence + K(sphere_i, sphere_j)×coherence_i×coherence_j

### `topology/manifold.py`

SimplicialComplex from two sources:
1. **Priors** (CAUSAL_EDGES, 15 hardcoded attack path relationships)
2. **Empirical** (co-realized wicket pairs from recent event files)

Weight formula for empirical edges:
```python
weight = min(1.0, 0.35 + 0.30 × mean_confidence)
```

H¹ obstructions detected via DFS cycle detection. Classification by domains involved (cross-domain vs. intra-domain). Each cycle gets interpretation + resolution hint.

### `topology/kuramoto.py`

Full Kuramoto dynamics for generating steady-state KuramotoState:

```python
dφ_i/dt = ω_i + (K/n) Σ_j w_ij A_j sin(φ_j − φ_i) − d_i
```

Default parameters: steps=200, dt=0.05, K=2.0.

Natural frequencies by evidence rank:
- Rank 1 (runtime) → ω = 1.00
- Rank 2 (config) → ω = 0.75
- Rank 3 (inferred) → ω = 0.50
- Rank 4 (network) → ω = 0.25

### `topology/sheaf.py`

Betti number β₁:
```python
β₁ = |E| − |V| + |C|    (on unknown wicket subgraph)
```

β₁ > 0 → mutual dependency cycle → "indeterminate_h1" classification.
The constraint surface must change (not observation) to resolve.

---

## 13. Potential Issues

| Location | Issue |
|----------|-------|
| `wicket_graph.py:239` | Phase gradient relies on adjacency completeness; incomplete adjacency silently misses high-value unknowns |
| `support.py:140` | Compatibility concentration metric may overweight single-run instruments; diversification bonus 0.1×(n-1) may be insufficient |
| `sheaf.py:68-70` | Cycle detection uses `path.index(neighbor)` — if neighbor appears multiple times, extracts first occurrence only |
| `folds.py:182` | temporal fold decay_factor defaults to 0.7 hardcoded; should derive from TTL metadata |
| `engine.py:327` | phi_fiber() wrapped in try-except; silent failures may hide field_functional integration issues |
| `support.py` | compatibility_span = len(cycle_ids) only if stamped; older observations fall back to family counting, making n inconsistent |
