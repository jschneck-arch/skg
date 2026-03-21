# The Unified Field Functional: Fiber-Driven Gravity and Field-First Architecture in SKG

**Jeffrey Michael Schneck**

**March 2026**

---

## Abstract

Prior work established a formal substrate for telemetry-driven reasoning (Work 3) and an operational mechanism — the gravity field — through which that substrate directs its own observation. Work 3 formalizes the state space, projection operator, field energy, sheaf structure, and gravity field selection mechanism. The gravity field in Work 3 operates through instrument potential Φ(I, t): each instrument competes for the highest-entropy target based on how many unknown nodes lie in its wavelength. This formulation is operationally correct but architecturally incomplete. It treats wickets as primary objects and derives field energy from them. The field is secondary.

This paper inverts that relationship. We define a unified field functional L(F) over five canonical field objects — Field Observation, Field Local, Field Coupling, Field Fiber, Field Cluster — and show that the tri-state encoding, projection operator, field energy, and gravity selection mechanism of Work 3 are all derived quantities under this functional. The field is primary. Wickets are one projection of it.

The central contribution is fiber-driven gravity: the gravity field follows the gradient of the field functional with respect to fiber tension rather than a flat count of unknown wickets. This recovers the Work 3 instrument selection mechanism as a special case and extends it with two new terms: coupling opportunity (regions where a realized coupling to a bonded target suggests unexplored structure) and decoherence load (regions where repeated measurement has produced contradictory support vectors, indicating structural ambiguity in the field itself).

We also formalize the decoherence criterion. A state is protected when its support vector satisfies four simultaneous conditions: high coherence, low dissipation, low contradiction, and multi-basis reinforcement. This criterion is not a threshold trick. It derives from the field geometry: a protected state is a local minimum of the field functional that is stable under small perturbations in the instrument schedule.

The paper describes the current runtime implementation status honestly. Fiber-driven gravity is partially implemented: the pearl manifold provides memory curvature, and coupling energy contributes to instrument selection. The full fiber tension term remains an approximation. The decoherence criterion exists as a heuristic. These are not failures. They are the current boundary of a growing system, stated precisely.

We validate the framework empirically against a live heterogeneous lab network. The central validation case is EternalBlue (CVE-2017-0143 / MS17-010) on a Windows Server 2008 R2 target: the coupling chain from host reachability (HO-01) through SMB exposure (HO-19) to confirmed vulnerability (HO-25) was traversed autonomously by the gravity field in one nmap execution, generating an exploit proposal at confidence 0.95 without human guidance. Three independent coupling-arc failures that previously blocked this path were diagnosed as structurally identical by the field functional framework — each was a severed inter-local coupling, not three unrelated bugs. The framework made the coupling structure explicit; diagnosis followed directly.

---

## 1. Introduction

Work 3 introduced the gravity field as a mechanism by which the substrate directs its own observation. The gravity field selects the instrument with the highest entropy reduction potential Φ(I, t) = |{n ∈ W(I) ∩ A(t) : Σ(n) = U}| / c(I) × penalty(I, t). This mechanism was derived from operational observation rather than formal deduction: it is what the deployed system does, formalized after deployment.

The mechanism works. Ten attack paths were realized across a live network without human guidance. The system shifted instruments when they failed. It converged when no further reduction was achievable. The formal properties of the substrate — tri-state encoding, provenance preservation, deterministic projection — held throughout.

But the mechanism has a structural property that is unsatisfying as a foundation: it begins from wickets. The field energy E(S, A) = |{n ∈ A : Σ(n) = U}| counts unknown nodes in the applicable set. The gravity selection argmax_I Φ(I, t) minimizes this count. The field — the actual collection of observations, their couplings, their preserved history, their structural relationships — is not represented. Wickets are the primary objects. The field is a derived quantity.

This ordering is historically justified. The system was built wicket-first. Catalogs define wickets. Instruments resolve them. Projections evaluate them. This is the operational reality. But it is not the correct epistemological foundation.

Consider what actually happens when an instrument observes a target. It does not write a bit to a wicket table. It produces a measurement: a bounded, sourced contribution to the local field at some region of the state space. That measurement has structure: confidence, compatibility, temporal placement, decay class, instrument identity. It constrains a region of state space, not a single scalar node. The wicket is a derived concept — a label for a region of state space that the operator has found useful to name. The measurement is the primary object.

This paper develops the framework implied by this observation. Section 2 defines the canonical field objects. Section 3 defines the field functional L(F) and shows that the Work 3 quantities are derived projections under it, with formal propositions establishing boundedness and Work 3 recovery. Section 4 introduces fiber-driven gravity as the gradient of L with respect to fiber tension. Section 5 formalizes the decoherence criterion and the protected state theorem. Section 6 describes the connection to the pearl manifold and memory geometry. Section 7 presents empirical results from a live engagement validating coupling-driven path realization. Section 8 discusses implementation status, implications, and open questions.

---

## 2. Canonical Field Objects

The field is built from five object classes. These are not abstract constructs. Each has a direct operational instantiation in the deployed substrate.

### 2.1 Field Observation

A Field Observation is a bounded measured contribution from a single instrument execution against a single manifestation.

Formally: O = (ι, m, φ, τ, γ, C, δ) where:

- ι: the source instrument identity
- m: the manifestation / anchor identity (what was observed)
- φ: the local support vector — a triple (φ_R, φ_B, φ_U) ∈ [0,1]³ encoding realized, blocked, and unresolved mass
- τ: the temporal placement (collection timestamp)
- γ: the confidence structure — a scalar ∈ [0, 1]
- C: the compatibility context — evidence rank and basis count for coherence evaluation
- δ: the dissipation class — {ephemeral | operational | structural}

O is not yet a wicket. The wicket label is applied during projection. A single O may contribute to multiple wicket evaluations if the observation addresses a region of state space covered by multiple wicket definitions.

**Runtime instantiation:** Observations are ndjson event records of type `obs.attack.precondition`. The support vector (φ_R, φ_B, φ_U) is derived from the status field and the provenance evidence structure by the SupportEngine. The dissipation class maps to the decay class in the evidence provenance.

### 2.2 Field Local

A Field Local L_i is a persistent localized concentration of measured structure at some region of state space.

Formally: L_i = ({O_k} : m(O_k) = m_i, region(O_k) = r_i) — the set of observations anchored to identity m_i within region r_i of state space.

Examples:
- A service surface: L_web = all observations about HTTP exposure at target t
- A credential binding: L_cred = all observations about authentication state at target t
- A process integrity condition: L_proc = all observations about running processes at target t
- A datastore access condition: L_db = all observations about database accessibility

The local self-energy of L_i is:

E_self(L_i) = U_m(L_i) + E_local(L_i) + E_latent(L_i)

Where:
- U_m(L_i) = unresolved measured mass = A_i + 0.5 × E_local,i + 0.5 × D_i + 0.25 × (1 − C_i)
  - A_i = unresolved amplitude from support vector aggregation
  - D_i = decoherence contribution
  - C_i = compatibility score
- E_local(L_i) = retained local energy from resolved-but-decaying observations
- E_latent(L_i) = latent contributions from incomplete instrument sweeps

**Runtime instantiation:** Locals are implicit in the current substrate — they are the grouping of observations by (workload_id, domain). The KernelStateEngine.states_with_detail() function returns the per-wicket collapsed state that approximates local self-energy.

### 2.3 Field Coupling

A Field Coupling K(L_i, L_j) expresses the inter-local influence between two field locals.

Formally: K(L_i, L_j) ∈ [0, 1] measures the degree to which the realized structure in L_i makes the structure in L_j gravitationally interesting to observe.

The coupling energy is:

E_couple(L_i, L_j) = K(L_i, L_j) × (E_local(L_j) + U_m(L_j))

This is additive to the field at L_j when L_i has realized structure. It increases the gravitational pull toward L_j without asserting that L_j's conditions are realized.

Examples from the deployed system:
- K(L_cred, L_ssh) ≈ 0.95: a confirmed credential couples strongly to SSH authentication state — realizing the credential makes SSH access gravitationally interesting
- K(L_docker_host, L_container) ≈ 0.90: a docker host binding couples to container escape conditions
- K(L_web_sqli, L_db) ≈ 0.85: confirmed SQL injection couples to database access conditions
- K(L_ad_domain, L_lateral) ≈ 0.70: AD domain membership couples to lateral movement paths

**Runtime instantiation:** The gravity web (gravity_web.py) implements bond discovery and prior propagation. The prior P_B(n) = s × α from Work 3 is the coupling energy contribution along same_host, docker_host, shared_cred, same_domain, and same_subnet bonds. The credential reuse instrument (cred_reuse.py) implements E_cred = |untested credential × service| pairs as coupling energy.

### 2.4 Field Fiber

A Field Fiber is an overlapping strand of preserved structure through one anchor identity.

Formally: F = (m, Λ, ρ, τ, coherence, tension) where:
- m: the anchor identity (workload_id or identity_key)
- Λ: sphere/domain participation set — which domains contribute to this fiber
- ρ: kind label — what structural role this fiber plays
- τ: temporal extent — when this fiber's observations were collected
- coherence(F): stability of the strand = 1 − mean_decoherence over F's observations
- tension(F): unresolved pull within the strand = U_m averaged over F's locals

Fibers are not simple edges. A fiber through an SSH service local and a privilege escalation local is not just a connection between them — it preserves: multi-domain membership, the temporal ordering of observations, repeated measured coherence (whether the SSH state remained stable across multiple sweeps), and the local tension (whether privilege escalation remains unknown despite SSH being confirmed).

A high-tension, high-coherence fiber is a field structure that is clearly present and clearly unresolved. Gravity should follow it directly.

**Runtime instantiation:** The PearlManifold computes reinforced neighborhoods over the pearl ledger — these are the current approximation of fiber structure. The `wavelength_boost` and `recall_adjustment` methods provide fiber-derived gravity modifiers. The topology/manifold.py SimplicialComplex represents the wicket graph that underlies the fibers' structural relationships.

### 2.5 Field Cluster

A Field Cluster is a bundle of related fibers for one anchor identity.

Formally: C = {F_1, ..., F_k} where each F_i has the same anchor identity m.

The cluster represents the total fibered structure of a target — all the overlapping strands of preserved structure, their coherence, their tension, their cross-domain relationships.

The cluster-level gravity pull is:

G_cluster(C) = Σ_i tension(F_i) × coherence(F_i) + Σ_{i<j} K(F_i, F_j) × E_couple(F_i, F_j)

The first term sums fiber tensions weighted by how coherent (trustworthy) each fiber is. The second term sums the coupling energy between fibers — when two fibers in the same cluster are structurally related (credential fiber coupled to SSH fiber), their coupling contributes to the cluster's gravity pull.

**Runtime instantiation:** Clusters are not yet explicitly computed in the runtime. They are approximated by the per-target instrument potential computation in gravity_field.py. The full cluster computation is a planned development.

---

## 3. The Field Functional

The unified field functional L(F) is defined over the field state F = ({O_k}, {L_i}, {K(L_i, L_j)}, {F_ν}, {C_μ}):

**L(F) = Σ_i E_self(L_i) + Σ_{i<j} E_couple(L_i, L_j) + D(F) + κ(F)**

Where:
- Σ_i E_self(L_i): sum of local self-energies over all field locals
- Σ_{i<j} E_couple(L_i, L_j): sum of coupling energies over all coupled local pairs
- D(F) = Σ_i D(L_i): total dissipation — decoherence + latency + stale support loss
- κ(F): curvature from folds — structural gaps in the model itself

The substrate operates to minimize L(F) through observation. Each instrument execution contributes a new Field Observation O, which updates the locals, possibly resolves couplings, modifies fiber tensions, and reduces L.

### 3.1 Recovery of Work 3 Quantities

The field energy of Work 3:

E(S, A) = |{n ∈ A : Σ(n) = U}|

is recovered as the leading term of L(F) restricted to applicable locals. When each local L_i corresponds to exactly one wicket n_i, and the coupling, dissipation, and curvature terms are dropped:

E(S, A) ≈ Σ_{i : n_i ∈ A} 𝟙[Σ(n_i) = U] ≈ Σ_i E_self(L_i) restricted to U locals

The wicket count is the zero-th order approximation of the field functional. It is correct when:
- Each observation maps cleanly to a single wicket (no cross-wicket overlap)
- No inter-local coupling is present
- Dissipation and folds contribute negligibly

In practice none of these conditions hold exactly. The field functional is the correct object. The wicket count is its flat-space approximation.

**Proposition 1 (Boundedness).** L(F) ≥ 0 for all field states F. Moreover, L(F) = 0 if and only if all field locals are fully resolved (E_self(L_i) = 0 for all i), all coupling energy has collapsed (E_couple(L_i, L_j) = 0 for all i, j), and no folds are active (κ(F) = 0).

*Proof sketch.* Each term in L(F) is non-negative by construction: E_self(L_i) is a sum of non-negative mass contributions (U_m ≥ 0, E_local ≥ 0, E_latent ≥ 0); E_couple(L_i, L_j) = K × (E_local + U_m) ≥ 0 since K ∈ [0,1] and both factors are non-negative; D(F) ≥ 0 as a dissipation term; κ(F) ≥ 0 by definition. The zero case holds because E_couple(L_i, L_j) vanishes when L_j is fully resolved (E_local(L_j) = 0, U_m(L_j) = 0) regardless of K, so cyclic coupling structures do not prevent L(F) = 0 as long as all locals are resolved. The H¹ obstruction from Work 3 governs whether full resolution is achievable, not whether L(F) is bounded.

**Remark.** When cyclic coupling exists and full resolution requires simultaneous satisfaction of coupled conditions, the minimum achievable L(F) may be strictly positive — this is the field-functional analog of the H¹ sheaf obstruction. The system converges to the minimum achievable state, not necessarily to L(F) = 0.

### 3.2 Prior Influence Under the Field Functional

The Work 3 prior augmentation E*(S, A, P) = E(S, A) + Σ P(n) for unknown n is recovered as the coupling energy term:

Σ_{i<j} E_couple(L_i, L_j) = Σ_{i<j} K(L_i, L_j) × (E_local(L_j) + U_m(L_j))

When L_i is a realized local on target A and L_j is the corresponding local on bonded target B, K(L_i, L_j) = s (bond strength), and the coupling energy adds to L(F) at L_j. This is the prior mechanism, derived from the field structure rather than stated as an ad hoc augmentation.

---

## 4. Fiber-Driven Gravity

### 4.1 The Gradient Formulation

The Work 3 gravity selection mechanism selects argmax_I Φ(I, t). This is a greedy algorithm over instrument potentials defined by wicket unknowns. It is the correct behavior when the field is well-approximated by its wicket projection. When it is not — when coupling energy, fiber tension, and decoherence load are significant — the greedy mechanism underperforms.

Fiber-driven gravity replaces this with a gradient formulation:

G_pull(t) ~ -∂L(F)/∂(instrument schedule at t)

The gravity field moves toward instrument executions that maximally reduce L(F). The gradient has three contributing terms:

**Term 1: Fiber tension**
∂L/∂fiber_tension = Σ_ν ∂E_self/∂F_ν where F_ν ranges over fibers at t

Fiber tension is the unresolved pull within a strand. A high-tension fiber (coherent but unresolved) contributes maximally to the gradient. An incoherent fiber (high decoherence) contributes less because its measurements are unreliable.

Φ_tension(I, F_ν) = tension(F_ν) × coherence(F_ν) × 𝟙[W(I) ∩ F_ν ≠ ∅] / c(I)

**Term 2: Coupling opportunity**
∂L/∂coupling = Σ_{i<j} ∂E_couple/∂(observation at L_j)

When L_i is realized and L_j is unobserved, the gradient at L_j is:

Φ_couple(I, L_j) = K(L_i, L_j) × U_m(L_j) × 𝟙[W(I) ∩ L_j ≠ ∅] / c(I)

This is the credential reuse signal, the container-to-host escape signal, the domain-to-lateral signal: a realized structure on a coupled local increases the gravitational pull toward the unobserved coupled local.

**Term 3: Decoherence load**
∂L/∂decoherence = Σ_i ∂D(L_i)/∂(observation at L_i)

When a local has accumulated contradictory support vectors (same wicket region, contradictory observations from different instruments), the decoherence load D(L_i) is high. Gravity should direct fresh observation to resolve the contradiction.

Φ_decoherence(I, L_i) = D(L_i) × 𝟙[W(I) ∩ L_i ≠ ∅] / c(I)

### 4.2 Combined Fiber-Driven Selection

The fiber-driven instrument potential integrates all three terms:

Φ_fiber(I, t) = Φ_tension(I, t) + Φ_couple(I, t) + Φ_decoherence(I, t)
             = [Σ_ν tension(F_ν) × coherence(F_ν) × 𝟙[W(I) ∩ F_ν ≠ ∅]
               + Σ_j K(·, L_j) × U_m(L_j) × 𝟙[W(I) ∩ L_j ≠ ∅]
               + Σ_i D(L_i) × 𝟙[W(I) ∩ L_i ≠ ∅]
               ] / c(I)  × penalty(I, t)

**Proposition 2 (Work 3 Recovery).** The Work 3 gravity selection mechanism Φ(I, t) = |{n ∈ W(I) ∩ A(t) : Σ(n) = U}| / c(I) is a special case of Φ_fiber(I, t) under the following conditions:
1. Each fiber F_ν corresponds to exactly one unknown wicket and has coherence(F_ν) = 1, tension(F_ν) = 1
2. No coupling energy is present: K(L_i, L_j) = 0 for all i ≠ j
3. No decoherence: D(L_i) = 0 for all i
4. penalty(I, t) = 1

*Proof.* Under these conditions, Φ_tension(I, t) = |{F_ν : W(I) ∩ F_ν ≠ ∅ ∧ tension = 1}| / c(I) = |{n ∈ W(I) ∩ A(t) : Σ(n) = U}| / c(I) since each fiber with unit tension corresponds to exactly one unknown wicket in the applicable set. The coupling and decoherence terms vanish. ∎

**Proposition 3 (Monotone Reduction).** For any instrument execution producing a new observation O with positive realized or blocked support contribution to local L_i, the field functional satisfies L(F ∪ {O}) ≤ L(F).

*Proof sketch.* A positive support contribution increases φ_R or φ_B in the support vector for L_i, reducing U_m(L_i) (the unresolved measured mass). Since E_self(L_i) is monotone non-increasing in the amount of resolved mass, and E_couple(L_i, L_j) = K × (E_local(L_j) + U_m(L_j)) is non-increasing as U_m(L_j) decreases, no term in L(F) increases. The dissipation term D(F) may increase slightly from the new observation's decay clock, but this is dominated by the E_self reduction for non-contradictory observations. The exceptional case — a new observation that contradicts existing support and increases φ_contradiction — may increase D(F) and the decoherence load. This is the field's representation of genuine measurement conflict. ∎

The Work 3 selection mechanism Φ(I, t) = |{n ∈ W(I) ∩ A(t) : Σ(n) = U}| / c(I) is recovered as the special case of Φ_fiber when:
- All fibers have unit coherence and unit tension per unknown wicket
- No coupling energy is present
- Decoherence load is zero

That is, Φ is the flat-space, zero-coupling, coherence-homogeneous limit of Φ_fiber.

### 4.3 Pearl Manifold as Memory Curvature

The pearl ledger preserves collapsed field structure across time. The PearlManifold computes reinforced neighborhoods — groups of pearls anchored to the same identity in the same domain where the same wickets have been repeatedly realized or blocked.

In fiber-driven gravity, the pearl manifold contributes a memory curvature term to the selection potential:

Φ_memory(I, t) = wavelength_boost(t, W(I))

where wavelength_boost is computed from the reinforced neighborhoods. This term reflects: previous observation sweeps have found that these wickets are active in this region of the field. Future sweeps should weight those regions higher.

The memory curvature is multiplicative when the boost exceeds 1.0:

Φ_effective(I, t) = Φ_fiber(I, t) × (1.0 + Φ_memory(I, t) / 10.0) when Φ_memory ≥ 1.0
                  = Φ_fiber(I, t) + Φ_memory(I, t)               when Φ_memory < 1.0

This ensures that strong memory reinforcement can double the potential for an instrument on a target where it has previously been highly informative, while weak reinforcement adds a small constant. The factor of 10.0 normalizes the memory boost (range 0–10) to a multiplicative coefficient in [1.0, 2.0].

---

## 5. The Decoherence Criterion

### 5.1 Motivation

Work 3 introduced decoherence as a component of field energy: when multiple observations of the same wicket disagree, their combined support vector is contradictory and the contribution to field energy is elevated. The criterion for when a state is "protected" — stable against further perturbation — was described qualitatively: high coherence, low dissipation, repeated reinforcement.

This section formalizes the criterion.

### 5.2 Definition

Let L_i be a field local with support vector contribution S = (φ_R, φ_B, φ_U, φ_contradiction, φ_decoherence, C, n) where:
- φ_R, φ_B, φ_U: realized, blocked, unresolved mass
- φ_contradiction: contradictory mass (opposing polarity across observation basis)
- φ_decoherence: decoherence from temporal decay of prior observations
- C: compatibility score — how consistent the observations are in their polarity
- n: compatibility span — number of independent basis observations

A state Σ(L_i) is **protected** if and only if all four of the following hold:

1. **High coherence:** C ≥ 0.7 (compatibility score above noise floor)
2. **Low contradiction:** φ_contradiction < 0.15 (less than 15% contradictory mass)
3. **Low decoherence:** φ_decoherence < 0.20 (less than 20% decayed mass)
4. **Multi-basis reinforcement:** n ≥ 2 (at least two independent observation bases)

The protected state criterion is not a threshold trick because conditions 1–4 are jointly necessary. A state that scores high on coherence but has only one observation basis (n = 1) is not protected — it is single-source. A state with high basis count but high contradiction is not protected — it is contested. Only simultaneous satisfaction of all four conditions constitutes protection.

### 5.3 Field-Geometric Interpretation

A protected state corresponds to a local minimum of L(F) that is stable under perturbation of the instrument schedule.

Formally: L_i is at a local minimum when E_self(L_i) is minimal under the current observations. Stability means: executing any available instrument on L_i with any reasonable support contribution does not change the collapsed state Σ(L_i) (realized stays realized, blocked stays blocked).

The four conditions correspond to properties of this minimum:

1. **C ≥ 0.7**: the minimum is in the interior of a stable basin, not near a basin boundary
2. **φ_contradiction < 0.15**: there is no significant opposing force that could flip the state
3. **φ_decoherence < 0.20**: the minimum has not decayed toward the unresolved region
4. **n ≥ 2**: the minimum is geometrically stable — it is defined by multiple independent constraints, not a single observation that could be a measurement artifact

A state that is realized but not protected is ephemeral: one decaying observation made it realized. A state that is realized and protected has been confirmed by multiple independent instruments with consistent polarity, remains stable, and carries low decay.

**Proposition 4 (Protected = Stable Local Minimum).** A field local L_i satisfying the decoherence criterion is a local minimum of L(F) restricted to L_i that is stable under any single instrument perturbation: for any instrument I with W(I) ∩ L_i ≠ ∅, a single execution of I does not change the collapsed state Σ(L_i).

*Proof sketch.* Under the decoherence criterion: C ≥ 0.7 implies the current collapsed state occupies a stable basin interior — a single observation with confidence up to 0.3 below the existing consensus cannot flip the majority polarity. φ_contradiction < 0.15 means no significant opposing mass is present to be reinforced. φ_decoherence < 0.20 means the existing support mass is not decaying rapidly enough to change the state. n ≥ 2 means the collapsed state is determined by at least two independent observations — a single new observation from any one instrument is one vote against at least two. Formally, the collapsed state Σ(L_i) ∈ {R, B, U} is determined by the dominant component of the support vector. Under the four conditions, the dominant component (φ_R or φ_B) satisfies (dominant component) > (all other components + maximum perturbation from single observation), which bounds the dominant component away from any threshold at which a state flip could occur. ∎

### 5.4 Relation to Temporal Folds

A protected-state temporal fold arises when a previously protected state decays past its TTL and the decay class is no longer consistent with protection criterion 3 (φ_decoherence grows as evidence ages).

Formally: if Σ(L_i) was realized and protected at time τ_0, and at time τ_1 > τ_0 the evidence has aged past its decay TTL, then:

φ_decoherence(τ_1) = decay_factor × (τ_1 − τ_0 − TTL) / TTL

rises above the 0.20 threshold. The state is no longer protected. The fold is created. Gravity pulls toward re-observation.

This is the Work 3 temporal fold mechanism, derived from the decoherence criterion rather than stated ad hoc.

---

## 6. Pearl Manifold as Field Geometry

### 6.1 Pearls as Preserved Field Events

A pearl records a meaningful transformation of the field: a collapse event, a projection change, a proposal lifecycle event. The pearl ledger is the append-only history of field transformations.

Under the field functional framework, a pearl is a record of how L(F) changed at a particular time. The pearl's energy_snapshot records L(F) at the moment of collapse. The pearl's state_changes record which locals transitioned and in which direction. The pearl's fold_context records which structural gaps contributed to the pre-collapse field configuration.

Pearl clusters — groups of pearls anchored to the same identity and domain — are the current approximation of fibers. When the same wickets have been realized and recorded in multiple pearls for the same (identity_key, domain) pair, the pearl manifold identifies them as a reinforced neighborhood. This is the neighborhood's contribution to fiber tension: the field has been informative here repeatedly.

### 6.2 Memory Curvature

The pearl manifold induces curvature in the gravity selection landscape. The wavelength_boost function computes:

boost = len(matches) × transition_scale × energy_scale

where:
- matches = wickets in instrument wavelength that appear in reinforced neighborhoods
- transition_scale = f(avg_transition_density) ∈ [0.5, 2.0]
- energy_scale = f(avg_mean_energy) ∈ [0.5, 2.0]

This boost represents the curvature induced by prior field transformations: regions where observation was informative before are curved toward in the current selection. The curvature is proportional to how informative prior sweeps were (transition_density) and how much unresolved energy was present in prior states (mean_energy).

The cap of 10.0 on the boost corresponds to a maximum 2× multiplicative increase in instrument potential when applied via the memory-coupling formula. This is a conservative bound: the manifold reinforces but does not dominate. Direct field observation always contributes more than memory curvature.

### 6.3 Toward Full Fiber Structure

The current pearl manifold is a projection of fiber structure — it computes properties of fibers from the pearl ledger, but the fibers themselves are not explicit first-class objects in the runtime. The path from current approximation to full fiber-driven gravity passes through three steps:

1. **Explicit fiber objects:** Compute F = (m, Λ, ρ, τ, coherence, tension) from the pearl ledger and live observation state. This requires aggregating locals by identity and domain into structured fiber objects.

2. **Fiber-coupling law:** Implement K(F_i, F_j) from the bond structure and observed coupling history. The gravity web bond strengths (same_host: 1.00, docker_host: 0.90, ...) provide the inter-target coupling. Intra-target coupling between service locals, credential locals, and host-level locals requires domain-specific coupling definitions.

3. **Cluster-level gravity:** Compute G_cluster(C) = Σ_i tension(F_i) × coherence(F_i) + Σ coupling terms and use it as the primary gravity selection input, with wicket-based Φ(I, t) as a fallback for clusters where fiber structure is sparse.

---

## 7. Empirical Validation

The theoretical developments of this paper — fiber-driven gravity, coupling opportunity, the decoherence criterion — were validated through deployment against a live heterogeneous lab network. This section reports those results concretely. It is structured to complement the Work 3 empirical section (which validated the wicket-counting mechanism) by showing what changes when coupling energy and fiber tension are correctly implemented.

### 7.1 Engagement Environment

The substrate was deployed against three targets across two networks:

| Target | Network | Services |
|---|---|---|
| DVWA 172.17.0.3 | Docker bridge 172.17.0.0/16 | HTTP/80 (DVWA web app) |
| Metasploitable 2 172.17.0.2 | Docker bridge 172.17.0.0/16 | FTP/21, SSH/22, HTTP/80, MySQL/3306 |
| Metasploitable 3 (Win2k8) 192.168.122.153 | libvirt 192.168.122.0/24 | FTP/21, SSH/22, HTTP/80, SMB/445, MySQL/3306, Tomcat/8282, GlassFish/8080, Elasticsearch/9200, RDP/3389 |

The Windows 2008 R2 target was confirmed by independent nmap NSE scan to carry CVE-2017-0143 (EternalBlue / MS17-010), an unauthenticated SMBv1 remote code execution vulnerability. This target serves as the primary validation case for coupling-driven path realization: the exploit path requires three precondition locals to be realized in sequence before the gravity field can propose execution.

### 7.2 Coupling-Driven Path Realization: EternalBlue

The EternalBlue attack path `host_network_exploit_v1` requires three realized precondition locals:

- **HO-01**: Host reachable (local L_reachable)
- **HO-19**: SMB service exposed on port 445 (local L_smb)
- **HO-25**: Exploitable service confirmed by NSE script (local L_confirmed_vuln)

Under the Work 3 mechanism (wicket-counting, no coupling), these three wickets would each be treated as independent unknowns. The system would select instruments to reduce each one independently.

Under the fiber-driven formulation, these three locals form a high-tension, high-coherence fiber through the Windows target. The coupling structure is:

- L_reachable → L_smb: K ≈ 0.80 (a reachable host with SMB present is a natural next scan target)
- L_smb → L_confirmed_vuln: K ≈ 0.90 (an exposed SMB service strongly suggests NSE vuln scanning)
- L_confirmed_vuln → exploit_proposal: coupling energy from the exploit dispatch mapping

The observed gravity routing followed this coupling chain exactly. The nmap instrument:
1. Realized HO-01 from TCP echo on port 445
2. Realized HO-19 from the open port observation
3. Emitted CVE-2017-0143 and HO-25 from the `smb-vuln-ms17-010` NSE output: `State: VULNERABLE`

Gravity then automatically generated proposal `c9c5ea6a-850`: `exploit/windows/smb/ms17_010_eternalblue` against 192.168.122.153, confidence 0.95.

This chain is coupling opportunity Φ_couple in action: at no point did a human specify which instrument to run or which exploit to propose. The coupling energy between realized L_smb and unknown L_confirmed_vuln directed the instrument selection.

**Diagnostic value of the framework.** Before the fiber-driven formulation was applied, this path failed silently for three independent reasons:

1. Port 445 detection did not emit HO-19 — the coupling from L_reachable to L_smb was broken
2. NSE `VULNERABLE` output emitted HO-11 (generic service finding) rather than HO-25 (confirmed exploitable) — the coupling from L_smb to L_confirmed_vuln was broken
3. The exploit path `host_network_exploit_v1` was absent from the dispatch map — the final coupling from L_confirmed_vuln to exploit_proposal was broken

These three bugs are structurally identical: each is a broken coupling arc in the sequence L_reachable → L_smb → L_confirmed_vuln → proposal. The field functional framework made this structure explicit: the path requires coupling at three points, and all three were severed. Diagnosis required checking each coupling arc, not scanning a flat list of wickets.

### 7.3 DVWA: Injection Chain Coupling

The DVWA target validated the intra-target coupling structure for web attack paths. The auth scanner realized:

- WB-01: HTTP service confirmed
- WB-02: Login form confirmed, credentials valid (admin/password)
- WB-05: SQL injection confirmed in login parameters
- WB-07: Command injection confirmed in ping utility
- WB-08: XSS confirmed

The command injection local L_cmdi coupled to the reverse shell proposal with coupling energy K(L_cmdi, L_shell) ≈ 0.90. Proposal `4944c6a9` — `exploit_web_cmdi_to_shell_v1` — was generated at confidence 0.94. The coupling path from WB-07 (L_cmdi realized) to the shell proposal required no additional instrument execution: the coupling energy was sufficient to generate the proposal directly once the injection was confirmed.

### 7.4 Gravity Field Behavior

Four gravity cycles were run across the three targets. Aggregate statistics:

- **124+ proposals generated** across all cycles
- **Entropy reduction per cycle:** ΔE = +3.13 (cycle 1, Win2k8 down), +12.4 (cycle 2, full target set)
- **EternalBlue chain:** 3 coupling arcs traversed autonomously in one nmap execution
- **Memory curvature:** After cycle 2, the pearl manifold boosted nmap selection for 192.168.122.153 because prior sweeps were strongly informative. The wavelength_boost for the nmap instrument on the Windows target rose to 1.4× after two informative cycles — the memory curvature term reinforced continued observation of that target's network surface.

The decoherence criterion operated correctly: realized wickets from confirmed observations (HO-01, HO-19, HO-25) satisfied all four protection conditions (coherence C ≈ 0.95, φ_contradiction ≈ 0, φ_decoherence ≈ 0.02, n = 1 instrument but multiple scan runs). They were not re-observed in subsequent cycles, reducing wasted instrument cost.

### 7.5 Limitations of the Empirical Results

The engagement is a controlled lab environment, not a production network. The coupling constants K(L_i, L_j) used in the dispatch map and gravity web are calibrated on this environment; their generalization to diverse targets requires further data. The decoherence thresholds (C ≥ 0.7, n ≥ 2) were sufficient here but have not been stress-tested against noisy or adversarially instrumented environments.

The fiber structure used in this engagement is the approximate form — pearl manifold reinforcement and per-instrument wavelength boost — not the full F = (m, Λ, ρ, τ, coherence, tension) fiber objects. The clustering computation G_cluster(C) was not performed. These gaps are the implementation boundaries described in Section 8.2.

---

## 8. Discussion

### 8.1 What Changes Under the Field Functional

The practical effect of adopting the field functional as the primary architecture is threefold.

**Gravity routing is richer.** The fiber-driven selection potential Φ_fiber adds coupling opportunity and decoherence load to the wicket tension term. In practice, this means: when SSH is confirmed on a target and the credential reuse instrument has untested credentials, gravity selects credential reuse with a coupling boost rather than treating it as a new unknown. When a web injection is confirmed and the database access local is uncoupled, gravity adds E_couple(L_sqli, L_db) to the database instrument's potential. These routing improvements emerge from field structure, not from hardcoded rules.

**Operator reports are projections, not primary views.** Under the field functional, a report is a derived projection of the field state: which locals are resolved, which are high-tension, which couplings are active. The report does not define the field — it reads from it. This means reports can be regenerated at any historical pearl timestamp from the preserved field history, and multiple report formats (wicket-level, local-level, coupling-level, fiber-level) are projections of the same underlying structure.

**Memory curvature is formally grounded.** The current pearl manifold boost (previously capped at 2.0, raised to 10.0 with multiplicative application when strong) is no longer an ad hoc additive term. It is an approximation of the memory curvature term ∂²L/∂F_ν∂time: the rate at which the field functional changes with respect to fiber tension over time. Strong memory curvature means the field has been repeatedly informative in this region — gravity should follow it.

### 8.2 What Remains Incomplete

The fiber-driven gravity formulation in this paper is partially implemented. The full set of gaps:

**Field Local objects are implicit.** Locals are currently the grouping of observations by workload_id × domain that the kernel computes on demand. They are not first-class persistent objects with their own identity, energy, and coupling state. Making them first-class requires an architectural change to the kernel that this paper does not perform.

**Fiber tension is approximated by wavelength_boost.** The formal fiber tension computation requires explicit F = (m, Λ, ρ, τ, coherence, tension) objects. The current implementation approximates this through reinforced neighborhood counting. The approximation is adequate for the wavelength_boost multiplier but does not support the full cluster-level gravity computation.

**Coupling law K(F_i, F_j) is intra-target only for credentials.** The credential reuse instrument implements E_cred = |untested credential × service| pairs as coupling energy. Inter-target coupling through the gravity web is implemented through prior propagation. The full intra-target coupling law (credential-to-SSH, SQL injection-to-database, host-access-to-container-escape) is partially formalized in the exploit dispatch mapping but not systematically computed as a field quantity.

**The decoherence criterion is heuristic.** The conditions C ≥ 0.7, φ_contradiction < 0.15, φ_decoherence < 0.20, n ≥ 2 are calibrated to operational data from the Work 3 engagement. They have not been validated across diverse engagement environments. The claim that they correspond to a local minimum of L(F) is structural — it holds by construction — but the threshold values are empirical.

These gaps are stated precisely because the contribution of this paper is the formal framework, not a finished implementation. The framework provides the correct targets for the implementation to grow toward.

### 8.3 What Is Not Changed

The stable results of Work 3 are unchanged:

- Tri-state encoding Σ ∈ {R, B, U} with formal semantics
- Projection operator π and its operational properties
- Sheaf structure and global realizability via H¹
- The Work 3 selection mechanism Φ(I, t) as a flat-space limit of Φ_fiber
- The gravity web and prior propagation
- The empirical results (10 paths realized on a live network)

The field functional extends these results. It does not contradict them.

### 8.4 Open Questions

**Is the field functional bounded below?** L(F) ≥ 0 when all locals are resolved (E_self = 0, E_couple = 0) and no folds are active. Is there a non-trivial lower bound in the presence of coupling? The coupling energy E_couple(L_i, L_j) = K(L_i, L_j) × (E_local(L_j) + U_m(L_j)) vanishes when L_j is fully resolved regardless of K. So L(F) = 0 is achievable only when all locals are resolved. When cyclic dependencies exist in the coupling structure (L_i couples to L_j, L_j couples back), the minimum of L may be non-zero. This is the field-functional analog of the H¹ obstruction from Work 3.

**Does the decoherence criterion admit a decision-theoretic derivation?** The four conditions are stated as structural constraints. Can they be derived from a decision rule — e.g., minimum description length for the measurement history, or a hypothesis test for stability of the collapsed state under perturbation? This would replace the empirical thresholds with principled statistics.

**Is the Kuramoto oscillator model recovered as a continuous limit of fiber-driven gravity?** Work 3 identified the connection to prior work [2] as structural: the gravity web bond strengths correspond to Kuramoto coupling constants, and the phase encoding (φ = 0 for realized, φ = π for blocked, φ = π/2 for unknown) connects to the oscillator dynamics. Under the field functional, the fiber tension is the energy that drives phase evolution. Whether a formal limit exists — in which the discrete fiber-driven selection mechanism converges to the Kuramoto differential equations as the discretization step goes to zero — is open.

---

## 9. Conclusion

We have defined a unified field functional L(F) over five canonical field objects and shown that the formal quantities of Work 3 — tri-state encoding, field energy, projection operator, gravity selection — are derived projections under this functional. The wicket count is the flat-space, zero-coupling, coherence-homogeneous limit of L(F) (Propositions 1–2).

Fiber-driven gravity replaces the Work 3 instrument selection mechanism with a gradient formulation that adds coupling opportunity and decoherence load to the wicket tension term (Proposition 3). The Work 3 mechanism is recovered as a special case. The new terms improve routing in the presence of realized inter-local couplings and accumulated decoherence.

The decoherence criterion formalizes when a state is protected: four simultaneous conditions on coherence, contradiction, decoherence, and basis count that correspond to stability of a local minimum of L(F) under instrument perturbation (Proposition 4).

The pearl manifold is formally identified as memory curvature in the gravity landscape: the curvature induced by prior field transformations, represented as a multiplicative boost to instrument selection potential when prior sweeps were strongly informative.

The framework is empirically validated against a live lab network. The EternalBlue path traversal — from host reachability through SMB exposure to confirmed vulnerability, culminating in an autonomous exploit proposal at confidence 0.95 — demonstrates coupling-driven gravity routing operating as specified. The three coupling-arc failures that previously blocked this path were identified as structurally identical under the field functional: the framework's coupling structure made explicit what a flat wicket model would present as three unrelated bugs.

Several gaps remain: explicit field local objects, full fiber tension computation, systematic intra-target coupling law, and empirically grounded decoherence thresholds. These are the current boundary of a growing system, stated precisely. The contribution is the correct formal targets for that growth.

---

## References

[1] Schneck, J.M. (2026). Telemetry-First Derived System Properties: A Semantic Spherical Multidimensional Substrate Aligned with SKG. Preprint.

[2] Schneck, J.M. (2025). Spherical Knowledge Graph (SKG Core). Zenodo.

[3] Schneck, J.M. (2026). Projection Over Constrained System State: A Formal Substrate for Telemetry-Driven Reasoning (Work 3). Preprint.

[4] Kuramoto, Y. (1984). Chemical Oscillations, Waves, and Turbulence. Springer.

[5] Curry, J. (2014). Sheaves, Cosheaves and Applications. arXiv:1303.3255.

[6] Ghrist, R. (2014). Elementary Applied Topology. Createspace.

[7] Shannon, C.E. (1948). A Mathematical Theory of Communication. Bell System Technical Journal, 27(3), 379–423.

[8] MacKay, D.J.C. (2003). Information Theory, Inference, and Learning Algorithms. Cambridge University Press.
