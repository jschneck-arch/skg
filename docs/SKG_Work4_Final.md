# SKG: Domain-Agnostic Substrate with Domain Expression Architecture

**Jeffrey Michael Schneck**

**March 2026**

---

## Abstract

SKG is a substrate for telemetry-driven reasoning. It treats any observable state space as a physical field, accumulates measurements as bounded contributions to that field, and directs its own observation through an information-theoretic gravity mechanism. Prior work formalized this as a unified field functional L(F) over five canonical field objects and derived the gravity selection mechanism as its gradient.

One architectural property was left implicit in that formalization: SKG has no domain-specific logic. "Web", "host", "data" are not components of the substrate. They are expressions of it — bindings between the abstract field machinery and a particular observation space. The substrate processes field objects regardless of what domain produced them. The instruments are domain-specific; the substrate is not.

This paper makes that architecture explicit and derives its consequences.

A domain expression is a four-tuple Δ = (Ω, Ι, Α, Π): a wicket catalog defining what can be observed, an instrument set specifying how, an adapter translating raw output to field events, and a projection evaluating observations against the substrate. Twelve domain expressions are currently registered across 221 named conditions. Five are daemon-native in the live runtime today; the rest are auxiliary or operator-invoked, but their projectors are discovered by the same registry-driven loader.

The field functional connects expressions through an inter-expression coupling law K(Δ_a, Δ_b). When a local in expression Δ_a is realized on a target, the coupling term elevates the field potential for instruments in Δ_b. Cross-domain attack chains emerge from this coupling energy — not from hardcoded sequencing.

We validate against a live three-target engagement with four active expressions. The gravity field crossed expression boundaries autonomously: web injection realization (WB-05) triggered selection of the data expression's database instrument via K(web, data) = 0.85; host chain realization (HO-01 → HO-19 → HO-25) triggered exploit proposal generation via K(smb, vuln) = 0.90. Neither transition was explicitly programmed. Both followed from the coupling energy in Φ_fiber.

The empirical results are preliminary — three lab targets, one operator, four cycles. The formal framework is the contribution; the engagement demonstrates that the coupling mechanism produces the expected selection behavior on real hardware. A fuller evaluation across diverse environments is needed before the coupling constants can be treated as anything other than calibrated estimates.

---

## 1. Introduction

### 1.1 What prior work established

Work 3 [3] defined the SKG substrate: tri-state encoding Σ ∈ {R, B, U}, a projection operator π mapping observations to state, a field energy E(S, A) = |{n ∈ A : Σ(n) = U}| counting unresolved conditions, and a gravity selection mechanism argmax_I Φ(I, t) directing instruments toward maximum entropy reduction. The mechanism worked. Ten attack paths were realized on a live network without human guidance.

Work 4 (prior version) introduced the unified field functional L(F) over five canonical field objects — Field Observation, Field Local, Field Coupling, Field Fiber, Field Cluster — and showed that the Work 3 quantities are derived projections under it. Fiber-driven gravity Φ_fiber extended the selection mechanism with coupling opportunity and decoherence load. The pearl manifold was identified as memory curvature. These results stand and are not revisited here.

### 1.2 What was left implicit

Both prior papers were written from inside a single deployment: a cybersecurity engagement against network targets. "Host", "web", "SMB", "data" appear in those papers as if they were natural categories of the substrate. They are not. They are namespaces — conventions for partitioning the wicket space that the substrate carries as metadata but does not process.

The substrate has no concept of "web". It has field locals indexed by (workload_id, domain_label), instruments with wavelengths over domain-labeled wickets, and a gravity field that selects by potential. The domain label is annotation. The substrate's rules are identical across all annotations.

This matters because the practical consequence of domain-agnosticity is architectural: new observation capabilities extend SKG by adding a domain expression, not by modifying the substrate. The substrate does not need to know what an IoT firmware scanner does. It needs to know W(firmware_scanner), c(firmware_scanner), and γ(firmware_scanner). Everything else is in the expression.

### 1.3 What this paper does

Section 2 defines the domain expression formally and describes the toolchain as its runtime form. Section 3 covers instruments as domain-specific measurement devices and the adapter as the only domain-specific component that touches the substrate's event format. Section 4 presents the field functional in domain-agnostic terms. Section 5 defines the inter-expression coupling law and the two coupling mechanisms — intra-target and cross-target — that connect expressions. Section 6 is fiber-driven gravity formulated over the union of all active expression locals. Section 7 is the decoherence criterion and protected-state theorem. Section 8 is the pearl manifold as memory curvature. Section 9 is the empirical engagement. Section 10 is implementation status, limitations, and what an honest assessment of the empirical claims looks like.

---

## 2. Domain Expression Architecture

### 2.1 What the substrate provides vs. what an expression provides

The substrate provides:

- Tri-state encoding: Σ ∈ {R, B, U} per field local
- Support engine: aggregation of bounded observations into support vectors
- Projection operator: π mapping events to state
- Field functional: L(F) over all active locals
- Gravity field: argmax_I Φ_fiber(I, t) over available instruments
- Pearl manifold: preserved history of field transformations
- WorkloadGraph: cross-target prior propagation

None of these components reference a specific domain. No substrate code path is conditional on the domain label. The label is carried as metadata and used for two purposes: routing events to the correct expression's projection, and looking up K(Δ_a, Δ_b) for the coupling calculation. Nothing else.

A domain expression provides everything the substrate needs to observe a specific class of target:

**Definition 1 (Domain Expression).** A domain expression is a four-tuple Δ = (Ω, Ι, Α, Π) where:

- **Ω** is a wicket catalog: a finite set of named condition identifiers {ω₁, ..., ωₙ} with precondition semantics. Ω defines the expression's wicket namespace. All identifiers carry a domain-specific prefix (HO-, WB-, DP-, etc.) that ensures namespace isolation across expressions.

- **Ι** is an instrument set: measurement devices {I₁, ..., Iₖ}, each a triple (W(Iₖ), c(Iₖ), γ(Iₖ)) — wavelength (which conditions it can resolve), cost (resource consumption), and confidence model. The gravity field sees only this triple.

- **Α** is an adapter: a function from raw instrument output to a sequence of `obs.attack.precondition` events. This is the expression's only contact with domain-specific output formats — nmap XML, HTTP response bodies, binary reports. Once the adapter emits a canonical event, the substrate processes it identically to any other event from any other expression.

- **Π** is a projection: a function from accumulated support vectors over Ω to tri-state assessments and attack path scores. The projection applies the substrate's StateEngine and CollapseThresholds — it does not implement its own evaluation logic.

### 2.2 Expression independence

Two expressions Δ_a and Δ_b are expression-independent if Ω_a ∩ Ω_b = ∅. All currently deployed expressions are expression-independent. A web observation cannot directly collapse a host wicket. The only cross-expression channels are the coupling law K(Δ_a, Δ_b), fiber-cluster structure spanning expression locals for the same identity, and cross-target propagation through the WorkloadGraph. None of these directly collapse state; they change which measurements are gravitationally attractive next.

The repository currently contains toolchains for the following expressions. Only a subset are daemon-native in the live runtime; the rest are auxiliary or operator-invoked even though their projectors are now discovered through the same registry-driven loader:

| Expression | Namespace | Wicket count |
|---|---|---|
| host | HO-, FI-, PI- | 49 |
| web | WB- | 20 |
| ad-lateral | AD- | 25 |
| container-escape | CE- | 14 |
| aprs | AP- | 14 |
| data | DP-, DE- | 26 |
| nginx | NX- | 12 |
| supply-chain | SC- | 12 |
| iot-firmware | IF- | 15 |
| ai-target | AI- | 20 |
| binary | BA- | 6 |
| metacognition | MC- | 8 |

221 named conditions. Four were active in the validation engagement.

### 2.3 The toolchain as the expression runtime

In the deployed substrate, each domain expression is packaged as a toolchain directory:

```
skg-{domain}-toolchain/
  contracts/catalogs/          # Ω: wicket catalog (JSON)
  adapters/{instrument}/       # Α: one adapter per instrument
  projections/{domain}/run.py  # Π: projection engine
  forge_meta.json              # expression manifest
```

The substrate discovers available expressions by enumerating toolchain directories. Adding a new domain expression requires implementing one toolchain. No substrate code changes. The consequence is concrete: someone who wants to add IoT firmware analysis to SKG writes a catalog of IF- wickets, an adapter that reads binwalk output, and a projection that applies the substrate's existing StateEngine to firmware-specific events. They do not touch gravity_field.py or the kernel.

### 2.4 The metacognition expression

One expression is unusual: metacognition (MC-01 through MC-08) has SKG's own coverage gaps as its observation space. MC-03 is "coverage gap detected — service class with no catalog wickets." MC-05 is "contradictory evidence without reconciliation." These are conditions about the substrate's own epistemic state, not about a target.

The runtime now separates substrate metacognition from cognitive generation artifacts. A realized substrate-side coverage gap is recorded as `MC-03` in the forge pipeline and can stage an operator-reviewed toolchain-generation proposal. When forge actually produces a candidate artifact, the runtime emits a separate `CP-01` cognitive signal. `MC-03` therefore remains about the substrate's own ignorance; `CP-01` records the act of candidate generation. `CP-01` is currently a runtime signal rather than a full projected expression, but the feedback loop is live.

---

## 3. Instruments as Domain-Specific Measurement Devices

### 3.1 What the gravity field knows about an instrument

The gravity field does not know what nmap does. It knows W(nmap) = {HO-01, HO-03, HO-19, HO-25, ...} — the set of wicket identifiers this instrument can produce observations for. It knows c(nmap) — cost. It knows γ(nmap) — confidence. That is all.

The domain label on the wickets in W(nmap) is visible as metadata. The selection mechanism does not inspect it. An instrument from the host expression and an instrument from the web expression compete for selection by the same formula over the same field state. The winner is whichever has higher Φ_fiber.

This is not an architectural accident. It is the operational consequence of domain-agnosticity: the gravity field routes toward unresolved structure regardless of which expression produced the observations that define that structure.

### 3.2 The adapter as the only domain boundary

The adapter Α is the single component in a domain expression that touches domain-specific content. Raw instrument output — an nmap XML file, an HTTP body, a binary analysis report — enters the adapter. Canonical `obs.attack.precondition` events exit it:

```json
{
  "type": "obs.attack.precondition",
  "payload": {
    "wicket_id":    "HO-19",
    "target_ip":    "192.168.122.153",
    "workload_id":  "host::192.168.122.153",
    "domain":       "host",
    "status":       "realized",
    "confidence":   0.95,
    "evidence":     "port 445/tcp open — smb",
    "decay_class":  "operational",
    "source":       "nmap"
  }
}
```

Once emitted, this event is processed identically to any other `obs.attack.precondition` event from any expression. The SupportEngine, StateEngine, and projection operator apply the same formulas. The domain label is carried for routing and coupling lookup, nothing else.

The adapter is where the reverse engineering lives. Parsing `smb-vuln-ms17-010: State: VULNERABLE` into a HO-25 realization with confidence 0.95 requires knowing what that NSE output means. The substrate does not know. The adapter does. The clean boundary means that an incorrect adapter mapping — the wrong wicket ID, the wrong confidence — is localized. It does not corrupt the substrate's state model.

### 3.3 Confidence calibration is domain-agnostic

Each instrument carries γ(I). The substrate's calibration mechanism computes empirical precision — the fraction of observations that were not reversed by subsequent observations — and adjusts γ downward when the instrument is overconfident:

    γ_calibrated(I) = α × γ_empirical + (1−α) × γ_hand_tuned

This formula applies to any instrument from any expression. A web_collector with γ_hand_tuned = 0.75 and empirical precision 0.533 receives a 28.9% correction. An SSH collector with γ_hand_tuned = 0.90 and empirical precision 0.80 receives an 11.1% correction. The correction does not know or care which domain the instrument belongs to.

This is a small validation of the domain-agnostic design: instrument quality is a property of the measurement device, not of the observation space. The same failure mode — overconfidence — is corrected by the same mechanism regardless of domain.

In the current runtime, this calibration is materialized as per-source factors in `$SKG_STATE_DIR/calibration.json`, produced by `skg calibrate` and loaded by `SensorContext` before history and graph priors are blended.

---

## 4. The Field Functional Over Domain Expressions

### 4.1 Field objects are domain-neutral

The five canonical field objects carry domain labels as annotation, not as structure.

**Field Observation** O = (ι, m, φ, τ, γ, C, δ): a bounded measured contribution from one instrument execution. ι is domain-specific (it names an instrument in a specific expression). The observation structure — support vector, temporal placement, dissipation class — is identical regardless.

**Field Local** L_i = grouping of observations by (workload_id, domain_label). The domain_label scopes the local to one expression's namespace. Two locals with different domain labels on the same target are distinct field objects. Their interaction is entirely through coupling energy, not through shared state.

**Field Coupling** K(L_i, L_j): inter-local influence. When L_i and L_j are in the same expression, K is intra-expression. When they are in different expressions, K is the inter-expression coupling law defined in Section 5.

**Field Fiber** F = (m, Λ, ρ, τ, coherence, tension): a strand of preserved structure. The domain participation set Λ identifies which expressions contribute. A fiber through a target observed by host, web, and data expressions has |Λ| = 3.

**Field Cluster** C = {F₁, ..., Fₖ}: all fibers for one anchor identity. The cluster is the total measured structure of a target across all active expressions.

### 4.2 The field functional

    L(F) = Σᵢ E_self(Lᵢ) + Σᵢ﹤ⱼ E_couple(Lᵢ, Lⱼ) + D(F) + κ(F)

- **Σᵢ E_self(Lᵢ)**: over all locals from all active expressions. E_self(Lᵢ) = U_m(Lᵢ) + E_local(Lᵢ) + E_latent(Lᵢ). The sum spans the full expression union.

- **Σᵢ﹤ⱼ E_couple(Lᵢ, Lⱼ) = K(Lᵢ, Lⱼ) × (E_local(Lⱼ) + U_m(Lⱼ))**: when Lᵢ and Lⱼ are in different expressions, K comes from the inter-expression table. When they are in the same expression, K is the intra-expression coupling.

- **D(F) = Σᵢ D(Lᵢ)**: total dissipation across all expressions. Decoherence and contradiction loads use the same formula regardless of which expression's local is being evaluated.

- **κ(F)**: curvature from structural gaps. The metacognition expression's unresolved wickets contribute explicitly to κ — MC-03 (coverage gap) is a recognized fold type in the field.

The Work 3 field energy E(S, A) = |{n ∈ A : Σ(n) = U}| is recovered as the leading term of L(F) restricted to a single expression's applicable locals, dropping coupling, dissipation, and curvature. The wicket count is the zeroth-order, single-expression, zero-coupling approximation.

**Proposition 1 (Boundedness).** L(F) ≥ 0 for all field states F. L(F) = 0 iff all locals from all expressions are fully resolved, all coupling energy has collapsed, and no folds are active.

*Proof sketch.* Each term is non-negative by construction. E_couple(Lᵢ, Lⱼ) = K × (E_local(Lⱼ) + U_m(Lⱼ)) vanishes when Lⱼ is fully resolved regardless of K — cyclic coupling structures do not prevent L(F) = 0 as long as all locals resolve. The H¹ obstruction from Work 3 governs whether full resolution is achievable; it does not affect sign. ∎

**Proposition 2 (Monotone Reduction).** A non-contradictory observation with positive realized or blocked support contribution to any local in any expression produces L(F ∪ {O}) ≤ L(F).

*Proof sketch.* A positive contribution reduces U_m(Lᵢ), which reduces E_self(Lᵢ). Coupling terms E_couple(Lⱼ, Lᵢ) for all Lⱼ coupled to Lᵢ decrease as U_m(Lᵢ) decreases. No term increases from a non-contradictory observation. The contradictory case — which can increase D(F) — is excluded by the statement. ∎

*Falsifiability.* Both propositions are falsified by any logged field state (available in `evidence/figures/A_energy.json` and `H_math.json`) that violates their conditions. The empirical record contains no such violation across all engagement cycles.

### 4.3 Runtime instantiation

The canonical runtime implementation of the field functional is `skg/kernel/field_functional.py:field_functional_breakdown()`. `skg/kernel/field_local.py` delegates to it for compatibility. Field locals are constructed from `KernelStateEngine.states_with_detail()` output by `build_field_locals()`, and the canonical breakdown now accepts optional fiber-cluster context so the same implementation covers local self-energy, coupling, dissipation, curvature, and cluster-aware fiber load. L(F) is logged to `evidence/figures/A_energy.json` on each gravity cycle.

---

## 5. Inter-Expression Coupling

### 5.1 Two coupling mechanisms

The substrate connects domain expressions through two distinct mechanisms:

**Intra-target inter-expression coupling**: K(Δ_a, Δ_b) applies to locals for the same target. When L_web and L_data both reference target T, K(web, data) = 0.85 creates coupling energy at L_data when L_web has realized structure. This drives depth — the substrate pursues more conditions on the same target across different expressions.

**Cross-target coupling** via WorkloadGraph: Kuramoto-inspired prior propagation across distinct targets. When target A realizes a condition, the WorkloadGraph propagates a prior to the same condition type on target B, weighted by the bond strength between A and B (same_identity: 0.85, credential_overlap: 0.45, same_subnet: 0.20). This drives breadth — related targets inherit elevated priors. This mechanism is domain-agnostic in the same sense as the rest of the substrate: it propagates by wicket pattern and relationship type, not by domain label.

### 5.2 The inter-expression coupling table

K(Δ_a, Δ_b) encodes how much realized structure in expression Δ_a contributes to the field potential at expression Δ_b on the same target:

| Source expression | Target expression | K | Basis |
|---|---|---|---|
| credential | host | 0.95 | Confirmed credential is a direct precondition for SSH auth — structural dependency |
| credential | web | 0.80 | Confirmed credential enables web auth — strong but not entailed |
| smb | vuln | 0.90 | Exposed SMB service implies NSE vulnerability scan applicability |
| web | data | 0.85 | SQL injection confirmed implies database accessibility |
| web (cmdi) | host | 0.90 | Command injection gives OS-level execution |
| container-escape | host | 0.85 | Container escape lands on the host |
| host | container-escape | 0.60 | Host presence enables container discovery |
| host | ad-lateral | 0.80 | Host foothold enables lateral movement |
| ad-lateral | host | 0.70 | Lateral pivot lands on a new host |

K = 0.90–0.95: structural dependency — target expression's conditions require source expression's realization. K = 0.65–0.89: strong implication — source realization makes target conditions gravitationally accessible. K = 0.10: default (no coupling data; effectively decoupled).

These values began as hand-tuned judgments on two engagements. In the deployed runtime they are now externalized to `config/coupling.yaml`, hot-reloaded by `skg/core/coupling.py`, and retrospectively learnable from engagement snapshots. They are still operator-curated by default rather than online-learned. Whether they generalize to environments other than the validation lab remains an empirical question.

### 5.3 Coupling energy as the cross-expression bridge

    E_couple(Lᵢ, Lⱼ) = K(Δ_a, Δ_b) × (E_local(Lⱼ) + U_m(Lⱼ))

adds to L(F) at Lⱼ (expression Δ_b) when Lᵢ (expression Δ_a) has realized structure. The practical effect: when WB-05 (SQL injection) is realized on a target, the coupling term adds 0.85 × U_m(L_data) to the field potential of the data expression's database instrument. The gravity field, selecting argmax_I Φ_fiber(I, t) over all instruments from all expressions, selects the database instrument next — not because of a sequencing rule, but because the coupling energy made it the highest-potential unresolved local.

This is how multi-domain attack chains emerge without explicit chaining logic. The coupling table is the knowledge base. The field functional is the inference engine.

### 5.4 Propagation selectivity by relationship type

Cross-target propagation is selective by relationship type. Not all expression conditions propagate through all bond types:

- `same_identity` (0.85): all expressions propagate — the same host confirmed via one workload propagates to the same host in all other workloads
- `credential_overlap` (0.45): ad-lateral and aprs — shared credentials couple AD and network protocol conditions
- `same_subnet` (0.20): aprs and container-escape — container networks and protocol signals propagate weakly through subnet adjacency
- `network_adjacent` (0.15): aprs only

The selectivity reflects the claim structure. A container escape on host A does not propagate AD lateral movement priors to host B via `same_subnet` — AD trust does not follow subnets. The selectivity is asserted as domain knowledge, not derived.

---

## 6. Fiber-Driven Gravity Across Domain Expressions

The Work 3 selection mechanism Φ(I, t) = |{n ∈ W(I) ∩ A(t) : Σ(n) = U}| / c(I) selects the instrument covering the most unknown wickets per unit cost. It is correct when each local's state is well-approximated by a scalar, coupling is absent, and decoherence is zero. In a multi-expression deployment none of those conditions hold.

Fiber-driven gravity follows the gradient of L(F) with respect to the instrument schedule:

    G_pull(t) ~ −∂L(F)/∂(instrument schedule at t)

Three terms contribute:

**Term 1: Fiber tension**

    Φ_tension(I, t) = Σᵥ tension(Fᵥ) × coherence(Fᵥ) × 𝟙[W(I) ∩ Fᵥ ≠ ∅] / c(I)

A high-tension, high-coherence fiber (clearly present and clearly unresolved) contributes maximally. The fiber may span multiple expressions — an instrument from any expression whose wavelength intersects any local in that fiber contributes to Φ_tension.

**Term 2: Coupling opportunity**

    Φ_couple(I, t) = Σⱼ K(·, Lⱼ) × U_m(Lⱼ) × 𝟙[W(I) ∩ Lⱼ ≠ ∅] / c(I)

When Lᵢ is realized in expression Δ_a and Lⱼ in expression Δ_b is coupled via K(Δ_a, Δ_b) > 0, any instrument in Δ_b with wavelength intersecting Lⱼ receives a coupling bonus. This is where cross-expression selection occurs: a realized web local elevates the potential of data instruments via K(web, data).

**Term 3: Decoherence load**

    Φ_decoherence(I, t) = Σᵢ D(Lᵢ) × 𝟙[W(I) ∩ Lᵢ ≠ ∅] / c(I)

Contradictory locals in any expression attract instruments. The substrate routes toward measurement conflicts before they accumulate.

Combined, the formal expression remains:

    Φ_fiber(I, t) = [Φ_tension + Φ_couple + Φ_decoherence] × penalty(I, t) / c(I)

The current runtime uses a hybrid realization of this formula. When an instrument intersects a usable explicit fiber cluster, cross-expression influence is carried by matched fibers and cluster structure, and the generic additive Φ_couple term is suppressed to avoid double counting. When no usable cluster context exists, the scheduler falls back to the older local-plus-coupling approximation. Selection is argmax_I Φ_fiber(I, t) over all instruments from all registered expressions.

**Proposition 3 (Work 3 Recovery).** Φ(I, t) from Work 3 is Φ_fiber(I, t) under: unit coherence and tension per unknown wicket, K = 0 everywhere, D = 0 everywhere, penalty = 1, one active expression.

*Proof.* Under these conditions Φ_tension reduces to counting unknowns in W(I) ∩ A(t); Φ_couple = 0; Φ_decoherence = 0. The result is the Work 3 count divided by c(I). ∎

Work 3 selection is the flat-space, zero-coupling, coherence-homogeneous, single-expression limit of Φ_fiber.

### 6.1 Memory curvature from the pearl manifold

The pearl manifold computes a wavelength_boost from reinforced neighborhoods — wickets in W(I) that appear repeatedly in the pearl ledger for the same (identity_key, domain_label). The boost represents prior informativeness:

    Φ_effective(I, t) = Φ_fiber(I, t) × (1.0 + wavelength_boost / 10.0)   when boost ≥ 1.0
                      = Φ_fiber(I, t) + wavelength_boost                    when boost < 1.0

The factor of 10.0 normalizes the boost range (0–10) to a multiplicative coefficient in [1.0, 2.0]. Strong memory reinforcement can double the potential for an instrument on a target where prior sweeps were highly informative. It cannot override direct field observation — the multiplier is bounded at 2×.

**Runtime instantiation.** The canonical implementation is `skg/kernel/field_functional.py:phi_fiber_breakdown()`, with `skg/kernel/field_local.py` delegating to it. The wavelength_boost comes from `skg/kernel/pearl_manifold.py:wavelength_boost()`. Kernel selection in `skg/kernel/engine.py` passes explicit fiber clusters into the breakdown when available, and gravity cycle execution in `skg-gravity/gravity_field.py` combines the resulting potential with the reuse penalty.

---

## 7. The Decoherence Criterion

### 7.1 What it is and why it is not a threshold trick

The decoherence criterion answers when re-observation is wasteful. The answer is domain-agnostic: the same four conditions determine stability whether the local is HO-01 (host reachable), WB-02 (web authenticated), or DP-10 (database accessible).

**Definition 2 (Protected State).** A field local Lᵢ in any expression is protected iff all four conditions hold simultaneously:

1. **C ≥ 0.7**: compatibility score above the single-instrument-dominance threshold
2. **φ_contradiction < 0.15**: less than 15% contradictory mass
3. **φ_decoherence < 0.20**: less than 20% decayed mass
4. **n ≥ 2**: at least two independent observation cycles

The conditions are jointly necessary. This is not an implementation detail — it is the content of the criterion. High coherence alone is not sufficient: a state confirmed by one instrument class in one cycle (n=1) is single-source, not protected. Two cycles with 20% contradiction is contested, not protected. Only simultaneous satisfaction of all four conditions constitutes protection. The reason: each condition eliminates a different failure mode.

### 7.2 Threshold derivation

The four thresholds are calibrated on operational data, not derived from first principles. Each has a structural motivation that the calibration number approximates.

**C ≥ 0.7.** Compatibility score = 1 − (dominant_family_weight / total_weight) + 0.1 × (n_families − 1). C ≥ 0.7 at n=2 implies no single instrument family contributes more than 40% of total support mass. This is a diversity condition: a state confirmed only by nmap, or only by SSH collection, should not be treated as protected because the instrument may have a systematic blind spot that repeated application cannot detect.

**φ_contradiction < 0.15.** With n=2 at confidence 0.8 (M ≈ 1.6), a single full-confidence opposing observation cannot flip the dominant polarity: 0.15×1.6 + 0.95 = 1.19 < 0.85×1.6 = 1.36. The bound is tight for minimum-confidence instruments (γ = 0.5, M ≈ 1.0), which is why the four conditions must be jointly satisfied — the contradiction bound alone is insufficient at minimum confidence.

**φ_decoherence < 0.20.** Three decay classes — ephemeral (TTL = 4 hours), operational (TTL = 24 hours), structural (TTL = 168 hours) — are currently configured identically across expressions in `config/coupling.yaml`. Expired observations are excluded from active support mass on access by the SupportEngine rather than left as indefinitely decayed residue. The 0.20 bound therefore applies to active evidence remaining within TTL and to temporal decay nearing expiry.

**n ≥ 2.** n counts gravity cycles, not instrument executions. A single sweep producing multiple observations is still n=1. This prevents a target briefly in an unusual state from being classified as protected on one informative sweep.

*Theoretical gap.* At minimum instrument confidence (γ = 0.5) with marginal values at each threshold boundary (C = 0.7, φ_contradiction = 0.14, φ_decoherence = 0.19, n = 2), a single adversarial full-confidence opposing observation could theoretically flip the state. This gap does not arise in the deployed configuration (all instruments have confidence ≥ 0.7 for their applicable wickets) but should be noted for generalization to lower-confidence sensor environments.

### 7.3 Field-geometric interpretation

A protected local is a local minimum of L(F) restricted to Lᵢ that is stable under any single instrument perturbation:

1. C ≥ 0.7: the minimum is in the interior of a stable basin, not near a boundary
2. φ_contradiction < 0.15: no significant opposing force is present to be reinforced
3. φ_decoherence < 0.20: the minimum has not decayed toward the unresolved region
4. n ≥ 2: the minimum is determined by multiple independent constraints — one observation is one vote against at least two

**Proposition 4 (Protected = Stable Local Minimum).** A field local in any expression satisfying Definition 2 is stable under any single instrument perturbation: no instrument I with W(I) ∩ Lᵢ ≠ ∅, in any single execution, changes the collapsed state Σ(Lᵢ).

*Proof sketch.* Under all four conditions, the dominant support component (φ_R or φ_B) satisfies (dominant component) > (all other components + maximum perturbation from any single observation) for γ ∈ [0.7, 0.95]. See §7.2 for the explicit bound and the identified gap at γ = 0.5. The proof holds domain-agnostically because the support accumulation formula and collapse thresholds are identical across all expressions. ∎

*Falsifiability.* Proposition 4 is falsified by any local in any expression that satisfies all four conditions at cycle τ and changes its collapsed state at cycle τ+1 under a single instrument execution. This is directly testable against the cycle evidence artifacts in `artifacts/cycle_evidence/`. No such falsification exists in the current engagement record — but the engagement record is three targets and four cycles. This is consistent with Proposition 4, not strong evidence for it.

### 7.4 Temporal folds

A protected-state temporal fold arises when evidence ages toward or past TTL and the local no longer satisfies the protection criterion. In the current runtime, expired observations are removed from active support aggregation on access, and temporal fold detection uses the same decay-class map as the support engine. The local is no longer protected. Gravity pulls toward re-observation. This is the Work 3 temporal fold mechanism, derived from the decoherence criterion rather than stated as a separate rule. The mechanism applies identically across all expressions — an aging web injection finding and an aging host reachability finding both generate temporal folds through the same decay logic.

---

## 8. Pearl Manifold as Field Geometry

A pearl records a transformation of L(F): a state collapse, a proposal lifecycle event, a significant projection change. The pearl ledger is the append-only history of field transformations across all domain expressions.

Pearl clusters — groups of pearls for the same (identity_key, domain_label) where the same wickets recur — remain the memory-curvature side of the geometry. A cluster of pearls in the host expression repeatedly realizing HO-01, HO-19, HO-25 for the same target represents prior informativeness, and `wavelength_boost` aggregates this into a bounded curvature modifier for Φ_effective.

The runtime now also computes explicit multi-expression fiber clusters for the same identity key in the topology layer and passes them into kernel selection. A fiber with |Λ| > 1 is therefore no longer purely aspirational: cross-expression clusters participate directly in Φ_tension and in the canonical field-functional breakdown. The remaining gap is hybridization, not absence. When usable cluster structure exists, fibers carry cross-expression pull; when it does not, the scheduler falls back to generic coupling.

The pearl manifold is still important because it preserves historical informativeness rather than only live structural pull. The current runtime therefore uses both: explicit fibers for present cross-expression geometry and pearl neighborhoods for bounded memory curvature.

---

## 9. Empirical Validation

### 9.1 The honest framing

Three lab targets. One operator (the author). Four gravity cycles. No comparison baseline.

These are preliminary results. They demonstrate that the coupling mechanism produces the expected instrument selection behavior — the gravity field selected database instruments after web injection realization, selected exploit proposals after vulnerability confirmation — and that the field functional values stay non-negative and decrease monotonically for non-contradictory observations. They do not demonstrate that SKG outperforms any alternative approach, or that the coupling constants generalize beyond this environment, or that the decoherence thresholds are correctly set for diverse sensor configurations.

The purpose of this section is to show that the mechanism works in a concrete case, not to make strong empirical claims. Stronger empirical claims require more targets, more operators, and comparison baselines.

### 9.2 Engagement environment

| Target | Active expressions | Services |
|---|---|---|
| DVWA 172.17.0.3 | web, data | HTTP/80, MySQL/3306 |
| Metasploitable 2 172.17.0.2 | host, web, data | FTP/21, SSH/22, HTTP/80, MySQL/3306 |
| Windows Server 2008 R2 192.168.122.153 | host | SMB/445, HTTP/80, Tomcat/8282, RDP/3389 |

Windows 2008 R2 was confirmed independently by nmap NSE to carry CVE-2017-0143 (EternalBlue / MS17-010). DVWA was configured with default credentials and all injection vulnerabilities enabled.

### 9.3 Cross-expression selection: web to data

The DVWA target produced the cross-expression coupling case. The web expression auth scanner realized WB-01 (HTTP service), WB-02 (credentials valid: admin/password), and WB-05 (SQL injection confirmed). On WB-05 realization:

    E_couple(L_web, L_data) = K(web, data) × U_m(L_data) = 0.85 × 1.0 = 0.85

added to the data expression's local for DVWA's MySQL backend (U_m ≈ 1.0, all data wickets unresolved). The gravity field evaluated all available instruments and selected the SQL profiler from the data expression next. The profiler realized DP-10 (source reachable) and DP-02 (schema structure confirmed).

The web injection coupling chain:

    WB-05 (web) → K(web, data) = 0.85 → DP-10 realized (data)

was traversed without any explicit "after SQLi, check the database" instruction. The coupling energy made the data local the highest-potential unresolved structure in the field.

The web expression also realized WB-07 (command injection, ping utility) and WB-08 (XSS). The K(cmdi, host) ≈ 0.90 coupling generated proposal `4944c6a9` — `exploit_web_cmdi_to_shell_v1` — at confidence 0.94 without an additional host expression instrument execution.

### 9.4 Single-expression chain: EternalBlue

The Windows target produced the intra-expression coupling case. The host expression's nmap instrument traversed the three-local chain in a single execution:

    HO-01 realized: TCP echo on port 445 — host reachable
    HO-19 realized: port 445/tcp open smb — SMB service exposed
    HO-25 realized: smb-vuln-ms17-010 NSE output: State: VULNERABLE

Coupling energies K(host, smb) = 0.80 and K(smb, vuln) = 0.90 were active throughout but the single nmap execution happened to traverse all three locals at once because W(nmap) covers all three wickets and all three were resolvable from one scan. Gravity selected nmap because the coupling energy between the Windows target's unresolved SMB and vuln locals was the highest-potential cluster in the field at cycle 2 (the target was unreachable at cycle 1).

Proposal `c9c5ea6a-850` — `exploit/windows/smb/ms17_010_eternalblue` against 192.168.122.153 — was generated at confidence 0.95.

**Diagnostic value.** Before the coupling structure was implemented, this path failed silently for three reasons: port 445 detection did not emit HO-19, NSE VULNERABLE output emitted HO-11 (wrong wicket ID) rather than HO-25, and the attack path `host_network_exploit_v1` was absent from the dispatch map. Under a flat wicket model these appear as three unrelated bugs. Under the coupling framework they are structurally identical: three broken arcs in the chain L_reachable → L_smb → L_vuln → proposal. The coupling structure named the problem precisely; diagnosis followed directly.

### 9.5 Field functional behavior

Across four cycles and three targets:

- **L(F) non-negative throughout**: no violation of Proposition 1. All field functional values in `evidence/figures/H_math.json` are ≥ 0.
- **Monotone reduction for non-contradictory observations**: consistent with Proposition 2. No non-contradictory observation produced an increase in the per-target field functional value.
- **Decoherence criterion**: HO-01, HO-19, HO-25 satisfied all four conditions after cycle 2 (C ≈ 0.95, φ_contradiction ≈ 0, φ_decoherence ≈ 0.02, n = 2). These locals were not re-observed in cycles 3–4.
- **Memory curvature**: after cycle 2, wavelength_boost for nmap on the Windows target was 1.4× — the pearl manifold reinforced continued Windows observation because prior sweeps were highly informative.
- **124+ proposals generated** across all cycles, covering web, host, network exploit, and catalog growth domains.

### 9.6 Sensor calibration

The calibration mechanism corrected instrument confidence across all active expressions identically:

| Instrument | Expression | γ_hand_tuned | Empirical precision | Correction |
|---|---|---|---|---|
| web_collector | web | 0.75 | 0.533 | −28.9% |
| ssh_collect | host | 0.90 | 0.80 | −11.1% |
| nvd_ingester | host | 0.85 | 1.00 | +conservative |

The web_collector result — a 28.9% correction — is the calibration mechanism catching the exact failure mode it was designed for: an instrument that is meaningfully overconfident relative to its empirical performance.

In the current implementation, this calibration path is unified: `skg calibrate` writes the same file the runtime consumes, and the live sensor context reloads it automatically when the file changes.

---

## 10. Discussion

### 10.1 What the domain expression architecture changes in practice

**New observation capabilities are additive.** Someone who wants to add IoT firmware analysis implements one toolchain — a catalog of IF- wickets, an adapter that reads firmware analysis tool output, a projection that applies the existing StateEngine. The substrate still does not need domain-specific changes. The live runtime does still expect a discoverable projector layout and registry metadata for daemon-native scheduling, but it no longer requires edits to a hardcoded projector table for standard projector discovery.

**The coupling table is where domain knowledge enters.** No domain-specific logic lives in the substrate. All expert knowledge about which observations imply which others is encoded in K(Δ_a, Δ_b). This is where the architecture makes the knowledge base explicit and auditable. Someone reviewing a deployment of SKG can read the coupling table and see exactly what structural dependencies the system is asserting. They can disagree with K(web, data) = 0.85 and change it to 0.60. The substrate's behavior changes accordingly. The knowledge is not buried in code.

**Multi-domain attack chains are emergent, not programmed.** This is the practical consequence most worth noting. The web-to-database chain in the DVWA validation was not written anywhere as a rule. It emerged because K(web, data) = 0.85 makes the database local gravitationally interesting when SQL injection is confirmed. The same mechanism applies to any chain encoded in the coupling table. Chains not in the table do not emerge. This makes the substrate's reasoning transparent: if you want to understand why SKG selected an instrument, look at the coupling energy contributions to Φ_fiber.

### 10.2 What remains incomplete and what that means

**Fiber scheduling is still hybrid.** Explicit multi-expression fiber objects and clusters now participate in selection, but the runtime still keeps a fallback generic coupling path for targets where cluster structure is sparse or absent. The clean theoretical endpoint is a scheduler driven entirely by fiber geometry with coupling as a residual or derived quantity.

**Coupling constants are configurable and learnable, but not self-updating.** K values now live in `config/coupling.yaml`, hot-reload at runtime, and can be retrospectively estimated from engagement history. They are still operator-curated by default rather than automatically rewritten from live data. A stronger empirical basis requires more engagements and a reviewed application path.

**The empirical evaluation is thin.** Three targets, one operator, one lab environment. The coupling constants may be correct for this environment and incorrect for others. The decoherence thresholds (C ≥ 0.7, n ≥ 2) were sufficient here and have not been tested in noisy or adversarially instrumented environments. The calibration corrections (−28.9% for web_collector) are specific to this engagement's target set. These limitations are not failures of the framework; they are the current boundary of what has been validated.

**Metacognition is split but not fully projected.** `MC-03` now records substrate-side coverage gaps and can stage toolchain-generation proposals through forge; `CP-01` records when the cognitive pipeline actually produced a candidate artifact. What is still missing is a first-class projected cognitive expression with its own decay, projection, and coupling semantics.

**Decay is enforced semantically, but not yet narrated as its own event stream.** Expired observations no longer contribute support mass, and temporal folds see the same TTL map as the support engine. The remaining gap is auditability: the runtime does not yet emit a separate "decayed" event ledger when observations age out.

### 10.3 Publication posture

This is worth putting on arXiv as a preprint. The ideas are in the literature; others can engage with them. It is not ready for a top-tier peer-reviewed security conference. The evaluation is too thin, there is no comparison baseline, and the coupling constants need cross-engagement validation before the empirical claims can be made strongly.

The right venue for a full paper submission is New Security Paradigms Workshop (NSPW) or a formal methods in security workshop. NSPW explicitly values unconventional frameworks and does not demand large-scale empirical evaluations. The field functional formalization and decoherence criterion have enough formal content to be interesting there without requiring 50 targets.

The dual-use question should be addressed in any published version. This paper describes a system that autonomously realizes exploitation chains. The description is accurate. Acknowledging that explicitly, and situating the work in the context of authorized red team automation and defensive security research, is the correct posture.

### 10.4 Open questions

**Is the coupling table learnable from engagement history?** The current K values are assertions. The substrate records which expression realizations occur in which sequences. A retrospective analysis over multiple engagements could estimate K empirically as the conditional probability P(Δ_b realization | Δ_a realization, same target). This would replace expert opinion with data, at the cost of requiring diverse engagement data to estimate reliably.

**Does the decoherence criterion admit a decision-theoretic derivation?** The four conditions are structural constraints calibrated on operational data. Can they be derived from a decision rule — minimum description length for the measurement history, or a hypothesis test for stability of the collapsed state? A principled derivation would replace the empirical thresholds with something that generalizes to sensor configurations not represented in the current engagement data.

**Is the Kuramoto continuous limit recoverable?** Work 3 identified the Kuramoto connection as structural: the gravity web bond strengths correspond to Kuramoto coupling constants, and the tri-state encoding maps to oscillator phases. Whether the discrete fiber-driven selection mechanism converges to the Kuramoto differential equations as the discretization step goes to zero is open. If the limit holds, it would provide a continuous-time analysis framework for the gravity field's convergence properties.

**What is the right granularity for domain expressions?** Current expressions are coarse-grained by technology category (host, web, data). Finer expressions (Apache vs. Nginx within "web") would increase coupling precision at the cost of expression proliferation. The right granularity is an empirical question requiring cross-engagement data.

---

## 11. Conclusion

SKG is a domain-agnostic substrate. Web, host, data, and the other ten registered expressions are not components of it. They are expressions of it — bindings between the abstract field machinery and a particular observation space.

The formal statement: a domain expression is a four-tuple Δ = (Ω, Ι, Α, Π). The substrate processes field objects produced by any expression through identical mechanisms. The coupling table K(Δ_a, Δ_b) is where expert knowledge about structural dependencies between observation spaces enters the system. Cross-domain attack chains emerge from coupling energy, not from explicit rules.

The field functional L(F) = Σ E_self + Σ E_couple + D(F) + κ(F) is the energy function over the union of all active expression locals. Fiber-driven gravity Φ_fiber follows its gradient across all registered instruments from all expressions simultaneously. The decoherence criterion is a domain-agnostic stability theorem for field locals: four simultaneous conditions corresponding to a stable local minimum of L(F) under single-instrument perturbation.

The empirical validation demonstrates the mechanism on three targets: the gravity field crossed expression boundaries twice autonomously (web to data, host to exploit), driven by coupling energy. The EternalBlue coupling chain was traversed in one nmap execution. These results are preliminary and should be read as proof-of-mechanism, not as a comprehensive evaluation.

The architecture's practical consequence: domain expressions are additive. New observation capabilities extend SKG by implementing one toolchain. The substrate does not change, even though the live runtime still distinguishes five daemon-native expressions from a larger set of registry-discoverable auxiliary toolchains.

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

[9] Pearl, J. (1988). Probabilistic Reasoning in Intelligent Systems. Morgan Kaufmann.
