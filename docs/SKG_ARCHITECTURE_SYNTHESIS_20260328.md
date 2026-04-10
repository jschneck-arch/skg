# SKG Architecture Synthesis — Where We Are, Where We Were, and Why the Dissonance Exists
**Date:** 2026-03-28
**Source:** Full read of all 47 docs, 18 audit documents, 2 formal papers, session history, engagement reports

---

## 1. What SKG Is Supposed To Be

SKG is a **bounded measurement substrate**, not a scanner, not a database, and not a reporting tool. It models the informational uncertainty of a target system as a physical field and uses that field to decide which observations to take next.

The three sentences that define everything:

> "The boundary between what SKG knows and what it does not know is the most valuable thing it produces."

> "The substrate refuses to resolve indeterminacy through inference."

> "The gravity field routes toward unresolved structure regardless of which expression produced the observations that define that structure."

### The formal model (Work 3 → Work 4)

**Work 3** established the substrate formally:
- System S = (N, T, κ) — nodes, telemetry map, constraint surface
- Tri-state Σ(n) ∈ {R, B, U} — Realized, Blocked, Unknown. U is stable, carries no prior, never converges without new telemetry. B is not ¬R; it means constraint-suppressed.
- Projection π(S, P) = ⊤ (all required realized) | ⊥ (any blocked) | ? (otherwise)
- Field energy E = |{n ∈ A : Σ(n) = U}| — count of unresolved nodes
- Gravity Φ(I, t) = |W(I) ∩ A(t) ∩ {U}| / c(I) × penalty — expected entropy reduction per unit cost
- Bonds: same_host (1.0), docker_host (0.9), same_compose (0.8), shared_cred (0.7), same_domain (0.6), same_subnet (0.4)

Work 3 was the formalization of an already-operational system. Gravity emerged from deployment, not theory. The penalty (0.2 for prior failures), the α = 0.5 prior attenuation, the convergence criterion ε were all operational heuristics formalized in retrospect.

**Work 4** extended to domain-agnosticity and a richer field functional:
- Domain expression Δ = (Ω, Ι, Α, Π) — catalog, instruments, adapter, projection. The substrate has no concept of "web" or "host". It has field locals indexed by (workload_id, domain_label). Domain label is annotation.
- Five canonical field objects: Field Observation, Field Local, Field Coupling, Field Fiber, Field Cluster
- Field functional: L(F) = Σ E_self(Lᵢ) + Σ E_couple(Lᵢ, Lⱼ) + D(F) + κ(F)
- Fiber-driven gravity with three terms: Φ_tension, Φ_couple, Φ_decoherence
- Protected state criterion: C ≥ 0.7, φ_contradiction < 0.15, φ_decoherence < 0.20, n ≥ 2
- "This is how multi-domain attack chains emerge without explicit chaining logic. The coupling table is the knowledge base. The field functional is the inference engine."

Work 4's most important architectural claim: **the adapter is the only domain-specific component**. Everything else — support aggregation, collapse, projection, gravity — is domain-agnostic. An incorrect adapter mapping does not corrupt the substrate's state model.

### The closed loop

```
observe (φ_R, φ_B)           → instruments emit support vectors
collapse (threshold)          → substrate aggregates, state ∈ {R, B, U}
evaluate projections          → operator-facing views derived from field
measure informational deficit → E = |{n : Σ(n) = U}| + fold mass
compute gravity               → Φ(I,t) = expected ΔE / cost
generate proposals            → ranked candidate observations
operator selects action       → human gates all exploitation
repeat                        ← observations update state
```

The loop is closed. Nothing leaves without going through it. Nothing enters the observation plane without a complete custody chain (artifact path, hash, source pointer, timestamp).

### What the AI is

The AI is an operator assistant over the substrate. It can explain, summarize, draft, cluster, and narrate. It **cannot** assign state, invent measurements, collapse indeterminacy by inference, or move advisory output into the observation plane without custody. The distinction between `derived_advice`, `mutation_artifact`, `reconciliation_claim`, and `observed_evidence` is not bureaucratic — it is the enforcement mechanism that prevents the system from narrating instead of measuring.

---

## 2. How It Was Built

### Layer 0: The substrate (built correctly)

`skg/kernel/`, `skg/substrate/`, `skg/identity/`, `skg/temporal/` — these layers implement the formal model faithfully:

- `SupportEngine` aggregates observations with decay, compatibility weighting, and decoherence
- `StateEngine` collapses support vectors to tri-state
- `KernelStateEngine` computes field energy, instrument potential, φ_fiber
- `FieldLocal` implements U_m, E_couple, decoherence criterion, protected-state test
- `FiberCluster.G_cluster()` computes cluster-level gravity
- `PearlLedger` and `PearlManifold` preserve measurement history
- `Fold` types exist (structural, contextual, projection, temporal)
- `ObservationMemory` provides semantic recall with confidence calibration
- `WicketGraph` applies Kuramoto dynamics to the semantic space of wickets

These are real. The formal model is implemented. The substrate exists.

### Layer 1: The toolchains (built correctly but unevenly)

Twelve domain toolchains, each with catalog (wickets + attack paths), adapters (parse.py → obs.attack.precondition NDJSON), and projection (run.py → interp). The architecture is right. The domain-expression model from Work 4 is implemented.

What's uneven: AI, IoT Firmware, and Supply Chain have no adapters at all (catalog only). Nginx and web are template-generated with forge errors. Binary returns wrapped envelope instead of top-level payload. Metacognition uses obs.substrate.node instead of obs.attack.precondition. No two toolchains agreed on output format.

### Layer 2: The sensors (partially right)

`skg/sensors/` — sensor adapters exist for SSH, MSF, BloodHound, CVE, web, data, USB, GPU, process, boot, cognitive. The `SensorLoop` and `SensorContext` provide the runtime structure. Evidence-rank weighting and confidence calibration exist.

What's wrong: many sensors hand-roll event dicts instead of using the canonical envelope helpers. Some sensors (cognitive_sensor) are fully implemented but never registered in SensorLoop. Rate limiting is sleep-based and blocks the loop. Per-sensor timeouts are absent. SshSensor.run() ignores its supplied target config and reloads all targets from targets.yaml.

### Layer 3: The gravity runtime shell (built for Work 3, not Work 4)

`skg-gravity/gravity_field.py` (~8000 lines) is the main gravity loop. It was built when Work 3 was current. It operates on **target rows** — hydrated from discovery surfaces, enriched with nmap and config data, iterated in entropy order.

Work 4 says gravity should operate on **workload locals** — the union of active (workload_id, domain_label) pairs from measured projection state. The formal machinery for this exists (`FieldLocal`, `field_functional.py`, `phi_fiber()`), and gravity_field.py calls it — but as a **modifier** applied inside a target-row loop, not as the **primary scheduling unit**. The loop structure was never changed.

This is the root of the most important dissonance: **Work 4 machinery is real but applied as a refinement inside a Work 3 control shell.**

### Layer 4: The daemon and CLI (built for convenience, never demoted)

`skg/core/daemon.py` and `skg/cli/` were built to support operators. They introduced hybrid discovery surfaces (surface_*.json), target registries (targets.yaml + injected locals), and multiple invocation paths for gravity (subprocess, module load, inline). These were designed as convenience and bootstrap layers.

The problem: they were **never demoted** when measured state became available. Discovery surfaces got embedded into:
- Gravity target selection (gravity loads from hydrated surface_*.json, not from measured workload locals)
- Topology energy injection (surface domains/services promoted to realized WicketState without going through projection)
- Surface ranking (prefers cardinality over recency — older rich discovery snapshots win over newer measured state)
- Daemon /targets endpoint (built from config + discovery files, not measured projections)

This is the second major dissonance: **convenience bootstrap layers were never subordinated to measured state after measured state existed.**

### Layer 5: The topology (built from the wrong inputs)

`skg/topology/energy.py` builds field energy and fiber clusters. It imports and uses daemon's `_all_targets_index()` and `_identity_world()` — which are themselves built from hybrid target/discovery state. So topology inherits the authority problem from daemon.

Additionally, topology injects world states (from surface files and daemon world snapshots) directly as realized WicketState entries — mixing hybrid config-derived state with measured projection state in the same field energy computation.

---

## 3. Where the Dissonance Came From — The Origin Story

The dissonance is not random decay. It follows a clear causal arc.

### Cause 1: Work 3 control shell was never replaced by Work 4 control shell

Work 3 scheduled gravity over target rows. Work 4 defined field locals as the scheduling unit. The transition happened in the formal model but not in the runtime:

- `rank_instruments_for_target()` in `skg/gravity/selection.py` takes a target row (not field locals)
- `GravityScheduler.rank()` scores proposals, not locals
- `landscape.py` builds landscape from service-port heuristics, not measured domain membership
- The `FieldLocal` and `phi_fiber()` computations are correct but they are called inside `rank_instruments_for_target()` as modifiers to target-row entropy, not as replacement schedulers

**Why this happened:** Work 4 was added incrementally. `field_local.py`, `field_functional.py`, and the fiber gravity terms were added to the kernel. But gravity_field.py was not refactored to use them as primary inputs — they were integrated as additions. The target-row loop was kept as the control structure because replacing it would have required a larger refactor than was done at the time.

### Cause 2: Hybrid discovery surfaces were embedded before measured state existed

When the system was first built, there was no measured surface. Everything came from nmap scans, targets.yaml, and bootstrap inference. This was the only source of truth. The surface_*.json files, the target registry, the hydration logic — all were the only way to run gravity at all.

Measured state (projections, delta store, intel surface) was added later. But the hybrid bootstrap surfaces had already been wired into:
- Gravity's starting landscape
- Topology's world-state fibers
- The daemon's /targets API
- The CLI's surface commands
- Kernel engine caching (keyed on surface mtime)

When measured state arrived, it was added alongside the hybrid state, not replacing it. Both became authorities. Measured state was supposed to win but there were no enforcement points — no code that said "if measured local exists, use it; discard discovery surface data."

**Why this happened:** The system needed to bootstrap on every engagement run. Discovery surfaces were operationally necessary. The transition from "bootstrap layer" to "permanently subordinate to measured state" was never implemented with authority enforcement.

### Cause 3: The two tree problem — canonical and deploy mirror treated as peers

`/opt/skg/skg/` (canonical) and `/opt/skg/skg_deploy/` (deploy mirror) were casually edited in parallel. When gravity_field.py was fixed in the canonical tree, the deploy mirror still had the old version. When adapters were updated, only one tree got the fix. The `SKG_CANONICAL_RUNTIME_MAP.md` and `SKG_RUNTIME_UNIFICATION_PLAN.md` both document this explicitly:

> "If both trees are edited casually: semantics drift, runtime fixes land in one tree but not the other, operator behavior becomes hard to reason about."

This amplified every other source of dissonance by creating a second surface where old code lived while new code ran.

### Cause 4: Observation boundary was defined late, so old producers were never updated

The canonical event envelope (`obs.attack.precondition` with provenance fields, node_id, target_ip, domain, evidence_rank, pointer) was defined and implemented in `skg/sensors/__init__.py`. But it was added after the sensors were already built. web_sensor, ssh_sensor, adapter_runner, and gravity_field.py all pre-date the envelope contract and hand-roll their own event dicts.

The canonical helpers were made available but old producers were never updated. The contract became partially enforced — some events have full provenance, some don't. Downstream consumers (kernel adapters, feedback, delta) have to handle both, which means they never fully trusted any event.

**Why this happened:** The envelope contract was a retrofit. Retrofits require going back and updating all producers. That work was never done.

### Cause 5: Mixed projector shapes were accepted instead of enforced

Binary and data toolchain projectors return wrapped envelopes (payload nested under `payload` key). Host, web, AD lateral projectors return top-level payload dicts. This was accepted as a compatibility measure when the toolchains were onboarded.

But `skg/sensors/projector.py`, `skg/temporal/feedback.py`, and `skg/temporal/__init__.py` all need to handle both. The downstream delta store expects top-level. Feedback does partial unwrapping. The result: wrapped toolchains (binary, data) produce empty `attack_path_id` and `wicket_states` in the delta store, silently breaking temporal memory for those domains.

**Why this happened:** When toolchains were added, the short-term fix was to make the projector dispatch layer accept both shapes. The right fix — normalizing all projectors to one canonical output shape — was deferred and never done.

### Cause 6: Pearl recording was implemented for specific operations, not as substrate-wide append

Pearls are supposed to be an append-only record of all field state transformations — the substrate's memory. Work 4 is explicit: "Pearls preserve transformed field structure through time, not reports."

In practice, pearls are recorded in three places:
1. Gravity cycles (gravity_field.py:5477–5606)
2. Proposal lifecycle events (forge/proposals.py:104–146)
3. Fold resolution via operator action (core/daemon.py:4048–4065)

They are not recorded for:
- Direct projection ingestion (standalone projector runs outside gravity)
- Observation closure (feedback.py confirmation events)
- State transitions driven by CLI observe commands

**Why this happened:** Pearl recording was implemented as part of the gravity cycle because that's where the first implementation needed it. The broader mandate (record all field transformations) was documented in Work 4 but the back-fill into other state-change paths never happened.

### Cause 7: Multiple implementations were never consolidated

When new implementations were added, old ones were rarely removed:
- `exploit_proposals.py` — replaced by `exploit_dispatch.py`, never deleted
- `gravity_web.py` — replaced by `skg/graph/__init__.py`, never deleted
- `IdentityRegistry` (kernel/identities.py) — defined but replaced in practice by `parse_workload_ref()`, never activated or removed
- Three calibrators: `sensors/confidence_calibrator.py`, `intel/confidence_calibrator.py`, `sensors/context.py` — all compute calibration differently, none canonical
- Two energy modules: `skg/kernel/energy.py` and `skg/topology/energy.py` — overlapping semantics, both imported in places
- Three coupling tables: `skg/core/coupling.py`, `skg/substrate/bond.py`, `skg/graph/__init__.py` — same domain pairs with different K values

**Why this happened:** When an implementation is superseded, the path of least resistance is to add the new one and leave the old one. Removing old code requires finding all callers, verifying nothing depends on it, and accepting the risk of breaking something. Under deadline pressure, this work gets deferred indefinitely.

### Cause 8: The code audit (2026-03-26) found correctness bugs that are still unfixed

The `skg_code_audit_20260326.md` document contains four critical bugs reported with reproduction steps:

1. **Projection file overwrite across attack paths** (`projectors.py:33–378`): `project_events()` writes to `<domain>_<workload>_<run_id>.json` without `attack_path_id`, then `_prune_interp_siblings()` prunes by same prefix. Two attack paths for the same workload overwrite each other. Only the last path survives.

2. **Gap detection deduplicates globally by service, not per target** (`intel/gap_detector.py:237–432`): `detect_from_events()` keys by `service` only. Two targets with the same service only produce one gap entry. The forge under-reports coverage.

3. **Calibration pipeline split into three incompatible paths** (`sensors/confidence_calibrator.py`, `intel/confidence_calibrator.py`, `sensors/context.py`, `core/daemon.py`): Three different calibrators write to different files. The daemon loads none of them at boot. Calibration training is never applied.

4. **`same_domain` edges inferred from wrong semantics** (`skg/graph/__init__.py:565–600`): Falls back to `event.domain` (e.g., "host") when no AD domain found. Creates spurious same_domain edges on unrelated hosts. Work 3 defines `same_domain` as AD/LDAP membership, not event domain label.

These are reproducing correctness bugs, not architectural aspirations. They are unfixed.

---

## 4. The Current State, Accurately Described

### What is working correctly

- **Substrate kernel**: support aggregation, state collapse, decoherence criterion, field energy, field locals, field functional computation, protected-state criterion — all correct per Work 4 specification
- **Toolchains (mature ones)**: AD lateral (3 adapters), host (4 adapters), data (2 adapters), container escape, APRS — collection and projection work, golden tests pass
- **Tri-state semantics**: U, R, B are correctly implemented and preserved throughout the substrate. Unknown state is never collapsed by inference.
- **Proposal gating**: no exploit executes without operator approval via `skg proposals trigger`. This invariant holds.
- **Sheaf analysis**: H¹ obstruction detection for indeterminate paths is implemented and used.
- **Pearl manifold**: wavelength boosts from pearl history are correctly applied to gravity ranking.
- **Wicket graph**: Kuramoto dynamics on wicket semantic space correctly compute phase gradients and entangled pairs.
- **Empirical validation**: EternalBlue (MS17-010) at 0.95 confidence, DVWA SQLi/CMDi/XSS, full engagement path realization — the system works on live targets.

### What is partially working (formal model implemented but not governing)

- **Fiber-driven gravity**: `phi_fiber()` is computed correctly, but it's applied as a modifier inside a target-row loop, not as the primary scheduling unit. Work 4 field locals are not the scheduler's primary object.
- **Measured surface authority**: exists in `skg/intel/surface.py` and is correct, but gravity and CLI still use hybrid discovery surfaces as primary. Measured state can win in some paths but not all.
- **Identity model**: `parse_workload_ref()` and identity_key are used throughout pearls and temporal memory, but kernel engine and gravity selection still use target_ip as primary key. Identity is honored in memory layers but not in scheduling.
- **Pearl recording**: works well for gravity cycles and operator actions, but absent from direct projection ingestion, observation closure, and CLI observe commands.
- **Event envelope**: canonical helpers exist and work, but not all producers use them. Mixed provenance.

### What is broken (correctness bugs)

- **Wrapped interp → delta store**: wrapped projection envelopes (binary, data, web) produce empty delta snapshots. Temporal memory is broken for ~30% of toolchains.
- **Projection file overwrite across attack paths**: second attack path for same workload silently overwrites first.
- **SshSensor.run() reloads all targets**: ignores supplied single-target config, collects from entire targets.yaml.
- **Gap detection global, not per-target**: forge under-reports coverage gaps when multiple targets share a service.
- **Calibration pipeline dead**: three calibrators, none loaded at daemon boot. Training never applied.
- **same_domain edge inference**: creates spurious AD graph edges from event domain labels.
- **Workload subject resolution collapses to last :: token**: `binary::192.168.1.1::ssh-keysign` becomes observation for target `ssh-keysign`.
- **Collect artifact path mismatch**: API reports synthetic filename that doesn't exist on disk.
- **HTTP auth failure heuristics**: cannot distinguish 404 (endpoint not found) from auth failure.
- **LLM calls without timeout**: cognitive_sensor and dark_hypothesis_sensor can hang the daemon indefinitely.

### What is absent (declared but not implemented)

- **AI, IoT Firmware, Supply Chain toolchain adapters**: catalogs exist, projections exist, no adapters. Three domains completely unmeasured.
- **DarkHypothesisSensor**: fully implemented, never registered in SensorLoop.
- **Per-sensor timeout enforcement**: none.
- **Sensor rate limiting / backpressure**: none.
- **Health check endpoint**: none.
- **State file rotation**: none.
- **`skg target remove`**: stub that prints a message and does nothing.

### What is confused (design-level contradictions)

- **Three "surface" products**: API /surface (measured projection), API /targets (hybrid registry), CLI `skg surface` (hydrated discovery). Same word, different semantics.
- **Gravity is both subprocess and module load**: daemon shells out to gravity_field.py; CLI loads it as module; comments describe a third (inline) path that doesn't exist.
- **Fold.location is four different things**: host (structural), target_ip (contextual), workload_id (projection), identity_key (temporal). No type safety, no subclasses.
- **Fiber.anchor means two things**: documented as identity anchor; used in code as service name, relation name, or host.
- **Binary sphere disagreement**: field_functional.py puts binary_analysis in "binary" sphere; topology/energy.py collapses it to "host".
- **Coupling K has three different tables**: core/coupling.py, substrate/bond.py, graph/__init__.py — same domain pairs, different values.

---

## 5. The Single Root Cause

Every specific dissonance traces back to one structural fact:

**The substrate (kernel, substrate, identity, temporal) was built correctly and implements the formal model. The wrapper shell (daemon, CLI, gravity_field.py, topology) was built for Work 3 semantics and was extended with Work 4 machinery as additive modifications rather than as replacements. Neither the Work 3 control shell nor the bootstrap convenience layers were ever demoted when the substrate became authoritative.**

The formal model says: field locals govern gravity, measured state governs authority, identity anchors govern memory. The runtime says: target rows govern gravity, hybrid discovery governs initial authority, target_ip anchors most memory operations.

The substrate is a pier. The wrapper shell is a bridge built to an older pier location. The pier moved. The bridge was extended to reach it. But the bridge's foundation is still at the old location, and the bridge's main span still runs to the old location — the extension to the new location is a spur off the main structure.

---

## 6. What "Fixed" Looks Like

The remediation plan (`SKG_MASTER_REMEDIATION_PLAN_20260328.md`) has 134 items. But structurally, there are five changes that would resolve the majority of the dissonance:

### Fix A: Workload locals as primary scheduler object

`skg/gravity/selection.py`: replace `rank_instruments_for_target(target_row, ...)` with `rank_instruments_for_locals(workload_locals: List[FieldLocal], ...)`. Gravity consults the union of measured field locals across all active expressions. Target IP is recovered from locals if needed for instrument invocation — it is never the scheduling key.

This collapses: BRK-010, BRK-011, UNC-004 (fold location), UNC-011 (workload resolution), CON-002 (target-first substrate), CON-004 (gravity driven by locals, not rows), and the measured authority problem in gravity.

### Fix B: Measured surface takes authority over discovery surface

In `skg/core/daemon.py` and `skg-gravity/gravity_field.py`: when measured workload locals exist for a target, use them. When they don't, fall back to discovery surface as bootstrap only. Enforce this ordering explicitly.

In `skg/topology/energy.py`: do not promote surface domains/services to realized WicketState. World states are context for display; measured projections are field truth.

In `skg/core/daemon.py`: surface ranking should be `mtime` primary; richness is tiebreaker only.

This collapses: BRK-006, BRK-007, UNC-001 (three surfaces), UNC-017 (ranking), CON-005 (authority), CON-006 (config as measured state), and the observation boundary problem.

### Fix C: Projector output canonical normalization

In `skg/sensors/projector.py`: all projectors return one shape. `canonical_interp_payload()` is called before writing output. Wrapped envelopes are normalized before hitting feedback and delta.

This fixes: BRK-001 (wrapped interp → delta), UNW-014 (projector output validation), UNC-003 (projector shape inconsistency), ABS-015 (wrapped interp test), and unblocks closed-loop observation for binary and data domains.

### Fix D: Observation envelope enforced at emission

In `skg/sensors/__init__.py`: validate every emitted event against the canonical envelope schema. Reject non-compliant events with a quarantine record. All producers (web_sensor, ssh_sensor, adapter_runner, gravity_field.py) updated to use canonical helpers.

This fixes: BRK-016 (malformed NDJSON silent drop), UNW-015 (envelope validation absent), UNC-002 (fragmented construction), UNC-018 (incomplete provenance), and removes the observation boundary leak.

### Fix E: Pearl recording as substrate-wide append

In `skg/temporal/feedback.py` and `skg/sensors/projector.py`: record pearl when observation closure occurs. In `skg/core/daemon.py`: record pearl on state transition driven by CLI observe commands. Pearl recording is not a gravity feature — it is a substrate feature.

This fixes: UNW-012 (fold resolution pearls), UNC-015 (pearl recording gravity-centric), and makes memory curvature reflect all field transformations, not just gravity summaries.

---

## 7. The Invariants That Must Not Break

Regardless of any other change, these properties are the system's identity. Violating them turns SKG into a different (lesser) thing:

1. **U is stable and carries no prior.** Unknown state does not converge toward R or B without new telemetry. No inference, no propagation, no "probably" admitted.

2. **B is not ¬R.** Blocked means constraint-suppressed, not structurally absent. A blocked path might become realizable if constraints change.

3. **Tools emit support, not state.** No adapter assigns R/B/U directly. Support vectors are aggregated by the substrate. Collapse is substrate-mediated.

4. **Operator gates all exploitation.** `skg proposals trigger <id>` is the only path to MSF execution. No autonomous execution.

5. **Observations are append-only.** Substrate state is not rewritten. Past measurements are preserved. Pearls are never modified after writing.

6. **The field is primary. Wickets are projections.** No computation that bypasses the field layer to directly manipulate wicket state is canonical.

7. **The adapter is the only domain-specific component.** Gravity, support aggregation, collapse, and projection are domain-agnostic. Conditional logic on domain label in core paths is a violation.

8. **AI output is advisory unless custody chain is complete.** AI cannot move `derived_advice` into the observation plane without: artifact path, hash, source pointer, collection timestamp.

---

## 8. Reading Order for a New Developer

To understand SKG in the right order:

1. **`SKG_Work3_Final.md`** — the substrate, tri-state, energy, gravity, sheaf. Read Section 2 (formal framework) and Section 5 (gravity field). This is the foundation.

2. **`SKG_Work4_Final.md`** — domain expression architecture, field functional, fiber-driven gravity, coupling law, protected state. Read Section 2 (domain expression), Section 3 (field functional), Section 4 (fiber-driven gravity), Section 5 (protected state criterion).

3. **`SKG_FIELD_FUNCTIONAL.md`** — the bridge between papers and code. Explicitly states what is implemented and what is still incomplete.

4. **`SKG_CANONICAL_DATA_MODEL.md`** and **`SKG_CANONICAL_RUNTIME_MAP.md`** — the nine canonical objects and which paths are authoritative.

5. **`SKG_OBSERVATION_BOUNDARY_AUDIT_20260327.md`** — read after the formal docs. This is where the observation boundary breaks down in code.

6. **`SKG_MEASURED_AUTHORITY_AUDIT_20260327.md`** — where discovery surfaces override measured state. The most operationally important dissonance.

7. **`SKG_GRAVITY_BOUNDARY_AUDIT_20260327.md`** — why gravity is still target-row, not field-local.

8. **`SKG_MASTER_REMEDIATION_PLAN_20260328.md`** — the work queue. Read after understanding the system.

---

## 9. In One Paragraph

SKG has a correct, working substrate that implements the formal model from Work 3 and Work 4 — support vectors, tri-state collapse, field energy, field locals, fiber-driven gravity terms, pearl memory, fold detection, sheaf obstruction, domain expressions, coupling tables. The substrate is real and has been empirically validated on live targets. The dissonance comes from the operational shell — the daemon, CLI, and gravity runtime — which were built when Work 3's target-row paradigm was current and were extended with Work 4 machinery as additive modifications rather than replacements. As a result, the formal field locals compute correctly but are applied inside a target-row scheduler; measured surface exists but discovery surfaces still govern gravity target selection; identity model exists in memory layers but target_ip governs kernel engine and selection; canonical event envelope exists but old producers bypass it; pearl recording exists for gravity cycles but not for all state transitions. The path to coherence is not to rebuild the substrate — it is correct — but to demote the wrapper layers: make workload locals the primary scheduler object, make measured state take authority over discovery surfaces, normalize projector output to one shape, enforce the envelope contract at emission, and record pearls as substrate-wide append rather than as a gravity feature. Five structural changes. Everything else is cleanup.
