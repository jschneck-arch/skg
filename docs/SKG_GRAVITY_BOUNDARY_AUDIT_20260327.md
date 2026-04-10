# SKG Gravity Boundary Audit

**Date:** 2026-03-27  
**Scope:** Core gravity semantics and runtime control flow. Audit/documentation pass. No runtime code changes.

## Summary

SKG does have a real gravity mechanism in the codebase. The problem is not absence.

The real issue is that the live gravity runtime is still a hybrid of two different layers:

1. **Formal field selection**: energy over unresolved structure, field locals, coupling, decoherence, protected-state suppression, failure memory.
2. **Operational target orchestration**: surface rows, service heuristics, first-contact bootstrap floors, filesystem history checks, broad bootstrap sweeps, top-N candidate truncation.

That hybridization is not wholly accidental. Work 4 explicitly says the current runtime uses a hybrid realization of `Φ_fiber` when explicit cluster structure is incomplete (`docs/SKG_Work4_Final.md:300`). So the presence of hybrid logic is not itself a violation.

What matters is the balance.

Right now the formal field layer exists, but the runtime still computes and executes gravity primarily as **target-row orchestration with field-functional modifiers**, not as a fully substrate-native selection over the union of active workload locals.

## Formal Standard From The Docs

The papers define gravity in a much stricter way than the runtime shell currently presents.

### 1. Work 3 defines a discrete but field-grounded selector

- `docs/SKG_Work3_Final.md:107`-`docs/SKG_Work3_Final.md:109` says gravity is a discrete instrument selection mechanism that follows the energy gradient.
- `docs/SKG_Work3_Final.md:125`-`docs/SKG_Work3_Final.md:131` defines:

  `Φ(I, t) = |{n ∈ W(I) ∩ A(t) : Σ(n) = U}| / c(I) × penalty(I, t)`

  and selects `argmax_I Φ(I, t)` for the highest-energy target.

- `docs/SKG_Work3_Final.md:137` says convergence is reached when no available instrument can further reduce uncertainty.

This is a greedy mechanism, but it is still formally tied to:

- applicable nodes
- measured state
- instrument wavelength
- failure memory

### 2. Work 4 lifts gravity from target counts to field locals

- `docs/SKG_Work4_Final.md:39` says the substrate has field locals indexed by `(workload_id, domain_label)`.
- `docs/SKG_Work4_Final.md:179`-`docs/SKG_Work4_Final.md:185` defines field locals and clusters over workloads and anchor identities.
- `docs/SKG_Work4_Final.md:191`-`docs/SKG_Work4_Final.md:199` defines `L(F)` over all locals from all active expressions.
- `docs/SKG_Work4_Final.md:251` says cross-expression coupling should elevate the next instrument because the coupled unresolved local has become highest-potential.
- `docs/SKG_Work4_Final.md:268`-`docs/SKG_Work4_Final.md:300` defines `Φ_fiber` over tension, coupling opportunity, and decoherence across the union of active expression locals.
- `docs/SKG_Work4_Final.md:300` is the key runtime disclaimer: the current runtime uses a hybrid realization, but selection is still supposed to be `argmax_I Φ_fiber(I, t)` over all instruments from all registered expressions.
- `docs/SKG_Work4_Final.md:507` restates the intended picture: gravity follows the gradient of `L(F)` across all registered instruments from all expressions simultaneously.

So the canonical standard is:

- the scheduler is field-driven
- locals are the meaningful units underneath selection
- targets are at most one operational grouping or locator layer

## What Already Works

There is real implementation progress toward the formal model.

### 1. Kernel gravity potential is no longer just a flat unknown count

- `skg/kernel/engine.py:273`-`skg/kernel/engine.py:399` computes `instrument_potential()` with:
  - base unresolved mass in the instrument wavelength
  - `phi_fiber` contribution
  - protected-local filtering
  - failure penalty
  - special exploit escalation behavior

This is materially closer to Work 4 than the old flat-space implementation.

### 2. FieldLocal and field-functional machinery are real

- `skg/kernel/field_local.py:237`-`skg/kernel/field_local.py:284` builds one `FieldLocal` per domain.
- `skg/kernel/field_functional.py:1`-`skg/kernel/field_functional.py:21` explicitly defines itself as the canonical runtime field-functional semantics.
- `skg/kernel/field_functional.py:158`-`skg/kernel/field_functional.py:201` computes a real field-functional breakdown across self energy, coupling, dissipation, and curvature.
- `skg/kernel/engine.py:419`-`skg/kernel/engine.py:443` exposes `L_field_functional()`.

That means Work 4 is not just paper language. There is executable structure for it.

### 3. Runtime gravity does include multiple field-derived modifiers

- `skg-gravity/gravity_field.py:6122`-`skg-gravity/gravity_field.py:6150` combines:
  - base energy
  - fold boost
  - topology/fiber pull
  - `L(F)` boost
  - wicket-graph boost
- `skg-gravity/gravity_field.py:6173`-`skg-gravity/gravity_field.py:6195` computes per-sphere order parameters.
- `skg/gravity/selection.py:122`-`skg/gravity/selection.py:139` uses sphere coherence and wicket-graph instrument boosts in ranking.

So the live runtime is not merely port-scan prioritization. There is real field-theoretic enrichment present.

### 4. The system still measures after acting

- `skg-gravity/gravity_field.py:6446`-`skg-gravity/gravity_field.py:6489` recomputes entropy after the instrument run and records `ΔE`.

That preserves the core Work 3 behavior: observation changes the field, and the field is re-evaluated.

## Where Gravity Still Departs From The Formal Model

These are the main conceptual boundaries where runtime gravity is still target/surface oriented.

### 1. The unit of scheduling is still the target row, not the union of active locals

- `skg-gravity/gravity_field.py:6069`-`skg-gravity/gravity_field.py:6221` builds a `landscape` entry per `surface["targets"]` row.
- `skg-gravity/gravity_field.py:6249`-`skg-gravity/gravity_field.py:6250` sorts those target rows by `entropy`.
- `skg-gravity/gravity_field.py:6282`-`skg-gravity/gravity_field.py:6296` iterates the sorted target rows and routes by IP.
- `skg/gravity/selection.py:64` defines `rank_instruments_for_target()`.
- `skg/gravity/selection.py:170` defines `choose_instruments_for_target()`.

This means the live scheduler is still fundamentally "pick a target row, then pick instruments for it." That is compatible with Work 3's deployment framing, but it is narrower than Work 4's "union of active expression locals."

### 2. Applicable state is derived from service hints and port heuristics before field-local reasoning

- `skg/gravity/landscape.py:92`-`skg/gravity/landscape.py:137` derives effective domains from:
  - service ports
  - service names
  - post-exploitation artifacts
  - speculative AI port probing
- `skg-gravity/gravity_field.py:6074`-`skg-gravity/gravity_field.py:6080` computes `effective_domains` and then `applicable_wickets`.

This is a major boundary. The set `A(t)` is not being derived primarily from workload locals or measured expression membership. It is being inferred from target-service heuristics and artifact hints, then used to decide what gravity thinks is applicable.

### 3. Cold-start bootstrap floors override pure field selection

- `skg/gravity/landscape.py:147`-`skg/gravity/landscape.py:168` applies a first-contact entropy floor and seeds a broad applicable wicket set when there is no prior nmap history.
- `skg-gravity/gravity_field.py:6152`-`skg-gravity/gravity_field.py:6165` uses that floor directly in the live landscape.
- `skg/gravity/selection.py:94`-`skg/gravity/selection.py:99` treats several conditions as cold start.
- `skg/gravity/selection.py:141`-`skg/gravity/selection.py:156` force-boosts specific instruments under cold-start conditions.
- `skg/gravity/selection.py:183`-`skg/gravity/selection.py:201` turns cold-start or high-unknown targets into broad bootstrap sweeps over `BOOTSTRAP_NAMES`.

This is not pure `argmax_I Φ(I, t)`. It is an orchestration heuristic layered on top of the field. It may be operationally useful, but it is a real departure from the simplest formal selector.

### 4. The named `GravityScheduler` is not the actual scheduler

- `skg/kernel/gravity.py:5`-`skg/kernel/gravity.py:14` defines `GravityScheduler.rank()` as a simple scoring sort over proposals.
- `skg/kernel/engine.py:392`-`skg/kernel/engine.py:399` uses it only as a single-proposal scoring helper.
- `skg-gravity/gravity_field.py:6069`-`skg-gravity/gravity_field.py:6365` contains the actual landscape construction, target ordering, candidate generation, bootstrap logic, concurrency decisions, and execution flow.

So the formal-sounding scheduler abstraction does not own the real scheduling semantics. The true policy lives in the orchestration layer.

### 5. `FieldLocal` is present, but still anchored to single-target IP state

- `skg/kernel/field_local.py:237`-`skg/kernel/field_local.py:248` describes `workload_id`, but its docstring still says `Target IP or identifier`.
- `skg/kernel/engine.py:401`-`skg/kernel/engine.py:417` builds field locals with `target_ip` as the anchor.
- `skg/kernel/engine.py:419`-`skg/kernel/engine.py:443` computes `L_field_functional()` for a `target_ip`.
- `skg/kernel/field_functional.py:4` explicitly calls itself canonical semantics for a **single target**.

This is one of the clearest gravity-boundary mismatches with Work 4. The runtime has field-local machinery, but it is still loaded through one-target/IP semantics rather than through first-class workload/identity clusters.

### 6. Selection is still shaped by filesystem artifact history and surface services

- `skg/gravity/selection.py:80`-`skg/gravity/selection.py:85` uses recent nmap/CVE/web/auth artifact existence to shape candidate scoring.
- `skg/gravity/selection.py:86`-`skg/gravity/selection.py:93` uses surface service rows and banners to define web/versioned-service conditions.
- `skg/gravity/selection.py:130`-`skg/gravity/selection.py:135` penalizes H1-overlapping instruments by reading interp files.

These are all practical hints, but they are not substrate-local field semantics. They are orchestration inputs.

### 7. Candidate execution policy truncates and batches beyond pure `argmax`

- `skg/gravity/selection.py:203` picks `candidates[:6]` for warm targets.
- `skg/gravity/selection.py:183`-`skg/gravity/selection.py:201` may choose a broader bootstrap sweep instead of the single highest-potential instrument.
- `skg-gravity/gravity_field.py:6355`-`skg-gravity/gravity_field.py:6365` executes selected instruments concurrently.

Again, that may be fine operationally. But it means the runtime behavior is not literally "select the maximum-potential instrument and run it." It is a batch policy built around the field score.

### 8. Post-run re-evaluation still re-enters through hydrated target state

- `skg-gravity/gravity_field.py:6451`-`skg-gravity/gravity_field.py:6464` refreshes the target by hydrating the surface from latest nmap, then re-derives domains and applicable wickets.

So even the "after measurement" entropy update still routes back through target/service hydration rather than staying entirely in workload-local measured state.

## What This Means

The live gravity runtime is best described as:

**a target-oriented orchestration shell with genuine field-functional scoring inside it**

That is not the same as saying gravity is fake. It is not fake.

It does mean the boundary is not yet where the papers imply:

- the formal field layer exists
- the runtime uses it
- but the orchestration shell still decides too much in terms of targets, services, and bootstrap policy

In other words:

- Work 3 recovery is present
- parts of Work 4 are present
- the full runtime still has not made workload-local field structure the unquestioned primary scheduler object

## What Should Be Preserved

This is not an argument to remove the heuristics.

Many of these likely have legitimate operational value:

- first-contact floors
- broad bootstrap sweeps
- service-derived domain hints
- recent-artifact suppression
- H1 penalties
- concurrency batching

The audit issue is not their existence. It is their current rank in the control stack. Right now they are still steering the scheduler more directly than the code's own field-local abstractions.

## Test Gaps

Current tests mostly validate the heuristic scheduler as it exists now.

Evidence of existing coverage:

- `tests/test_gravity_runtime.py:409` covers `derive_effective_domains()`
- `tests/test_gravity_runtime.py:435` covers `apply_first_contact_floor()`
- `tests/test_gravity_runtime.py:456` covers cold-start `nmap` boosting
- `tests/test_gravity_runtime.py:501` covers metasploit serialization
- `tests/test_gravity_routing.py:2`-`tests/test_gravity_routing.py:13` describes routing as highest-entropy target first

What is not really covered:

- validating that `Φ_fiber` actually dominates selection when field-local structure exists
- selection over workload/identity locals rather than target rows
- proving cross-expression instrument choice emerges from coupling rather than bootstrap heuristics
- ensuring `L(F)` meaningfully changes ranking, not just adds a bounded side boost
- verifying that protected locals are actually suppressing re-observation in end-to-end gravity cycles
- checking whether batch execution changes the intended `argmax` behavior materially

## Conclusion

Gravity in SKG is real, but it is not yet purely substrate-native.

The codebase already contains the field-local, coupling-aware, Work 4-style machinery needed for a more canonical scheduler. But the live runtime still wraps that machinery in a target-row orchestration shell that relies heavily on service heuristics, bootstrap policy, and discovery artifacts.

The central audit conclusion from this pass is:

SKG's gravity engine currently behaves more like **field-enriched target orchestration** than like **direct selection over the union of active measured locals**.

That is the next conceptual boundary in core SKG. The substrate pieces are there. The orchestration layer still speaks louder than they do.
