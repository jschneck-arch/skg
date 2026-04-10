# SKG Core Unification Audit

Date: 2026-03-27

Scope: core SKG only.

Included:

- `skg/substrate`
- `skg/kernel`
- `skg/temporal`
- `skg/identity`
- `skg/graph`
- `skg/gravity`
- `skg/core`
- `skg/assistant`
- `skg/forge`
- operator surfaces that directly shape substrate truth (`skg/cli`, `ui`) only where they alter canonical state semantics

Excluded for this pass:

- domain toolchains under `skg-*-toolchain`
- preserved mirrors and backups
- generated staging trees

This is not a deletion plan.
It is a classification and unification audit for base SKG.

## Summary

The base SKG runtime is real.
It is not an illusion created by the adapters.

The strongest substrate-aligned pieces are:

- path authority in `skg/core/paths.py`
- canonical tri-state unification in `skg/kernel/state.py`
- support aggregation and temporal decay in `skg/kernel/support.py`
- append-only temporal memory in `skg/temporal/__init__.py`
- append-only identity memory in `skg/identity/__init__.py`
- runtime toolchain discovery in `skg/core/domain_registry.py`
- proposal artifact immutability in `skg/assistant/action_proposals.py`

The main core problem is not that SKG is missing.
The main problem is that core state and control still depend too heavily on:

- config-driven synthetic targets
- filename and prefix heuristics
- hardcoded instrument/domain tables
- multiple gravity invocation stories
- silent exception swallowing in state loaders

That is the current reason the system can feel adapter-consumed even when the substrate is present.

## Governing Standard

The following architectural statements are explicit in the docs and are the standard used here:

- observations are primary objects, and structure/proposals are derived over measured state
  - `README.md:3-7`
- SKG is field-first, not a hard-coded path runner
  - `README.md:5-7`
- the canonical loop is `observe -> collapse state -> evaluate projections -> measure informational deficit -> compute gravity -> generate proposals -> operator selects actions -> observe again`
  - `SKG_CLOSED_OBSERVATION_LOOP.md:3-10`
- AI must not become substrate truth
  - `SKG_AI_ASSISTANT_CONTRACT.md:3-26`
- there is one canonical live runtime
  - `SKG_CANONICAL_RUNTIME_MAP.md:7-18`
- the substrate is stable even though the operational mechanisms are still developing
  - `SKG_Work3_Final.md:248-258`

## What Already Works

### 1. Path authority is centralized and mostly respected

`skg/core/paths.py:4-65` is a real single source of truth for:

- `SKG_HOME`
- `SKG_STATE_DIR`
- `SKG_CONFIG_DIR`
- runtime subdirectories under `/var/lib/skg`

This matches `SKG_CANONICAL_RUNTIME_MAP.md:34-52`.

### 2. Tri-state authority is unified

`skg/kernel/state.py:1-40` explicitly re-exports `TriState` from `skg.substrate.node`.
That fixes the earlier split between substrate and kernel encodings.

This is one of the cleanest signs that core SKG does exist as a coherent substrate.

### 3. Support collapse is substrate-first and mathematically legible

`skg/kernel/support.py:13-160` does real weighted evidence aggregation:

- per-observation decay
- contradiction tracking
- decoherence accounting
- compatibility span across distinct runs

This is aligned with the papers far better than most wrapper layers are.

### 4. Temporal memory is genuinely append-only

`skg/temporal/__init__.py:188-316` defines `DeltaStore` as append-only.
Snapshots and transitions are written as historical memory, not overwritten state.

That is directly aligned with the measured-field model in the docs.

### 5. Identity memory is append-only and useful

`skg/identity/__init__.py:1-162` is small but structurally sound:

- append-only journal
- explicit read-only lock in anchor mode
- compatibility parser for workload manifestation vs identity

### 6. Toolchain discovery is materially dynamic now

`skg/core/domain_registry.py:111-240` discovers toolchains from `skg-*-toolchain`, reads manifests, and locates projector entrypoints.

This is one of the major places where base SKG is correctly consuming adapters rather than being hardcoded around them.

### 7. Proposal artifacts are now immutable

`skg/assistant/action_proposals.py:20-82` generates timestamped, versioned filenames.
That is aligned with SKG's broader append-only stance.

## Core Findings

### Critical 1. Surface truth is still being mutated from configuration, not observation

This is the strongest substrate violation in the base runtime.

The CLI surface helpers inject a configured local Ollama endpoint directly into the surface:

- `skg/cli/utils.py:95-116`
- `skg/cli/utils.py:119-169`

The daemon also merges configured local targets into the canonical target index:

- `_configured_local_targets()` in `skg/core/daemon.py:152-184`
- merge into live target view in `skg/core/daemon.py:1762-1767`

That means a target can appear in the SKG surface because it exists in config, not because an instrument observed it.

This conflicts with:

- `README.md:3-7`
- `README.md:13-19`
- `SKG_CLOSED_OBSERVATION_LOOP.md:3-10`

Assessment:

- core architectural defect
- not an adapter problem
- should be reworked so configured endpoints are operator hints or seed candidates, not measured surface facts

### Critical 2. Canonical ingest still depends on filename and instrument-name heuristics

The temporal feedback path is still partially adapter-shaped:

- domain inference from payload keys and filename substrings in `skg/temporal/feedback.py:16-43`
- workload/run extraction from filename conventions in `skg/temporal/feedback.py:46-64`
- those heuristics are used in live ingestion in `skg/temporal/feedback.py:176-197`

The kernel event loader is also still pattern-driven:

- hardcoded discovery filename patterns in `skg/kernel/adapters.py:160-240`
- explicit instrument decay mapping in `skg/kernel/adapters.py:51-75`
- target inference from `workload_id.split("::")[-1]` in `skg/kernel/adapters.py:107-113`

Gravity selection also still depends on hardcoded core tables:

- bootstrap instruments in `skg/gravity/selection.py:10-25`
- sphere prefix mapping in `skg/gravity/selection.py:27-45`
- instrument-specific history checks and boosts in `skg/gravity/selection.py:82-156`

Kernel integration itself still says it is a drop-in replacement around `gravity_field.py`, not the full authority:

- `skg/kernel/engine.py:4-24`
- domain inference by wicket prefix in `skg/kernel/engine.py:44-69`

Assessment:

- core is still too dependent on naming conventions invented by adapters and old runtime wrappers
- this is the main reason SKG still feels more like a federation than a substrate

### Medium 3. Gravity still has multiple operational stories

The daemon runs gravity as a subprocess:

- `skg/core/daemon.py:470-603`

But `_gravity_loop()` still says it uses logic inline to avoid subprocess overhead:

- `skg/core/daemon.py:632-639`
- actual call path is still `_run_gravity_cycle()` at `skg/core/daemon.py:663`

The CLI also loads `gravity_field.py` directly as a file module:

- `skg/cli/commands/gravity.py:11-73`
- helper loader in `skg/cli/utils.py:200-206`

So the current core has at least three gravity authority surfaces:

- reusable kernel/gravity library
- `skg-gravity/gravity_field.py` runtime driver
- CLI/daemon wrappers that invoke it differently

This does not mean gravity is fake.
It means gravity is not yet presented by one clean runtime story.

### Medium 4. Core graph semantics are live, but still partly hardcoded and split from formal substrate bond semantics

The live graph layer owns propagation today:

- `skg/graph/__init__.py:75-93`
- `skg/graph/__init__.py:409-503`

It includes hardcoded:

- propagation weights
- propagation scopes
- intra-target trigger wickets

The formal bond object still exists separately:

- `skg/substrate/bond.py:1-140`

The two surfaces are not the same authority.
Example: `same_domain` is `0.35` in `skg/graph/__init__.py:76-83` but `0.60` in `skg/substrate/bond.py:10-17` and `skg/substrate/bond.py:66-80`.

This is not a reason to remove `bond.py`.
It is a reason to document that:

- `skg/graph/__init__.py` is live authority today
- `skg/substrate/bond.py` is a formal/reference surface that is not yet the live runtime authority

### Medium 5. Core state loaders still swallow corruption too quietly

Examples:

- feedback state resets silently in `skg/temporal/feedback.py:122-128`
- graph edge/prior load silently drops malformed lines in `skg/graph/__init__.py:202-224`
- registry config falls back silently in `skg/core/domain_registry.py:118-128`
- proposal iteration silently skips malformed records in `skg/forge/proposals.py:72-89`

This behavior preserves runtime continuity, but it weakens operator trust because corruption becomes data disappearance instead of a visible substrate event.

Assessment:

- not a crash bug
- a core reliability issue
- should become operator-visible, ideally through explicit warnings or quarantine records

### Medium 6. The runtime is still strongly mode-driven in core

The docs increasingly center the closed observation loop.
But the daemon still pivots runtime behavior around `KERNEL`, `RESONANCE`, `UNIFIED`, and `ANCHOR`:

- mode definitions in `skg/modes/__init__.py:1-70`
- runtime switching in `skg/core/daemon.py:672-694`

This is not necessarily wrong.
But it is still a second explanatory frame layered on top of the canonical loop.

Right now the mode machine is still more operationally concrete than the observation-loop story.
That is a core unification gap.

## What Does Not Look Broken In Core

- `skg/core/paths.py:4-65` is coherent and consistent with configured state-root behavior.
- `skg/kernel/state.py:1-40` is a real canonicalization fix, not a placeholder.
- `skg/kernel/support.py:51-160` is substantive logic and aligns with the papers.
- `skg/temporal/__init__.py:188-316` preserves append-only temporal memory correctly.
- `skg/identity/__init__.py:109-162` preserves append-only identity memory correctly.
- `skg/core/domain_registry.py:189-240` is a real dynamic discovery layer and a net architectural improvement.
- `skg/assistant/action_proposals.py:20-82` correctly enforces artifact immutability.
- `skg/forge/proposals.py:51-140` clearly separates pending, accepted, rejected, and superseded proposal stores under `SKG_STATE_DIR`.

## Test Gaps

Current tests do cover some core areas:

- `KernelStateEngine`, `WorkloadGraph`, and proposal helpers appear in `tests/test_sensor_projection_loop.py`
- gravity runtime helpers appear in `tests/test_gravity_runtime.py`
- some identity and same-domain regressions appear in `tests/test_runtime_regressions.py`

But there are still obvious gaps in core-only coverage:

- no test asserting that surface state is observation-derived and not config-injected
- no test asserting that malformed `feedback.state.json` produces a visible warning rather than silent reset
- no test asserting that malformed graph/proposal records are surfaced to operators
- no test asserting equivalence between daemon gravity invocation and CLI gravity invocation
- no test asserting that a newly discovered instrument can participate without editing `BOOTSTRAP_NAMES`, `SPHERE_PREFIXES`, or event-file glob tables
- no test asserting a single authoritative bond semantics source between `skg/graph` and `skg/substrate/bond`

## Core-Only Next Audit Order

Before moving outward into adapters, the next useful core audit order is:

1. Observation boundary
   - every way targets, workloads, and services enter the canonical surface
2. Projection ingest contract
   - eliminate filename/prefix heuristics where explicit schema should exist
3. Gravity authority
   - reconcile daemon, CLI, kernel, and `gravity_field.py` into one runtime story
4. Graph/bond authority
   - document which coupling surface is formal, which is live, and why
5. Corruption visibility
   - replace silent state resets/skips with operator-visible substrate events

## Final Assessment

Core SKG is already present.
The kernel, substrate, temporal memory, identity memory, and registry layers prove that.

What is still not fully on point is the authority boundary.

Today, too much core behavior still depends on:

- config injection
- filename heuristics
- hardcoded domain/instrument tables
- parallel invocation surfaces
- silent parse failure

So the right conclusion is not that SKG lacks a base.
The right conclusion is that the base exists, but its authority is still being diluted by compatibility logic and adapter-shaped assumptions inside core runtime code.
