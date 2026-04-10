# SKG Measured Authority Audit

**Date:** 2026-03-27  
**Scope:** Core SKG authority boundary. Audit/documentation pass. No runtime code changes.

## Summary

SKG's papers and README are clear about authority:

- observations are primary objects (`README.md:3`)
- the system is field-first, not policy-first (`README.md:7`)
- the closed loop is `observe -> collapse state -> evaluate projections -> measure informational deficit -> compute gravity -> generate proposals -> observe again` (`docs/SKG_CLOSED_OBSERVATION_LOOP.md:3`-`docs/SKG_CLOSED_OBSERVATION_LOOP.md:10`)
- system properties must be derived from measured state, and indeterminacy must not be collapsed by inference (`docs/SKG_Work3_Final.md:27`, `docs/SKG_Work3_Final.md:67`)
- priors are allowed to steer observation, but must be consumed by measurement once observation exists (`docs/SKG_Work3_Final.md:85`-`docs/SKG_Work3_Final.md:87`)
- adapters emit canonical events, and once emitted those events are processed identically by the substrate (`docs/SKG_Work4_Final.md:134`-`docs/SKG_Work4_Final.md:153`)

The live runtime does contain that measured path.

The problem is authority inversion around it.

There are currently three different classes of state in play:

1. **Measured substrate state**: event envelopes, projected interps, delta history, graph transitions.
2. **Hybrid discovery/config state**: `surface_*.json`, `targets.yaml`, injected configured locals, tool-specific refresh logic.
3. **Operator presentation state**: CLI summaries, `/targets`, `/report`, `/surface`-adjacent output, world views.

These classes are not consistently ordered. In several core paths, hybrid discovery/config artifacts are allowed to pre-populate, rank, hydrate, or even inject quasi-realized world structure ahead of measured workload state. That is the main authority problem in current SKG.

## The Measured Path That Already Exists

The substrate-side authority chain is real and should be preserved as canonical.

### 1. The docs define measurement as the source of truth

- `README.md:3` and `README.md:19` define observations and observation-driven gravity as the center of the system.
- `docs/SKG_Work3_Final.md:27` and `docs/SKG_Work3_Final.md:67` explicitly reject resolving uncertainty through inference.
- `docs/SKG_Work4_Final.md:153` says canonical events from any expression are processed identically by the substrate.

### 2. The measured operator surface exists in code

- `skg/intel/surface.py:1`-`skg/intel/surface.py:20` describes a surface built from `INTERP_DIR`, `DELTA_DIR`, `EVENTS_DIR`, graph, and observation memory.
- `skg/intel/surface.py:80`-`skg/intel/surface.py:126` reads projection outputs from `INTERP_DIR`.
- `skg/intel/surface.py:164`-`skg/intel/surface.py:220` builds the current attack surface from projected workloads, not from static target declarations.

This is the best current example of the runtime following the substrate.

### 3. Feedback explicitly says it is not the truth-defining layer

- `skg/temporal/feedback.py:97`-`skg/temporal/feedback.py:105` states the intended boundary cleanly: feedback routes consequences; feedback does not define truth.

That is exactly the correct contract.

## Where Authority Is Inverted

The following are the main places where hybrid discovery/config state is allowed to act like primary truth.

### 1. Surface file selection prefers "richness" over measured recency

- `skg/core/daemon.py:50`-`skg/core/daemon.py:65` chooses the current surface by `(target_count + service_count, target_count, mtime)`.
- `skg-gravity/gravity_field.py:177`-`skg-gravity/gravity_field.py:193` uses the same richness-based strategy.
- `skg/topology/energy.py:114`-`skg/topology/energy.py:118` also selects a current surface file.

This means the runtime may prefer a richer older discovery snapshot over the most recently measured state. That is useful as a bootstrap heuristic, but it is not a valid definition of authoritative field state.

### 2. The daemon exposes a target index built from config plus discovery snapshots

- `skg/core/daemon.py:1419`-`skg/core/daemon.py:1452` exposes `/targets` as a primary summary route.
- `skg/core/daemon.py:1732`-`skg/core/daemon.py:1775` builds `_all_targets_index()` by merging:
  - `targets.yaml` via `_load_targets()`
  - all `surface_*.json` files
  - configured local targets
- `skg/core/daemon.py:152`-`skg/core/daemon.py:183` injects configured local runtime endpoints as target rows.

This means a non-measured declared or configured endpoint can become a first-class row in the operator model before the measured projection surface says anything about it.

### 3. Gravity starts from hydrated target surfaces, not from measured projection locals

- `skg/core/daemon.py:470`-`skg/core/daemon.py:489` launches gravity with `--surface`, and optionally `--target`.
- `skg-gravity/gravity_field.py:5850`-`skg-gravity/gravity_field.py:5875` begins each cycle by:
  - hydrating the selected surface from latest nmap
  - falling back to raw surface JSON
  - merging configured targets from `targets.yaml`
- `skg-gravity/gravity_field.py:5875`-`skg-gravity/gravity_field.py:5890` then scopes by `focus_target` using `surface["targets"]`.

So gravity's starting landscape is not purely "measured projected field state." It is a hybrid target surface enriched by discovery refresh and config injection.

### 4. Gravity rewrites target records based on classification helpers

- `skg-gravity/gravity_field.py:243`-`skg-gravity/gravity_field.py:269` updates a target record in the surface file by reclassifying it from services and current wicket states.
- `skg-gravity/gravity_field.py:368`-`skg-gravity/gravity_field.py:434` injects targets declared in `targets.yaml` that were never observed in the current discovery surface.
- `skg-gravity/gravity_field.py:437`-`skg-gravity/gravity_field.py:470` rehydrates each target row from latest nmap and current wicket states.

This is useful operator support. But it also means `surface_*.json` behaves less like a transient convenience artifact and more like a mutable world model assembled from partial measured plus declared facts.

### 5. Topology energy injects realized world states directly from the hybrid surface

- `skg/topology/energy.py:793`-`skg/topology/energy.py:799` says world states from surface are "not wicket collapses" but "direct observed-world contributions."
- `skg/topology/energy.py:807`-`skg/topology/energy.py:845` turns target domains and services from the surface file into realized `WicketState` entries like `world::{host}::domain::web`.
- `skg/topology/energy.py:1351`-`skg/topology/energy.py:1358` injects those world states into sphere energy alongside measured and pearl-derived states.

This is one of the strongest authority drifts in core. A hybrid surface row is being promoted into realized field contributions without passing through the same measurement/projection discipline as canonical precondition events.

### 6. CLI surfaces often show hydrated discovery state instead of measured surface state

- `skg/cli/commands/surface.py:61`-`skg/cli/commands/surface.py:78` loads the latest surface file and hydrates it through gravity runtime helpers.
- `skg/cli/commands/report.py:18`-`skg/cli/commands/report.py:33` does the same.

This means the main CLI summary/report surfaces are not using the measured `skg.intel.surface.surface()` path as their default authority source. They are using a hydrated discovery surface.

### 7. The sensor boundary still falls back to declared target config

- `skg/sensors/__init__.py:262`-`skg/sensors/__init__.py:300` builds a synthetic target dict for `collect_host()`, but then runs `SshSensor`.
- `skg/sensors/ssh_sensor.py:17` and `skg/sensors/ssh_sensor.py:38`-`skg/sensors/ssh_sensor.py:48` define SSH collection as target-config driven from `targets.yaml`.
- `skg/sensors/ssh_sensor.py:77`-`skg/sensors/ssh_sensor.py:80` reloads targets from `SKG_CONFIG_DIR` inside `run()` instead of honoring the already-supplied one-target config.

This is an authority break at the observation boundary itself. A direct collection request can still be re-routed through config-sourced target state.

### 8. Kernel/topology caches treat surface snapshots as field context

- `skg/kernel/engine.py:113`-`skg/kernel/engine.py:132` uses `surface_*.json` mtimes as part of the fiber-context cache key.

That ties kernel-side field caching to hybrid surface artifacts, which is another sign that discovery state is treated as a field-defining input rather than a secondary operator convenience.

## What Still Works Correctly

Not everything is inverted.

### 1. Projection-based measured surface is the right direction

- `skg/intel/surface.py:164`-`skg/intel/surface.py:220` is closer to the papers than most older shell paths.

### 2. The feedback contract is conceptually correct

- `skg/temporal/feedback.py:97`-`skg/temporal/feedback.py:105` preserves the right conceptual line between routing effects and defining truth.

### 3. Config and discovery artifacts do have legitimate roles

The problem is not that these files exist.

These all have valid uses:

- `targets.yaml` as declared reachability, credentials, and scope hints
- `surface_*.json` as discovery/bootstrap/operator convenience
- local configured endpoints as seed locators
- topology/world hints as non-collapse presentation context

The issue is that they are too often allowed to outrank measured workload state.

## What Should Be Preserved

This audit is classification, not cleanup.

The following should be preserved, but their authority should stay secondary:

- `targets.yaml`
- `surface_*.json`
- gravity hydration helpers
- local configured-target injection
- topology world-state augmentation
- CLI target/surface/report convenience commands

They may remain important as bootstrap, operator memory, declared scope, or compatibility layers. They should just stop impersonating the canonical field.

## Test Gaps

The current tests do not appear to directly guard this authority boundary.

Important uncovered or under-covered cases:

- choosing between richest discovery surface and most recent measured surface
- ensuring CLI `surface` / `report` agree with `skg.intel.surface.surface()`
- preventing configured targets from appearing as equivalent to measured identities
- ensuring gravity can start from measured workload locals instead of hydrated target rows
- preventing topology energy from treating discovery-only domains/services as realized field state
- single-target collect honoring the supplied observation request instead of reloading `targets.yaml`

## Conclusion

SKG already has a real measured substrate path. That is not the missing piece.

The missing piece is authority discipline around it.

Right now, several core modules still let declared targets, hydrated discovery surfaces, and convenience world-state synthesis pre-populate or reshape the live field before measured projection state has the final word. That is why the system can feel conceptually split even when the underlying substrate is sound.

The key audit conclusion from this pass is:

`surface_*.json` and `targets.yaml` are useful support artifacts, but they are not the substrate's truth model.

Measured events and their projected workload state are the truth model. The rest should remain visible, preserved, and useful, but secondary.
