# SKG Observation Boundary Audit

Date: 2026-03-27

Purpose: trace where target, workload, service, and surface facts enter base SKG, and classify each path as measured, inferred, synthetic, or hybrid.

This is not a fix plan.
It is an audit of the observation boundary.

## Summary

Base SKG currently has two different "surface" products:

1. A projection surface built from `INTERP_DIR`, exposed at `/surface`.
   - This is the closest thing to a measured canonical attack surface.
   - It is synthesized from projection artifacts, identity parsing, graph relationships, and temporal memory.

2. A discovery surface stored in `DISCOVERY_DIR / surface_*.json`.
   - This is what gravity uses for target selection.
   - This is also what several CLI paths use for `target list`, `surface`, target registration, and bootstrap discovery.
   - It is not measurement-only. It is a hybrid of config targets, manual registrations, classification results, and observed service lists.

The main observation-boundary problem is not that SKG lacks a measured path.
The problem is that important runtime control paths still obey the hybrid discovery surface rather than the measured projection surface.

## The Measured Path

This is the strongest substrate-aligned path in the current code.

### 1. Sensors emit structured observation envelopes

Base envelope and precondition payload helpers live in:

- `skg/sensors/__init__.py:71-177`

These preserve:

- event type
- source identity
- provenance
- confidence
- workload identity
- tri-state status

### 2. Events are written as append-only artifacts

Sensor event emission goes through:

- `skg/sensors/__init__.py:552-576`

This writes NDJSON envelopes to `EVENTS_DIR`.

### 3. Kernel adapters convert raw events into canonical observations

Event-to-observation mapping is in:

- `skg/kernel/adapters.py:87-157`

Target loading and observation assembly are in:

- `skg/kernel/adapters.py:160-240`

This is the core bridge from domain/adapters into substrate objects.

### 4. Projection artifacts are ingested into append-only temporal memory

Temporal snapshot/transition ingestion is in:

- `skg/temporal/__init__.py:188-316`

Feedback routing from projection results into delta store and workload graph is in:

- `skg/temporal/feedback.py:97-220`

### 5. The API `/surface` is built from projection state

Projection-surface synthesis is in:

- `skg/intel/surface.py:164-261`

The daemon endpoint is:

- `skg/core/daemon.py:1467-1482`

This path is the most faithful implementation of:

- `README.md:3-7`
- `SKG_CLOSED_OBSERVATION_LOOP.md:3-10`

## The Hybrid Path

This is where observation boundary drift currently lives.

### 1. Discovery surface files are read and written directly

CLI surface helpers:

- `_latest_surface()` in `skg/cli/utils.py:72-88`
- `_load_surface_data()` in `skg/cli/utils.py:95-106`
- `_write_surface_data()` in `skg/cli/utils.py:109-116`

Daemon gravity target selection:

- `_surface_score()` in `skg/core/daemon.py:50-58`
- `_select_surface_path()` in `skg/core/daemon.py:61-65`

### 2. Targets can be inserted without measurement envelopes

Manual target registration:

- `_register_target()` in `skg/cli/utils.py:209-227`
- `cmd_target add` in `skg/cli/commands/target.py:22-29`

Bootstrap network discovery writes directly to discovery surface:

- `_bootstrap_target_surface()` in `skg/cli/utils.py:301-312`

Web observation registration writes classified target data directly to discovery surface:

- `_register_web_observation_target()` in `skg/cli/utils.py:241-264`

Configured local runtime endpoints are injected directly:

- `_ensure_local_runtime_targets()` in `skg/cli/utils.py:119-169`
- `_configured_local_targets()` in `skg/core/daemon.py:152-184`

### 3. `/targets` is a hybrid target registry, not a measured state view

Target aggregation path:

- `_all_targets_index()` in `skg/core/daemon.py:1732-1775`
- `/targets` endpoint in `skg/core/daemon.py:1419-1452`

This path merges:

- `targets.yaml`
- `surface_*.json`
- configured local runtime targets
- derived world/profile overlays from artifacts

That makes `/targets` useful, but not canonical measured substrate state.

## Critical Findings

### 1. Gravity is driven by a hybrid discovery surface, not a measurement-only surface

Gravity selects its surface file with:

- `_select_surface_path()` in `skg/core/daemon.py:61-65`
- `_run_gravity_cycle()` in `skg/core/daemon.py:470-487`

That surface file can contain:

- manually added targets via `skg target add`
  - `skg/cli/commands/target.py:22-29`
- bootstrap discovery classifications
  - `skg/cli/utils.py:301-312`
- web URL classifications
  - `skg/cli/utils.py:241-264`
- configured local runtime targets
  - `skg/cli/utils.py:119-169`
  - `skg/core/daemon.py:152-184`

So gravity target selection currently operates on a hybrid registry, not on strictly observed substrate facts.

This is the clearest mismatch with:

- `README.md:3-7`
- `README.md:13-19`
- `SKG_CLOSED_OBSERVATION_LOOP.md:3-10`

### 2. Discovery surface truth is sticky and can become stale by design

Both CLI and daemon rank `surface_*.json` files by "richness" rather than recency alone:

- `skg/cli/utils.py:72-88`
- `skg/core/daemon.py:50-58`

Richer files win even if they are older.

Inside `_all_targets_index()`, services are only replaced when the incoming service list is at least as large as the current one:

- `skg/core/daemon.py:1755-1756`

So service truth is effectively monotone by cardinality:

- more services tends to persist
- fewer services does not reliably replace older state

This means:

- stale ports/services can remain authoritative for gravity and `/targets`
- newer but narrower observations cannot reliably retract prior service claims

### 3. Single-target collection does not preserve a clean target-to-artifact boundary

The daemon `/collect` single-target path creates a synthetic target dict:

- `skg/core/daemon.py:1367-1383`

It then calls:

- `collect_host()` in `skg/sensors/__init__.py:262-300`

But `collect_host()` constructs `SshSensor(sensor_cfg)` with the requested target and then calls `sensor.run()`, while `SshSensor.run()` ignores `cfg["targets"]` and reloads targets from `targets.yaml`:

- `skg/sensors/__init__.py:286-297`
- `skg/sensors/ssh_sensor.py:77-84`

So the requested target boundary is not authoritative.
The runtime may collect from config-defined targets instead of the caller-supplied target.

The reported artifact path is also synthetic:

- `/collect` returns `host_{workload_id}_{run_id}.ndjson`
  - `skg/core/daemon.py:1385-1397`

But actual sensor event emission uses timestamped `emit_events()` naming:

- `skg/sensors/__init__.py:566-576`
- `skg/sensors/ssh_sensor.py:112-115`

So the API can report an events file that does not exist.

`collect_host()` also returns `True` after `sensor.run()` regardless of whether any events were written:

- `skg/sensors/__init__.py:292-297`

This breaks three boundaries at once:

- requested target
- persisted artifact
- reported artifact

## Medium Findings

### 4. Direct web/auth observe outputs do not match the kernel loader contract

`cmd_observe` writes:

- `observe_auth_{host}.ndjson`
  - `skg/cli/commands/target.py:176-186`
- `observe_web_{host}.ndjson`
  - `skg/cli/commands/target.py:188-209`

But by inspection, `load_observations_for_target()` only looks for patterns such as:

- `gravity_http_*`
- `gravity_auth_*`
- `gravity_nmap_*`
- `gravity_ssh_*`
- `gravity_data_*`
- `web_events_*`

See:

- `skg/kernel/adapters.py:176-216`

`observe_web_*` and `observe_auth_*` are not in the canonical loader pattern set.

Inference:

- direct CLI web/auth observation artifacts are not consistently part of the canonical kernel observation loader path
- they may exist as useful artifacts without becoming substrate observations

### 5. Web observation registration is classification-driven, not evidence-driven

`_register_web_observation_target()` accepts `events_file` but does not use it:

- signature and body in `skg/cli/utils.py:241-264`

Instead it:

- classifies the target from URL/port
- loads latest wicket states from discovery
- merges that into `surface_*.json`

So even after a web collector runs, the surface update path is still primarily classification-driven rather than derived from the emitted observation artifact itself.

### 6. "Surface" means different things in different operator paths

API `/surface`:

- measured projection surface
- `skg/core/daemon.py:1467-1482`
- `skg/intel/surface.py:164-261`

API `/targets`:

- hybrid target registry
- `skg/core/daemon.py:1419-1452`
- `skg/core/daemon.py:1732-1775`

CLI `skg surface`:

- reads `surface_*.json` directly
- optionally asks `gravity_field.py` to hydrate it
- `skg/cli/commands/surface.py:61-77`

UI initial load:

- fetches both `/targets` and `/surface`
- `ui/app.js:604-613`

So the runtime currently exposes multiple "surface" products under the same word.

### 7. Target config authority is duplicated

Target loading exists in:

- `skg/sensors/__init__.py:220-243`
- `skg/sensors/ssh_sensor.py:38-48`
- `skg/cli/utils.py:286-298`

These are small differences, but they are still parallel authority surfaces over the same `targets.yaml`.

### 8. CLI collect still does not carry the full measurement input boundary

The daemon request model accepts `password`:

- `skg/core/daemon.py:1300-1309`

But the CLI parser does not expose `--password`:

- `skg/cli/app.py:185-191`

And `cmd_collect()` omits `password` when posting to `/collect`:

- `skg/cli/commands/exploit.py:593-602`

So an operator cannot fully specify the observation boundary through the top-level `skg collect` wrapper even though the daemon supports it.

## What Works

### 1. The measured event schema is coherent

- `skg/sensors/__init__.py:71-177`
- `skg/kernel/adapters.py:87-157`

The envelope and precondition schema are substantive and preserve provenance.

### 2. Identity collapse from workload manifestation to stable identity is useful

- `skg/identity/__init__.py:23-68`

This is one of the cleaner base-SKG abstractions.

### 3. Temporal memory remains append-only

- `skg/temporal/__init__.py:188-316`
- `skg/temporal/feedback.py:190-220`

The measured path into delta and graph memory is real.

### 4. The API `/surface` is closer to the documented architecture than the discovery surface is

- `skg/intel/surface.py:164-261`
- `skg/core/daemon.py:1467-1482`

If the question is "where is the measured attack surface today?", `/surface` is the better answer than `surface_*.json`.

## Test Gaps

Current tests only lightly cover this boundary.

There is import-level coverage for the CLI helper functions:

- `tests/test_cli_commands.py:220-260`

But there is no substantive regression coverage for:

- `_register_target()` writing synthetic targets into `surface_*.json`
- `_bootstrap_target_surface()` bypassing canonical event/provenance ingestion
- `_register_web_observation_target()` ignoring `events_file`
- `_surface_score()` preferring richer older discovery surfaces
- `_all_targets_index()` preserving stale service lists by cardinality
- `/collect` single-target semantics vs `SshSensor.run()` reloading `targets.yaml`
- `/collect` reported artifact path vs actual `emit_events()` output path
- CLI/API contract divergence between `/surface`, `/targets`, and `skg surface`
- direct `observe_web_*` / `observe_auth_*` filenames vs canonical kernel loader patterns

## Final Assessment

Base SKG already has a real measured observation boundary.

That boundary is:

- envelope event
- canonical observation object
- projection artifact
- temporal ingestion
- projection-derived `/surface`

The problem is that several high-leverage runtime paths still operate on a different boundary:

- discovery surface files
- target config
- direct classification writes
- wrapper-generated synthetic target state

So the current system is not failing because it lacks a substrate.
It is failing because its control layer still treats hybrid discovery state as if it were canonical measured state.
