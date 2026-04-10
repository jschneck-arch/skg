# SKG Bottom-Up Remediation Plan

Date: 2026-03-27

## Purpose

This plan turns the current core audits into a bottom-up remediation order.

SKG should be treated as a protocol stack:

- lower layers define canonical substrate truth
- higher layers are only allowed to consume that truth
- compatibility shims may remain temporarily, but they must stop acting as alternate authorities

The goal is not to shrink the codebase first. The goal is to restore a single authoritative substrate path and then move upward layer by layer until the daemon, gravity, CLI, API, UI, and domain toolchains all obey it.

## Ground Rules

1. Do not remove features just because they are old or ambiguous.
2. Keep compatibility shims until higher layers are migrated.
3. Every layer gets explicit entry criteria, exit criteria, and tests.
4. No higher-layer fixes should introduce new substrate contracts.
5. Pearls are part of base SKG and stay in scope throughout.

## The Stack

### Layer 0: Subject Model

This is the foundation.

Primary question:

- what is the canonical substrate subject?

Required answer:

- node/workload/identity locals are primary
- `target` is a compatibility shell, not the substrate subject

Current drifts:

- workload subjects still collapse to `split("::")[-1]`
- target/IP shells still outrank node/workload locals in core paths

Primary files:

- [adapters.py](/opt/skg/skg/kernel/adapters.py)
- [projection.py](/opt/skg/skg/substrate/projection.py)
- [identity/__init__.py](/opt/skg/skg/identity/__init__.py)
- [run.py](/opt/skg/skg-host-toolchain/projections/host/run.py)
- [daemon.py](/opt/skg/skg/core/daemon.py)

Exit criteria:

- binary/data/web workloads resolve to correct identity/workload anchors
- core support aggregation no longer relies on trailing-token heuristics
- target rows become derived views over workload/identity state

Required tests:

- `binary::host::artifact` identity parsing
- `mysql::host:port::table` identity parsing
- host-local and artifact-local observations both map to the same identity where intended
- no core loader drops valid events because the subject is not an IP string

### Layer 1: Observation Envelope

Primary question:

- what is the only canonical observation shape entering SKG?

Required answer:

- one canonical `obs.attack.precondition` envelope
- one canonical precondition payload
- adapters and sensors emit this, nothing else

Current drifts:

- shared helpers exist, but many producers still hand-roll event dicts
- fields like `node_id`, `target_ip`, `domain`, and provenance are inconsistently carried

Primary files:

- [__init__.py](/opt/skg/skg/sensors/__init__.py)
- [web_sensor.py](/opt/skg/skg/sensors/web_sensor.py)
- [ssh_sensor.py](/opt/skg/skg/sensors/ssh_sensor.py)
- [adapter_runner.py](/opt/skg/skg/sensors/adapter_runner.py)
- [gravity_field.py](/opt/skg/skg-gravity/gravity_field.py)

Exit criteria:

- all core-generated `obs.attack.precondition` events go through the shared helpers
- all required identity/provenance fields are present and consistent
- adapter output is the only domain-specific boundary into substrate events

Required tests:

- event contract fixtures for each daemon-native domain
- regression tests proving helper-produced and adapter-produced events are identical in shape
- malformed-event tests that fail visibly rather than disappearing silently

### Layer 2: Projection Contract

Primary question:

- what is the canonical projection representation inside SKG?

Required answer:

- one internal projection payload shape
- wrappers may serialize envelopes, but core consumers read through one normalized path

Current drifts:

- projectors return mixed shapes
- `surface()` handles that mix better than `feedback` and `delta`

Primary files:

- [projector.py](/opt/skg/skg/sensors/projector.py)
- [feedback.py](/opt/skg/skg/temporal/feedback.py)
- [__init__.py](/opt/skg/skg/temporal/__init__.py)
- [surface.py](/opt/skg/skg/intel/surface.py)
- projector `run.py` files under toolchains

Exit criteria:

- every projection consumer sees the same effective payload regardless of source projector
- feedback, delta, timeline, surface, and projection endpoints agree on classification and wicket sets
- wrapped and unwrapped interp files behave identically during migration

Required tests:

- round-trip tests for wrapped and unwrapped interps
- `projection -> feedback -> delta -> timeline` tests for host, binary, data, and web
- regression proving no wrapped interp loses `attack_path_id` or `wicket_states`

### Layer 3: Temporal And Closure Layer

Primary question:

- how does SKG convert projection changes into temporal memory and closed-loop learning?

Required answer:

- feedback consumes canonical projection state
- delta records canonical workload snapshots
- observation memory closes observations against canonical workload/identity state

Current drifts:

- observation closure still relies on workload/target heuristics
- feedback and delta do not yet behave uniformly across all projector shapes

Primary files:

- [feedback.py](/opt/skg/skg/temporal/feedback.py)
- [__init__.py](/opt/skg/skg/temporal/__init__.py)
- [observation_memory.py](/opt/skg/skg/resonance/observation_memory.py)
- [context.py](/opt/skg/skg/sensors/context.py)

Exit criteria:

- every projection update yields correct snapshot and transition behavior
- pending observations close on canonical subject identity, not string coincidence
- calibration and recall consume the same workload/node model as the substrate

Required tests:

- direct observation-memory closeout tests across multiple workload forms
- delta snapshot tests for mixed domains
- calibration tests using persisted runtime state, not wrapper-only assumptions

### Layer 4: Pearl Memory

Primary question:

- how is append-only substrate memory recorded and reused?

Required answer:

- pearls record meaningful field transformations across all relevant substrate paths
- pearl manifold remains derived memory, not alternate truth

Current drifts:

- pearls are real, but recording coverage is still gravity-heavy
- direct projection ingestion does not yet consistently create pearl history

Primary files:

- [pearls.py](/opt/skg/skg/kernel/pearls.py)
- [pearl_manifold.py](/opt/skg/skg/kernel/pearl_manifold.py)
- [feedback.py](/opt/skg/skg/temporal/feedback.py)
- [gravity_field.py](/opt/skg/skg-gravity/gravity_field.py)
- [proposals.py](/opt/skg/skg/forge/proposals.py)

Exit criteria:

- observe/project/transition/proposal/fold events all leave coherent pearl memory where appropriate
- pearl neighborhoods reflect direct substrate history, not just gravity cycle summaries
- pearl reinforcement never becomes a truth source, only a curvature modifier

Required tests:

- direct projector run creates expected pearl memory
- proposal lifecycle pearls remain intact
- manifold reinforcement matches recorded history by identity and domain

### Layer 5: Measured Surface

Primary question:

- what is the canonical operator-visible state synthesized from measured substrate state?

Required answer:

- measured surface is authoritative
- config/bootstrap/discovery shells are explicitly secondary

Current drifts:

- hybrid discovery/config surfaces still outrank measured projections in several runtime paths

Primary files:

- [surface.py](/opt/skg/skg/intel/surface.py)
- [daemon.py](/opt/skg/skg/core/daemon.py)
- [utils.py](/opt/skg/skg/cli/utils.py)
- [energy.py](/opt/skg/skg/topology/energy.py)

Exit criteria:

- `/surface`, timeline views, and operator summaries all derive from measured workload/identity state first
- config/bootstrap artifacts are labeled as seed state, not treated as measured state

Required tests:

- measured surface wins over stale discovery surface
- identity/workload summaries remain correct across host, binary, data, and web locals

### Layer 6: Gravity And Selection

Primary question:

- does gravity operate on field state, or on target-row convenience state?

Required answer:

- gravity consumes measured locals, folds, pearls, and fibers
- target rows are derived compatibility views only

Current drifts:

- selection still starts from hydrated target rows and service heuristics
- focused runs can still bleed across unrelated work

Primary files:

- [gravity_field.py](/opt/skg/skg-gravity/gravity_field.py)
- [selection.py](/opt/skg/skg/gravity/selection.py)
- [engine.py](/opt/skg/skg/kernel/engine.py)
- [field_functional.py](/opt/skg/skg/kernel/field_functional.py)
- [landscape.py](/opt/skg/skg/gravity/landscape.py)

Exit criteria:

- gravity selection is explainable in substrate terms
- focused runs stay scoped to the intended identity/workload
- pearl and fiber effects are modifiers over measured uncertainty, not substitutes for it

Required tests:

- focused gravity run touches only the selected subject set
- gravity candidate generation from measured locals only
- pearl reinforcement and fiber coupling remain bounded and reproducible

### Layer 7: Wrappers And Shells

Primary question:

- do operator-facing paths report substrate truth faithfully?

Required answer:

- CLI, API, and UI are truthful adapters over substrate state
- they do not invent or flatten alternate authority

Current drifts:

- some CLI paths still claim success too early
- some API/UI flows still depend on slow or hybrid surfaces
- target-oriented naming still leaks into core views

Primary files:

- [app.py](/opt/skg/skg/cli/app.py)
- `skg/cli/commands/*`
- [daemon.py](/opt/skg/skg/core/daemon.py)
- [app.js](/opt/skg/ui/app.js)

Exit criteria:

- observe/collect/exploit/report/status all reflect real substrate outcomes
- APIs and UI render partial truth instead of blocking on slow secondary endpoints
- node/workload/identity language becomes primary, with `target` retained only as compatibility terminology where needed

Required tests:

- CLI integration tests for truthful failure/success
- API regression tests for partial renderability
- UI tests for non-blocking load behavior

## Execution Order

The order should be strict:

1. Layer 0
2. Layer 1
3. Layer 2
4. Layer 3
5. Layer 4
6. Layer 5
7. Layer 6
8. Layer 7

Do not start gravity cleanup before the measured surface is authoritative.
Do not start wrapper cleanup before the projection and temporal contracts are stable.
Do not touch higher-layer naming before the subject model is fixed.

## Immediate Starting Point

The next actual implementation phase should start at Layer 0 and Layer 1 together, because they are the substrate admission boundary:

- canonical subject identity
- canonical observation event shape

That means the first concrete work package should be:

1. remove trailing-token target resolution from core substrate paths
2. define required event fields for all `obs.attack.precondition` producers
3. migrate core event producers onto the shared envelope helpers
4. add contract tests before moving upward

## Definition Of Done

This remediation effort is only complete when:

- the same observation means the same thing everywhere in SKG
- the same projection means the same thing everywhere in SKG
- pearls record substrate memory across the real loop, not just selected subsystems
- gravity consumes measured substrate state rather than wrapper convenience state
- CLI, API, and UI become faithful views over that substrate

Until then, higher-layer polish should be treated as secondary.

