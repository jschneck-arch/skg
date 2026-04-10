# SKG Event And Pearl Contract Audit

Date: 2026-03-27

## Scope

This pass audits the canonical substrate contract from emitted observation to projected state to memory:

- canonical `obs.attack.precondition` event construction
- adapter and sensor handoff into the substrate
- projector output shape
- feedback and delta ingestion
- observation-memory closure
- pearl recording and pearl-manifold reuse

The standard used here is the substrate-first contract stated in:

- `README.md:3-19`
- `docs/SKG_CLOSED_OBSERVATION_LOOP.md:3-10`
- `docs/SKG_Work4_Final.md:132-155`
- `docs/SKG_Work4_Final.md:308-317`
- `docs/SKG_Work4_Final.md:373-379`

Those documents make four claims that matter for this audit:

1. Observations are primary substrate objects.
2. The adapter is the only domain boundary.
3. Once emitted, canonical events are processed identically by the substrate.
4. Pearls are part of SKG memory, recording transformations of the field across domain expressions.

## Summary

The core contract exists, but it is not yet uniform.

There is a real canonical path:

- sensors can emit compliant envelope events through `skg/sensors/__init__.py:71-177`
- projectors can run in-process through `skg/sensors/projector.py:321-477`
- the measured surface can read both wrapped and unwrapped projection payloads through `skg/intel/surface.py:80-126`
- pearls are real kernel memory through `skg/kernel/pearls.py:46-124` and `skg/kernel/pearl_manifold.py:94-255`

The main break is that the contract changes shape mid-stream:

- event construction is not centralized in practice
- projector compute functions do not agree on output shape
- feedback and delta still assume a top-level projection payload in places where wrapped interps are now common
- pearl recording is real but incomplete, and remains gravity-centric rather than substrate-wide

So the substrate is present, but the observation-to-memory path is still heterogeneous.

## What Works

### 1. A canonical observation envelope exists

`skg/sensors/__init__.py:71-177` defines a real envelope and precondition payload contract:

- stable event envelope
- provenance structure
- confidence, local energy, phase, and latent-state hints
- `wicket_id` plus `node_id` aliasing

This is substrate-aligned and is the right center of gravity.

### 2. Some sensors already obey the canonical path

Examples of sensors using the shared helpers rather than ad hoc event dicts:

- `skg/sensors/net_sensor.py:295-310`
- `skg/sensors/msf_sensor.py:270-285`
- `skg/sensors/cve_sensor.py:179-193`

These paths are closer to the design in `docs/SKG_Work4_Final.md:132-155` because the adapter/sensor output is normalized before it reaches the rest of SKG.

### 3. Projector dispatch and metadata normalization are real

`skg/sensors/projector.py:185-204` normalizes event status and toolchain names.

`skg/sensors/projector.py:289-318` normalizes interp metadata and names results per `(domain, workload_id, attack_path_id, run_id)`.

That is a real substrate service, not a toolchain-local behavior.

### 4. Pearl memory is real and integrated into field selection

Pearls are not incidental:

- ledger and identity enrichment: `skg/kernel/pearls.py:16-124`
- pearl neighborhoods and reinforcement: `skg/kernel/pearl_manifold.py:94-255`
- field functional includes pearl persistence: `skg/kernel/field_functional.py:182-187`
- gravity selection applies pearl reinforcement: `skg/gravity/selection.py:116-120`

On this point, the code agrees with `docs/SKG_Work4_Final.md:308-317` and `docs/SKG_Work4_Final.md:373-379`: pearls are part of SKG.

### 5. Observation memory is identity-aware

`skg/resonance/observation_memory.py:156-199` stores:

- `workload_id`
- `identity_key`
- emitted confidence
- local energy
- phase
- latent flag

That is materially aligned with substrate-side memory rather than raw target-shell bookkeeping.

## Critical Contract Drifts

### 1. Wrapped interp results do not flow cleanly into feedback, delta, or observation closure

This is the highest-value substrate mismatch in this pass.

`skg/sensors/projector.py:289-309` and `skg/sensors/projector.py:321-427` explicitly preserve both interp shapes:

- top-level payload dict
- wrapped envelope with nested `payload`

The projector layer therefore accepts mixed projector conventions.

That mix is real in the codebase:

- wrapped interp returned directly from compute function:
  - `skg-binary-toolchain/projections/binary/run.py:34-42`
  - `skg-data-toolchain/projections/data/run.py:104-126`
  - `skg-web-toolchain/projections/web/run.py:79-101`
- top-level payload returned from compute function:
  - `skg-host-toolchain/projections/host/run.py:130-154`

The feedback layer only partially adapts to that mix:

- `skg/temporal/feedback.py:178-188` unwraps payload for metadata lookup
- but `skg/temporal/feedback.py:190-197` passes the original `interp` object into `DeltaStore.ingest_projection()`
- `skg/temporal/feedback.py:254-266` also reads `realized/blocked/unknown` from the top level when closing observations

`DeltaStore.ingest_projection()` still expects the projection content at the top level:

- `skg/temporal/__init__.py:235-295`

Verified locally:

- a wrapped binary interp ingested through `DeltaStore.ingest_projection()` produced one snapshot with:
  - empty `attack_path_id`
  - empty `wicket_states`

That means wrapped domains can successfully write interp files and still fail to enter temporal memory correctly.

Impact:

- timeline state can silently under-report or miss wrapped projector results
- observation-memory pending records may not be closed for wrapped interps
- the closed observation loop in `docs/SKG_CLOSED_OBSERVATION_LOOP.md:3-10` is only fully correct for some projector shapes

### 2. Core event-to-observation target resolution still collapses workload identity to the last `::` token

The substrate still contains target-shell assumptions that are wrong for node/workload locals.

`skg/kernel/adapters.py:107-113` resolves target as:

- `payload.target_ip`, else
- `payload.workload_id.split("::")[-1]`

The same assumption appears in:

- `skg/kernel/adapters.py:268-274`
- `skg-host-toolchain/projections/host/run.py:51-69`
- `skg/substrate/projection.py:235-255`

Verified locally:

- an event with `workload_id="binary::192.168.254.5::ssh-keysign"` becomes an `Observation` with target `ssh-keysign`

That is not a node-agnostic substrate interpretation. It is a string shortcut that treats the trailing artifact/table name as the target anchor.

Impact:

- binary and data locals can be support-aggregated against the wrong subject
- `load_observations_for_target()` can skip valid observations for a host because the inferred target does not equal the host IP
- the node/workload model defined in the docs is still being reduced back into a target string at a core boundary

### 3. The envelope contract exists, but event construction is still fragmented

The canonical helpers are present in `skg/sensors/__init__.py:71-177`, but many event producers still hand-roll envelopes.

Examples using the canonical helper path:

- `skg/sensors/net_sensor.py:295-310`
- `skg/sensors/msf_sensor.py:270-285`
- `skg/sensors/cve_sensor.py:179-193`

Examples bypassing it:

- `skg/sensors/web_sensor.py:578-608`
- `skg/sensors/ssh_sensor.py:154-178`
- `skg/sensors/adapter_runner.py:327-345`
- `skg-gravity/gravity_field.py:3908-3923`

The practical result is a mixed event contract:

- some paths emit both `wicket_id` and `node_id`
- some omit `node_id`
- some carry `target_ip`
- some rely on `workload_id`
- some carry domain in payload
- some infer it later from toolchain name or filename

This violates the claim in `docs/SKG_Work4_Final.md:132-155` that the adapter is the clean and singular boundary into canonical substrate events.

### 4. Pearls are part of SKG, but pearl recording is not substrate-wide

The docs define pearls as append-only memory of field transformations across domain expressions:

- `docs/SKG_Work4_Final.md:373-379`

The runtime implements real pearl memory, but records only some classes of transformations.

Actual pearl write sites in core/runtime:

- gravity cycle pearl: `skg-gravity/gravity_field.py:5477-5606`
- proposal lifecycle memory: `skg/forge/proposals.py:104-146`
- fold resolution memory: `skg/core/daemon.py:4048-4065`

What is missing is just as important:

- `skg/temporal/feedback.py:176-252` processes projection consequences but does not record pearls
- direct projector runs that update interp state outside a gravity cycle do not themselves create pearl records

So pearls are implemented, but not yet as the append-only memory of all significant field transformations. They are currently strongest around:

- gravity cycle summaries
- proposal lifecycle events
- selected operator actions

Impact:

- pearl memory under-represents direct observe/project transitions
- pearl neighborhoods can lag real substrate history
- memory curvature is real but incomplete

## Medium Drifts

### 5. Silent parse/drop behavior still exists at several contract boundaries

Malformed state is often discarded without operator-visible signal.

Examples:

- adapter NDJSON read silently drops bad lines: `skg/sensors/adapter_runner.py:61-72`
- projector event-file grouping silently skips unreadable events: `skg/sensors/projector.py:446-453`
- feedback state load silently resets on parse error: `skg/temporal/feedback.py:122-128`
- observation closure swallows matching errors: `skg/temporal/feedback.py:271-293`
- measured surface silently skips unreadable interp files: `skg/intel/surface.py:85-121`
- pearl ledger load resets to empty on load failure: `skg/kernel/pearls.py:103-113`

This weakens the “observations are primary” claim because malformed primary evidence can disappear without an explicit integrity failure.

### 6. Observation closure still relies on workload and target-string heuristics

`skg/temporal/feedback.py:271-292` matches pending observations by:

- exact workload match, or
- target-hint substring match

That is a compatibility bridge, not a canonical identity/workload join.

This is workable as a transitional shim, but it is not the node/workload-first contract the docs describe.

## Pearls In SKG

This pass confirms that pearls must stay in the definition of core SKG.

They are not “extra memory” or “adapter output history.” They are already part of the base field machinery:

- ledger: `skg/kernel/pearls.py`
- manifold: `skg/kernel/pearl_manifold.py`
- functional curvature term: `skg/kernel/field_functional.py:182-187`
- scheduler reinforcement: `skg/gravity/selection.py:116-120`

So future unification should treat pearl correctness as a core requirement, not a gravity add-on.

The problem is not that pearls are out of scope. The problem is that pearl recording coverage still lags the substrate story told in the docs.

## Bottom Line

At this boundary, SKG is neither “just adapters” nor “fully unified substrate.”

It already has:

- a canonical observation envelope
- a real in-process projection layer
- a real temporal/delta layer
- a real observation-memory layer
- a real pearl-memory layer

But those layers are still connected by mixed compatibility assumptions:

- mixed event constructors
- mixed projector output shapes
- target-shell fallbacks in node/workload handling
- pearl recording that is real but not yet universal

The next core pass should stay inside SKG and trace one step upward from here:

- where daemon/world/target surfaces consume this mixed contract and turn it into operator-visible truth

