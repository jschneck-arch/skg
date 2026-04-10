# SKG Identity / Memory / Topology Audit

**Date:** 2026-03-27  
**Scope:** Core folds, pearls, pearl manifold, and topology layers. Audit/documentation pass. No runtime code changes.

## Summary

This layer of SKG is in a better state than the outer target shell, but it is still not fully unified.

The strongest result from this pass is:

- **pearls and the pearl manifold are the most identity-aligned memory layer in core SKG**
- **folds are mixed: temporal folds are identity-aware, but structural/contextual/projection folds still use heterogeneous location strings**
- **topology is identity-aware at the cluster level, but it is still assembled from daemon target/world shells and contains a few internal semantic mismatches**

That means the core memory geometry is not fake or absent. But it is not yet cleanly substrate-native either.

## Architectural Standard From The Docs

Work 4 is explicit about what these layers are supposed to mean:

- `docs/SKG_Work4_Final.md:179`-`docs/SKG_Work4_Final.md:185`
  - Field locals are grouped by `(workload_id, domain_label)`.
  - Field clusters are all fibers for one **anchor identity**.
- `docs/SKG_Work4_Final.md:310`-`docs/SKG_Work4_Final.md:317`
  - pearl memory is keyed by `(identity_key, domain_label)` and contributes bounded `wavelength_boost`.
- `docs/SKG_Work4_Final.md:373`-`docs/SKG_Work4_Final.md:379`
  - the pearl ledger is append-only history of field transformations
  - pearl clusters are groups of pearls for the same `(identity_key, domain_label)`
  - explicit multi-expression fiber clusters for the same identity key participate directly in selection
- `README.md:40`-`README.md:47`
  - `kernel`, `identity`, and `topology` are core architecture layers, not toolchain afterthoughts.

So the intended structure is:

- pearls preserve transformed field history
- pearl neighborhoods reinforce memory by identity and domain
- fibers and clusters are anchored on identity
- folds represent missing structure in the field, not just "things wrong with a host row"

## What Works

Several parts of this layer are already aligned with the docs.

### 1. Pearl records are enriched with identity metadata

- `skg/kernel/pearls.py:16`-`skg/kernel/pearls.py:43` enriches pearls with:
  - `workload_id`
  - `identity_key`
  - `manifestation_key`
- `skg/kernel/pearls.py:121`-`skg/kernel/pearls.py:124` applies that enrichment on record.

This is a strong compatibility pattern: existing append-only pearl structure is preserved while identity metadata is normalized into it.

### 2. Pearl neighborhoods are grouped by `(identity_key, domain)`

- `skg/kernel/pearl_manifold.py:106`-`skg/kernel/pearl_manifold.py:155` groups pearls by `(identity_key, domain)`.
- `skg/kernel/pearl_manifold.py:129`-`skg/kernel/pearl_manifold.py:152` preserves `manifestation_keys` separately from the identity anchor.
- `skg/kernel/pearl_manifold.py:157`-`skg/kernel/pearl_manifold.py:255` applies recall, growth, and wavelength reinforcement by identity-aware host filters.

This is one of the clearest examples of the code following the Work 4 memory model.

### 3. Temporal folds already deduplicate across manifestations by identity

- `skg/kernel/folds.py:490`-`skg/kernel/folds.py:531` tracks latest realized evidence by `(identity_key, wicket_id)`.
- `skg/kernel/folds.py:589`-`skg/kernel/folds.py:615` creates temporal folds with `location=identity_key`.

This is materially better than the older host/IP-centric pattern. It means stale evidence is treated as stale field state for an identity, not as separate unrelated decay per manifestation string.

### 4. Fiber clusters are grouped by identity in topology

- `skg/topology/energy.py:1175`-`skg/topology/energy.py:1225` builds `FiberCluster` objects grouped by identity key.
- `skg/topology/energy.py:1206`-`skg/topology/energy.py:1207` merges pearl-memory fibers into those identity-anchored clusters.

That is directly in line with `docs/SKG_Work4_Final.md:185`.

### 5. There is meaningful regression coverage in this area

Positive coverage exists for the main identity-aware behavior:

- `tests/test_sensor_projection_loop.py:944`-`tests/test_sensor_projection_loop.py:955`
  - pearl ledger identity enrichment
- `tests/test_sensor_projection_loop.py:957`-`tests/test_sensor_projection_loop.py:1006`
  - temporal fold dedup across manifestations by identity
- `tests/test_sensor_projection_loop.py:1037`-`tests/test_sensor_projection_loop.py:1124`
  - pearl manifold grouping and identity-based recall/growth/wavelength behavior
- `tests/test_sensor_projection_loop.py:2213`-`tests/test_sensor_projection_loop.py:2235`
  - `compute_field_fibers()` clustering world strands by identity
- `tests/test_sensor_projection_loop.py:1995`-`tests/test_sensor_projection_loop.py:2036`
  - topology protected/curvature decomposition

So this layer is not only present; parts of it are already intentionally tested.

## Where The Layer Is Still Split

### 1. There is no authoritative kernel identity registry in use

- `skg/kernel/identities.py:12`-`skg/kernel/identities.py:33` defines `Identity` and `IdentityRegistry`.
- A repo-wide search shows it is effectively unused outside exports.

In practice, identity semantics are coming from:

- `skg.identity.parse_workload_ref()`
- ad hoc enrichment in pearls
- daemon world builders
- topology helpers

So the codebase has a nominal kernel identity abstraction, but the real authority lives elsewhere. That is not broken, but it is a clear sign of drift.

### 2. Fold anchoring is inconsistent across fold types

Temporal folds are identity-aware. The others are not consistently so:

- structural folds use `location=host`
  - `skg/kernel/folds.py:372`-`skg/kernel/folds.py:394`
- contextual folds use `location=f"cve::{target_ip}"`
  - `skg/kernel/folds.py:433`-`skg/kernel/folds.py:466`
- projection folds use either `location=host` or `location=wid`
  - `skg/kernel/folds.py:670`-`skg/kernel/folds.py:700`
  - `skg/kernel/folds.py:728`-`skg/kernel/folds.py:760`
- only temporal folds use `location=identity_key`
  - `skg/kernel/folds.py:589`-`skg/kernel/folds.py:615`

This means `Fold.location` is currently overloaded across:

- host/IP strings
- workload IDs
- `cve::target_ip` pseudo-locations
- identity keys

That makes the fold layer harder to treat as one coherent substrate concept.

### 3. Fold persistence is still per-IP in gravity/runtime

- `skg-gravity/gravity_field.py:6652`-`skg-gravity/gravity_field.py:6668` reassigns folds to targets by substring matching:
  - `if tip in fold.location or fold.location.endswith(tip)`
  - then persists them as `folds_<ip>.json`
- `skg-gravity/gravity_field.py:475`-`skg-gravity/gravity_field.py:491` loads persisted fold managers per IP.
- `skg/core/daemon.py:875`-`skg/core/daemon.py:888` also loads fold summaries per IP from those filenames.

So even though temporal folds are identity-aware internally, the runtime storage and lookup layer still partitions active fold state by IP. That is a direct shell-first seam.

### 4. Pearl memory still preserves target-shell fallback semantics

- `skg/kernel/pearls.py:24`-`skg/kernel/pearls.py:29` falls back to `gravity::{target_ip}` when no workload ID exists.
- `skg/kernel/pearl_manifold.py:30`-`skg/kernel/pearl_manifold.py:45` keeps the same fallback pattern.

This is understandable as backward compatibility, but it means pearls are not natively workload/identity-first all the way down. Identity is enriched into the record after the older target snapshot is accepted.

### 5. Topology still depends on daemon target/world shells

- `skg/topology/energy.py:947`-`skg/topology/energy.py:970` builds runtime world states by importing daemon `_all_targets_index()` and `_identity_world()`.
- `skg/topology/energy.py:1175`-`skg/topology/energy.py:1225` builds field fibers from the daemon registry layer, not directly from measured workload locals.

That means topology is not an independent substrate view. It is downstream of the daemon's target/world formation layer.

This is especially important because earlier audits already showed that `_all_targets_index()` and the hybrid surface shell are not purely measured authority surfaces.

### 6. Topology injects world and pearl states as realized sphere observations

- `skg/topology/energy.py:793`-`skg/topology/energy.py:864` turns surface domains/services into realized `WicketState` entries.
- `skg/topology/energy.py:867`-`skg/topology/energy.py:970` turns daemon world snapshots into realized `WicketState` entries.
- `skg/topology/energy.py:973`-`skg/topology/energy.py:1049` turns pearl aggregates into realized `WicketState` entries.
- `skg/topology/energy.py:1351`-`skg/topology/energy.py:1361` merges all of those into field energy computation.

Some of this was already noted in the measured-authority audit. It matters again here because the topology layer is mixing:

- measured path-derived state
- hybrid world/surface supplements
- memory-derived supplements

That makes topology rich, but not cleanly grounded.

### 7. `Fiber.anchor` is semantically overloaded

The dataclass says one thing:

- `skg/topology/energy.py:375`-`skg/topology/energy.py:389`
  - `Fiber.anchor` is documented as the anchor identity.

But `_world_snapshot_fibers()` does something else:

- `skg/topology/energy.py:1059`-`skg/topology/energy.py:1109`
  - credential-binding fibers use `anchor=service`
  - access-path fibers use `anchor=service`
  - datastore fibers use `anchor=service`
  - relation fibers use `anchor=relation_name`

And the tests codify that overloaded meaning:

- `tests/test_sensor_projection_loop.py:2211`
  - expects a relation fiber with `f.anchor == "docker_host"`

So the cluster layer is identity-anchored, but the `Fiber.anchor` field inside it is not consistently an identity anchor. That is a real semantic mismatch between code comments, paper language, and runtime behavior.

### 8. Domain-to-sphere mapping is inconsistent between kernel and topology

- `skg/kernel/field_functional.py:45`
  - `"binary_analysis": "binary"`
- `skg/topology/energy.py:76`
  - `"binary_analysis": "host"`

This is a concrete cross-layer inconsistency.

The field-functional layer treats binary analysis as its own binary sphere. The topology layer collapses it into host. That means memory/topology and field-functional computations can disagree about where binary-derived structure belongs.

This is one of the clearest line-by-line mismatches found in this pass.

## What This Means

This layer is not uniformly target-shell driven.

In fact, pearls and temporal folds show the opposite: some of the strongest identity-aware behavior in SKG lives here already.

But the layer is still split in three ways:

1. **identity semantics are distributed**
   - `parse_workload_ref()`
   - pearl enrichment
   - daemon world formation
   - topology helpers
   - dormant `IdentityRegistry`

2. **fold semantics are heterogeneous**
   - temporal folds act like identity-level field gaps
   - structural/contextual/projection folds still act like target/location gaps
   - runtime persistence pushes all of them back into per-IP files

3. **topology is cluster-aware but shell-dependent**
   - cluster assembly uses identity keys
   - but the inputs come from daemon target/world shells and hybrid state injections

So the honest characterization is:

**memory is ahead of topology, and topology is ahead of fold persistence**

That is a useful finding, because it means the identity-first pieces already exist. They are just not yet governing the whole layer consistently.

## Test Gaps

Existing coverage is better here than in several other core areas, but important gaps remain.

Covered:

- pearl identity enrichment
- temporal fold dedup by identity
- pearl manifold grouping and reinforcement by identity
- topology cluster assembly by identity
- basic protected-sphere / curvature decomposition

Missing or under-covered:

- structural fold dedup across multiple manifestations of the same identity
- contextual/projection fold normalization to identity or workload locals
- per-IP fold persistence versus identity-scoped fold semantics
- `Fiber.anchor` semantic consistency
- topology behavior when daemon registry is unavailable
- consistency between `field_functional.py` and `topology/energy.py` sphere mappings
- non-IP identity anchors and non-host manifestations

## Conclusion

The folds / pearls / topology layer is not uniformly broken. Parts of it are some of the most substrate-aligned code in core SKG.

The clearest positive result is that pearl memory already behaves much more like the Work 4 model than the outer runtime shell does.

The clearest negative result is that this layer still contains several authority and semantics splits:

- folds are not consistently anchored the same way
- topology still depends on daemon target/world shells
- `Fiber.anchor` does not mean one thing consistently
- binary sphere placement disagrees across layers

The central audit conclusion from this pass is:

**identity-aware field memory is already real in SKG, but it is still wrapped in mixed fold and topology semantics that have not fully escaped the older target/IP shell.**
