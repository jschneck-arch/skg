# SKG Node Model Audit

**Date:** 2026-03-27  
**Scope:** Core SKG only. Audit/documentation pass. No runtime code changes.

## Summary

The docs already define SKG in domain-agnostic terms, but the live runtime only partially follows that model.

At the formal level, SKG is node-first:

- Work 3 defines the substrate over a node set `N`, telemetry map `T`, and constraint surface `κ`; nodes are measurable preconditions, not hosts or targets (`docs/SKG_Work3_Final.md:13`, `docs/SKG_Work3_Final.md:39`).
- Work 4 explicitly corrects the deployment-language drift of earlier papers: "host", "web", "SMB", and "data" are namespaces, not substrate categories (`docs/SKG_Work4_Final.md:37`-`docs/SKG_Work4_Final.md:41`).
- The substrate's active field objects are indexed by `(workload_id, domain_label)`, and field clusters are anchored by identity, not by "target" as a primitive (`docs/SKG_Work4_Final.md:179`-`docs/SKG_Work4_Final.md:185`).
- The README repeats the same claim: observations are primary objects, and `skg/substrate/` plus `skg/identity/` are the core abstractions (`README.md:3`, `README.md:39`-`README.md:48`).

In code, that architecture exists, but the operational shell around it is still heavily target/IP-centric. The result is not that SKG lacks a node model. The result is that the node model is not yet the primary organizing abstraction of the live runtime.

The central drift is semantic collapse:

1. `node` in the formal substrate means a measurable condition / wicket.
2. `workload` in the runtime means a domain manifestation of an identity.
3. `identity` is the anchor that connects manifestations.
4. `target` is still used in large parts of the runtime as the public name for "the thing being observed", but in practice it often collapses host, locator, identity, and workload into one IP-keyed object.

That collapse is the main reason SKG still feels more security-target oriented than truly domain-agnostic.

## Architectural Standard From The Docs

The papers are consistent on the model SKG is supposed to obey:

- `docs/SKG_Work3_Final.md:13` defines SKG over a node set, not over a host set.
- `docs/SKG_Work3_Final.md:61`-`docs/SKG_Work3_Final.md:67` defines projections over sets of preconditions.
- `docs/SKG_Work4_Final.md:37`-`docs/SKG_Work4_Final.md:41` states explicitly that domain labels are annotation, not substrate structure.
- `docs/SKG_Work4_Final.md:65`-`docs/SKG_Work4_Final.md:76` assigns domain-specific knowledge to the expression/toolchain boundary, not the substrate.
- `docs/SKG_Work4_Final.md:179`-`docs/SKG_Work4_Final.md:185` defines field locals by `(workload_id, domain_label)` and clusters by anchor identity.

So the correct canonical object stack is:

- `Node`: measurable condition / wicket / precondition.
- `Workload`: domain manifestation carrying measurements for one identity.
- `Identity`: anchor tying manifestations together.
- `Target`: at most an operator or deployment-facing alias for a manifestation or locator, not a substrate primitive.

## What Already Matches The Node Model

Several core files are already much closer to the intended design.

### 1. Substrate types are explicitly node-first

- `skg/substrate/node.py:4`-`skg/substrate/node.py:12` defines a node as the atomic unit of the information field and explicitly distinguishes substrate semantics from domain skin.
- `skg/substrate/node.py:66`-`skg/substrate/node.py:144` models node state as epistemic state over a `node_id`, not as a host record.
- `skg/substrate/path.py:4`-`skg/substrate/path.py:12` defines paths as ordered sequences of node preconditions.
- `skg/substrate/path.py:19`-`skg/substrate/path.py:86` keeps `Path` and `PathScore` centered on required nodes, with `workload_id` carried as context rather than replacing the node model.

This is the clearest evidence that base SKG has not conceptually lost the substrate.

### 2. Identity parsing is already a good bridge away from raw target strings

- `skg/identity/__init__.py:43`-`skg/identity/__init__.py:68` is one of the healthiest bridge points in the runtime.
- `parse_workload_ref()` keeps `workload_id` as manifestation, derives `identity_key`, and exposes `domain_hint`, `locator`, and `host` without pretending they are identical.

This is exactly the kind of compatibility helper the codebase needs: it preserves current behavior while making the deeper model visible.

### 3. Surface synthesis is closer to workload/identity semantics than older runtime paths

- `skg/intel/surface.py:164`-`skg/intel/surface.py:220` builds the operator-facing measured surface from projections keyed by `workload_id`, then derives `identity_key` and `manifestation_key` through `parse_workload_ref()`.

This is materially closer to Work 4 than the older `surface_*.json` target snapshots.

### 4. Graph identity handling is partly aligned

- `skg/graph/__init__.py:106`-`skg/graph/__init__.py:111` uses `parse_workload_ref()` to compare workloads by identity instead of by raw workload string.

That is the right direction: coupling and relation logic should operate on identity and manifestation, not on raw IP text.

## Where The Runtime Is Still Target-Centric

The following are not minor naming issues. They are places where target/IP semantics still shape the actual control flow.

### 1. The kernel observation object is still target-list oriented

- `skg/kernel/observations.py:13`-`skg/kernel/observations.py:28` defines `Observation` with `targets: List[str]` and `context: str`.
- `skg/kernel/observations.py:41`-`skg/kernel/observations.py:45` exposes `by_target()`.

This means the core compatibility observation type is still organized around "which targets did this observation hit?" rather than around:

- which node/precondition it bears on
- which workload manifestation emitted it
- which identity it belongs to

For a security deployment this is survivable. For a domain-agnostic substrate it is backwards: targets are one possible locator, not the canonical object.

### 2. The kernel engine still computes by `target_ip`

- `skg/kernel/engine.py:149`-`skg/kernel/engine.py:153` loads observations by `target_ip`.
- `skg/kernel/engine.py:155`-`skg/kernel/engine.py:177` computes states for a `target_ip`.
- `skg/kernel/engine.py:179`-`skg/kernel/engine.py:239` computes detailed states for a `target_ip`.
- `skg/kernel/engine.py:241`-`skg/kernel/engine.py:271` computes energy for a `target_ip`.
- `skg/kernel/engine.py:273` onward computes instrument potential for a `target_ip`.

This is a major conceptual mismatch. Work 3 field energy is over applicable nodes; Work 4 locals are `(workload_id, domain_label)`. The kernel engine is still acting like the central problem is "what is the state of this IP?"

### 3. Gravity selection is still explicitly "for target"

- `skg/gravity/selection.py:64` defines `rank_instruments_for_target`.
- `skg/gravity/selection.py:66`-`skg/gravity/selection.py:69` takes `target_row` and `focus_target`.
- `skg/gravity/selection.py:78` binds the object to `ip = target_row["ip"]`.
- `skg/gravity/selection.py:86`-`skg/gravity/selection.py:99` evaluates service history and cold-start logic from the target row's IP/service view.
- `skg/gravity/selection.py:170`-`skg/gravity/selection.py:205` chooses instruments for a target and prints bootstrap state in target terms.

This is not just vocabulary. Gravity's ranking substrate is still populated by target-centric discovery rows instead of by a node/workload/identity field view. That keeps the scheduler coupled to the security deployment shell.

### 4. The daemon's public API is still target-first

- `skg/core/daemon.py:1419`-`skg/core/daemon.py:1452` exposes `/targets` as the primary summary route.
- `skg/core/daemon.py:1423`-`skg/core/daemon.py:1430` merges rows by `ip` / `host` / `workload_id`, but still privileges the host/IP form when choosing the identity key.
- `skg/core/daemon.py:1455`-`skg/core/daemon.py:1464` exposes `/world/{identity_key}`, but then resolves the backing row by matching `(ip or host) == identity_key`.
- `skg/core/daemon.py:1732`-`skg/core/daemon.py:1775` builds `_all_targets_index()` from `targets.yaml`, `surface_*.json`, and configured locals.
- `skg/core/daemon.py:1778`-`skg/core/daemon.py:1825` computes identity relations from `ip`, subnet families, and host-style heuristics.
- `skg/core/daemon.py:2013`-`skg/core/daemon.py:2117` produces a much healthier identity world object, but it is still passed a `target` dict whose service and kind fields come from the target index layer.

The daemon therefore contains both models:

- a better identity/workload world view
- an older target/IP aggregation shell

The older shell still dominates operator entry points.

### 5. CLI utilities treat the discovery surface as a mutable target registry

- `skg/cli/utils.py:95`-`skg/cli/utils.py:116` loads and writes a surface object whose top-level collection is `targets`.
- `skg/cli/utils.py:119`-`skg/cli/utils.py:168` injects local runtime endpoints as observable targets.
- `skg/cli/utils.py:209`-`skg/cli/utils.py:227` registers a new target directly into the surface file.
- `skg/cli/utils.py:230`-`skg/cli/utils.py:264` merges web observations into that same target surface.
- `skg/cli/utils.py:267`-`skg/cli/utils.py:312` persists target config and bootstraps target surface from IP scans.

This is a strong sign that the hybrid discovery surface is still acting as an authority object, not just as a convenience artifact.

### 6. The main CLI is target-first all the way down

- `skg/cli/commands/target.py:19`-`skg/cli/commands/target.py:29` implements `skg target add`.
- `skg/cli/commands/target.py:42`-`skg/cli/commands/target.py:80` removes a target from surfaces, config, and artifacts by IP.
- `skg/cli/commands/target.py:164`-`skg/cli/commands/target.py:171` defines observation as "trigger observation on a target".
- `skg/cli/commands/target.py:211`-`skg/cli/commands/target.py:245` drives SSH collection with a `target` payload keyed by IP/host/workload alias.
- `skg/cli/commands/target.py:267`-`skg/cli/commands/target.py:289` hands gravity a `--target` argument.

This is the public shape of the system. Even if deeper layers are more substrate-aligned, operators are still encouraged to think in terms of mutable targets rather than measured identities, manifestations, and nodes.

### 7. Compatibility helpers still privilege `target_ip` in substrate-adjacent code

- `skg/substrate/projection.py:195`-`skg/substrate/projection.py:201` derives the subject from `payload.get("target_ip") or payload.get("workload_id")`, then strips to the last `::` segment.
- `skg/temporal/feedback.py:24`-`skg/temporal/feedback.py:43` still infers domain from filenames and payload hints.
- `skg/temporal/feedback.py:46`-`skg/temporal/feedback.py:71` derives workload/run/target hints heuristically from filenames and free text.

These bridges are understandable as compatibility code, but they show that canonical runtime truth is still too dependent on deployment-era filename and target conventions.

## What This Means

The problem is not simply "rename `target` to `node`."

That would be incorrect, because `node` in SKG's formal model is a precondition, not a host or service row.

The real conceptual repair is:

1. Stop treating `target` as the canonical substrate noun.
2. Preserve `target` only where it is genuinely deployment-facing or domain-specific.
3. Make the live core runtime consistently distinguish:
   - `node`: measurable condition / wicket
   - `workload`: one domain manifestation
   - `identity`: anchor across manifestations
   - `locator` or `target`: one operator-facing way to reach or name a manifestation

Right now those layers are present, but too many code paths still collapse them back to the IP row.

## What Should Be Preserved

This audit is not a removal argument.

Several target-centric constructs may still have valid roles if they are demoted to the right layer:

- security-specific discovery snapshots
- operator convenience surfaces
- bootstrap host/IP locators
- compatibility helpers for legacy events and filenames
- CLI verbs that remain useful for security engagements

The issue is authority, not mere existence. These constructs should not be the canonical definition of what SKG is.

## Test Gaps

The current tests do not appear to exercise the node-vs-target boundary directly.

Evidence of partial coverage:

- `tests/test_runtime_regressions.py:211` checks `parse_workload_ref()` on a binary workload.
- `tests/test_gravity_runtime.py:456` covers `rank_instruments_for_target()`.
- `tests/test_sensor_projection_loop.py:2224` touches `_all_targets_index()` through the daemon registry shim.

Missing or underrepresented coverage:

- kernel observation behavior when the same identity has multiple manifestations
- kernel state/energy computation keyed by workload or identity rather than raw target IP
- daemon/API behavior where identity and target diverge
- CLI/surface behavior for non-IP or non-host manifestations
- invariants asserting that node/precondition semantics are not replaced by host rows

## Conclusion

Base SKG is not conceptually lost. The substrate files, identity bridge, and measured surface logic show that the domain-agnostic model is real in the codebase.

But the live runtime still presents and drives SKG primarily through a target/IP shell. That shell is now the main obstacle to conceptual unification.

The most important audit conclusion from this pass is:

`target` should no longer be treated as the default name for the thing SKG fundamentally reasons over.

SKG fundamentally reasons over measured nodes, organized into workload locals, anchored by identity. Targets are deployment artifacts and operator handles. The codebase already contains that model; it is just not yet consistently allowed to govern the runtime.
