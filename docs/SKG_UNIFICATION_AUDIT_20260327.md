# SKG Unification Audit

Date: 2026-03-27

Purpose: audit the canonical SKG runtime against the current docs and classify code by role, authority, and unification status.

This is not a deletion plan.
It is a documentation pass intended to keep all code visible while making the active system legible.

## Summary

The canonical SKG runtime does exist.
It is not just a pile of domain adapters.
The base system is visible in the current live tree as:

- a domain-agnostic substrate in `skg/substrate`
- a kernel object model in `skg/kernel`
- temporal ingestion and propagation in `skg/temporal`
- identity and graph layers in `skg/identity` and `skg/graph`
- a daemon/runtime shell in `skg/core`
- a gravity runtime driver in `skg-gravity/gravity_field.py`

The main unification problem is not absence of substrate.
The problem is that several wrapper, orchestration, and compatibility layers still behave as partially independent authority surfaces.

The result is a system where the core SKG objects are real, but some intermediate layers still bypass or distort them before state reaches the substrate.

## Governing Architectural Invariants

The current docs are consistent on the following points:

- SKG is a domain-agnostic telemetry substrate, not an adapter bundle.
  - `README.md:3-7`
- observations are primary, and paths/proposals are derived over measured state.
  - `README.md:3-23`
- the core operational loop is:
  - `observe -> collapse state -> evaluate projections -> measure informational deficit -> compute gravity -> generate proposals -> operator selects actions -> observe again`
  - `SKG_CLOSED_OBSERVATION_LOOP.md:3-10`
- SKG measures rather than infers, preserves uncertainty, and should say when it reaches observational limits.
  - `SKG_Work3_Final.md:246-258`
- AI is an instrument/operator assistant and must not become substrate truth.
  - `SKG_AI_ASSISTANT_CONTRACT.md:3-26`
- there is one canonical live runtime and one preserved deploy mirror.
  - `SKG_CANONICAL_RUNTIME_MAP.md:7-18`
  - `SKG_RUNTIME_UNIFICATION_PLAN.md:8-40`

These invariants are the standard used in this audit.

## Canonical Runtime Classification

The docs explicitly define the live runtime surface as:

- `/opt/skg/bin/skg`
- `/opt/skg/skg`
- `/opt/skg/skg-gravity`
- `/opt/skg/skg-*-toolchain`
- `/opt/skg/tests`
- `/var/lib/skg/*`

References:

- `SKG_CANONICAL_RUNTIME_MAP.md:9-40`
- `SKG_RUNTIME_UNIFICATION_PLAN.md:12-40`

### Authoritative Core

- `skg/substrate`
  - formal substrate objects and projection helpers
  - `skg/substrate/__init__.py:1-27`
- `skg/kernel`
  - kernel object model: `Observation`, `StateEngine`, `ProjectionEngine`, `Fold`, `EnergyEngine`, `GravityScheduler`, `IdentityRegistry`
  - `skg/kernel/__init__.py:1-12`
- `skg/temporal`
  - feedback ingestion, deltas, temporal transitions
  - `skg/temporal/feedback.py:1-80`
- `skg/identity`
  - workload/identity parsing and identity persistence
- `skg/graph`
  - workload graph and prior propagation
- `skg/core`
  - daemon, path authority, domain registry, runtime shell

### Authoritative Runtime Driver

- `skg-gravity/gravity_field.py`
  - this is the actual active gravity loop/orchestration driver
  - it explicitly imports reusable pieces from `skg.gravity` and `skg.kernel`
  - `skg-gravity/gravity_field.py:52-68`

### Authoritative Reusable Gravity Components

- `skg/gravity`
  - reusable gravity support functions
  - failure reporting, target selection, proposal emitters
  - `skg/gravity/__init__.py:1-28`

This split is legitimate:

- `skg/gravity` is a reusable library surface
- `skg-gravity/gravity_field.py` is the runtime driver

That is not random duplication.
It is an intentional driver/library split.

### Compatibility Shims

These files are intentionally non-authoritative wrappers:

- `bin/skg`
  - repository bootstrap shim
  - `bin/skg:1-16`
- `skg/cli.py`
  - compatibility shim for older imports
  - `skg/cli.py:1-6`
- `skg-gravity/gravity.py`
  - compatibility shim delegating to `gravity_field.py`
  - `skg-gravity/gravity.py:1-47`

These should be documented as shims, not treated as parallel primary implementations.

### Preserved / Non-Canonical Trees

These are explicitly preserved by the docs and should remain classified, not deleted:

- `/opt/skg/skg_deploy`
  - preserved deploy mirror
  - `SKG_RUNTIME_UNIFICATION_PLAN.md:19-25`
- `/opt/skg/skg-web-toolchain.backup`
  - preserved backup tree
  - `SKG_RUNTIME_UNIFICATION_PLAN.md:22-25`
- `/opt/skg/forge_staging`
  - staging area for generated growth
  - `SKG_RUNTIME_UNIFICATION_PLAN.md:22-25`

## What Is Aligned

The current runtime does satisfy a meaningful portion of the documented SKG architecture:

- the kernel object model is explicit and real
  - `skg/kernel/__init__.py:1-12`
- the substrate layer is explicit and intentionally domain-agnostic
  - `skg/substrate/__init__.py:1-27`
- the gravity runtime is already consuming kernel/gravity modules rather than being completely standalone
  - `skg-gravity/gravity_field.py:52-68`
- temporal feedback is a real substrate consequence path
  - projection files are ingested into `DeltaStore` and `WorkloadGraph`
  - `skg/temporal/feedback.py:97-184`
- the domain/toolchain registry is real and materially useful
  - `skg/core/domain_registry.py:179-220`
- sensor import is dynamically discovered from `*_sensor.py`
  - `skg/sensors/__init__.py:41-56`

In other words:
the base SKG is present and active.

## Main Unification Findings

### 1. The substrate exists, but some runtime layers still bypass it through naming heuristics

The clearest example is `skg/temporal/feedback.py`.
It is a canonical runtime module, but it still infers domain and workload/run identity partly from file naming conventions:

- `_infer_domain()` uses score-key and filename heuristics
  - `skg/temporal/feedback.py:16-43`
- `_extract_workload_run()` parses filenames directly
  - `skg/temporal/feedback.py:46-64`

This means canonical temporal state is still partially coupled to adapter/projector filename behavior rather than a fully explicit registry-backed schema.

Assessment:

- canonical module
- partially unified
- should remain
- needs stronger schema authority

### 2. Gravity is only partially normalized into one runtime story

The code now has a real reusable gravity library in `skg/gravity`, but the live loop still runs out of `skg-gravity/gravity_field.py`.
That is acceptable.
The problem is that the surrounding control surfaces still mix direct module loading, subprocess execution, and comments that no longer match reality.

Examples:

- CLI loads `skg-gravity/gravity_field.py` as a file module
  - `skg/cli/commands/gravity.py:11-64`
- daemon shells out to `gravity_field.py`
  - `skg/core/daemon.py:470-500`
- daemon `_gravity_loop()` says it uses gravity logic inline to avoid subprocess overhead, but actually calls `_run_gravity_cycle()`, which shells out
  - comment: `skg/core/daemon.py:632-639`
  - subprocess path: `skg/core/daemon.py:663`

Assessment:

- the driver/library split is intentional
- the invocation story is not yet unified
- comments and runtime behavior have drifted

### 3. The operator/wrapper layer is the least unified part of the runtime

Several operator-facing paths still violate substrate-first truthfulness.

Examples already observed live:

- `observe --with ssh` posts `/collect` without credentials
  - `skg/cli/commands/target.py:211-218`
- the direct fallback hardcodes `user=root`
  - `skg/cli/commands/target.py:229-244`
- `skg collect` still has no `--password`
  - `skg/cli/app.py:185-192`
- `collect_host()` still returns `True` after `sensor.run()` even if zero events are produced
  - `skg/sensors/__init__.py:292-299`
- `SshSensor.run()` still reloads targets from config rather than consuming the passed one-target runtime config
  - `skg/sensors/ssh_sensor.py:77-95`
- UI boot still blocks on `Promise.all()` over slow endpoints
  - `ui/app.js:604-615`
- the web collector still prints a wrong follow-up command
  - `skg-web-toolchain/adapters/web_active/collector.py:1259-1263`
- the direct web projector still points at a missing catalog path
  - `skg-web-toolchain/projections/run.py:21-25`

Assessment:

- these are wrapper/intermediate-layer defects
- they do not prove the substrate is absent
- they do prove the system is not yet uniformly substrate-truthful

### 4. Bond and prior-propagation semantics are split across three surfaces

The live graph layer, the old gravity-web module, and the formal bond object are not the same thing.

Live graph runtime:

- `skg/graph/__init__.py:75-93`
  - uses `same_identity`, `same_domain`, `credential_overlap`, `same_subnet`, `network_adjacent`, `trust_relationship`

Formal bond object:

- `skg/substrate/bond.py:1-89`
  - defines `BondState` and a different older bond vocabulary and weights

Legacy gravity web:

- `skg-gravity/gravity_web.py:1-40`
  - contains an older bond vocabulary and simple prior propagation model

Import search results from the canonical live tree show:

- no canonical imports of `skg.substrate.bond`
- no canonical imports of `gravity_web.py`

Assessment:

- `skg/substrate/bond.py` looks like a formal reference object with future value
- `skg-gravity/gravity_web.py` looks like a preserved older implementation/reference
- `skg/graph/__init__.py` is the live runtime authority today

These files should be classified, not removed.
But the distinction must be documented clearly.

### 5. Proposal generation has multiple stores and histories

The active runtime now uses proposal machinery under `skg.assistant` and `skg.forge`, and the gravity runtime imports `exploit_dispatch`.
However, `skg-gravity/exploit_proposals.py` still exists as an alternative proposal store rooted at `SKG_STATE_DIR / "exploit_proposals"`.

Evidence:

- active gravity runtime uses `exploit_dispatch`
  - `rg` search on 2026-03-27 found imports from `exploit_dispatch` in `gravity_field.py` and CLI, not `exploit_proposals.py`
- `exploit_proposals.py` defines its own pending proposal storage
  - `skg-gravity/exploit_proposals.py:1-154`

Assessment:

- likely preserved earlier proposal mechanism
- not current canonical proposal path
- should be explicitly labeled as non-canonical/reference unless reactivated deliberately

### 6. Runtime comments and docs are ahead of some implementation details

The docs correctly describe one canonical runtime and a substrate-first system.
The code partially reflects that.
But some implementation surfaces still carry older operational assumptions:

- mode-oriented daemon control still exists in `skg/core/daemon.py` and `skg/modes`
  - while the conceptual docs increasingly describe a direct observation loop rather than mode-driven semantics
- `KernelStateEngine` explicitly describes itself as a surgical replacement inside `gravity_field.py`, not the full authority
  - `skg/kernel/engine.py:4-23`

Assessment:

- this is unification drift, not conceptual absence
- the direction of travel is visible, but incomplete

## Classification Matrix

| Path | Current Role | Classification | Keep Reason |
| --- | --- | --- | --- |
| `bin/skg` | CLI bootstrap | compatibility shim | stable entrypoint |
| `skg/cli.app` | authoritative CLI parser/dispatch | canonical | live operator surface |
| `skg/substrate/*` | formal substrate objects | canonical | core SKG |
| `skg/kernel/*` | kernel object model and state mechanics | canonical | core SKG |
| `skg/temporal/*` | temporal state and feedback | canonical | core SKG |
| `skg/identity/*` | identity/workload model | canonical | core SKG |
| `skg/graph/*` | live propagation graph | canonical | core SKG |
| `skg/core/daemon.py` | live daemon/runtime shell | canonical | live runtime |
| `skg/gravity/*` | reusable gravity library | canonical | active shared gravity components |
| `skg-gravity/gravity_field.py` | live gravity driver | canonical | active runtime driver |
| `skg-gravity/gravity.py` | gravity entry shim | compatibility shim | backward compatibility |
| `skg-gravity/exploit_dispatch.py` | active exploit/proposal translation | canonical runtime helper | currently used |
| `skg-gravity/exploit_proposals.py` | alternate proposal store | preserved / likely legacy | may still be useful as reference |
| `skg-gravity/gravity_web.py` | older gravity web model | preserved / likely legacy | conceptual reference |
| `skg/substrate/bond.py` | formal bond object | preserved / future-use / not in live call graph | useful formal model |
| `skg-gravity/gravity_field.py.pre_fix` | pre-fix snapshot | preserved snapshot | historical recovery/debug value |
| `skg_deploy/*` | deploy mirror | preserved mirror | explicit doc-preserved surface |
| `forge_staging/*` | generated-growth staging | staging | explicit doc-preserved surface |
| `skg-web-toolchain.backup/*` | backup copy | preserved backup | explicit doc-preserved surface |

## What Should Be Audited Next

No deletion.
No collapse of preserved trees.
The next useful audit order is:

1. canonical substrate/state path
   - `skg/substrate`
   - `skg/kernel`
   - `skg/temporal`
   - `skg/identity`
   - `skg/graph`
2. projection and state-ingest contract
   - explicit object schema vs filename heuristics
   - workload/domain/run identity handling
3. gravity runtime unification
   - `skg/gravity` vs `skg-gravity/gravity_field.py`
   - comment/runtime drift
   - daemon/CLI invocation consistency
4. operator wrapper truthfulness
   - CLI
   - API
   - UI
   - `observe` / `collect` / proposal paths
5. toolchain instrument contract audit
   - one adapter at a time
   - input contract
   - observation envelope contract
   - projector contract
   - artifact/state-root contract
6. preserved-tree classification and sync policy
   - `skg_deploy`
   - `forge_staging`
   - `*.backup`
   - `*.pre_fix`

## Final Assessment

SKG is not being wholly consumed by the domain adapters.
The substrate and kernel are real and active.

But SKG is also not yet fully unified around that substrate.
The strongest remaining drift is in:

- wrapper truthfulness
- filename/adapter-shaped temporal heuristics
- partially overlapping gravity surfaces
- preserved older models that are still present but not clearly classified in the runtime story

The immediate need is not removal.
It is authoritative classification and progressive reduction of parallel authority.
