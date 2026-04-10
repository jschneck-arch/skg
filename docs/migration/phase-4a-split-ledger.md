# Phase 4A Split Ledger

Date: 2026-04-01  
Scope: split the highest-risk mixed legacy modules before broader service migration.

## Split Records

| Original path | Split output path | Ownership | Action | Rationale | Unresolved risks | Phase 4B safe? |
|---|---|---|---|---|---|---|
| `skg/kernel/adapters.py` | `packages/skg-protocol/src/skg_protocol/observation_mapping.py` | PROTOCOL | `split` | Extracted domain-neutral event->observation contract mapping (`status`/`confidence`/decay mapping + admissibility gate). | Decay policy constants are still hardcoded and may drift from service policy. | Yes, with drift watch. |
| `skg/kernel/adapters.py` | `packages/skg-services/src/skg_services/gravity/observation_loading.py` | SERVICE | `split` | Extracted gravity runtime file scanning/dedup logic from contract layer. | Filename pattern logic is still legacy-shape and should later move to manifest-driven discovery. | Yes. |
| `skg/kernel/adapters.py` | `skg/kernel/adapters.py` (compat shim) | LEGACY | `rewritten` | Legacy module now delegates to protocol/service extractions when available; fallback remains to preserve behavior. | Dual implementation remains until fallback branch is removed. | Yes, temporary only. |
| `skg/substrate/projection.py` | `packages/skg-core/src/skg_core/substrate/projection.py` | CORE | `split` | Kept substrate-only projection/classification logic in canonical core. | Legacy file still carries richer optional fields not yet fully mirrored in canonical core. | Yes. |
| `skg/substrate/projection.py` | `packages/skg-services/src/skg_services/gravity/state_collapse.py` | SERVICE | `split` | Moved event-collapse bridge/runtime aggregation out of core substrate. | Collapse thresholds still hardcoded in runtime bridge. | Yes. |
| `skg/substrate/projection.py` | `skg/substrate/projection.py` (compat shim) | LEGACY | `rewritten` | Legacy collapse entrypoints now delegate to service bridge if installed, with fallback path retained. | Duplicate bridge logic still exists in fallback code paths. | Yes, with cleanup scheduled. |
| `skg/sensors/__init__.py` | `packages/skg-protocol/src/skg_protocol/events.py` | PROTOCOL | `split` | Contract-only envelope + precondition payload builders extracted from mixed sensor runtime module. | Subject derivation logic exists in multiple places and needs convergence. | Yes. |
| `skg/sensors/__init__.py` | `packages/skg-services/src/skg_services/gravity/event_writer.py` | SERVICE | `split` | Extracted runtime event-file emission from mixed contract/runtime module. | Sensor scheduler/bootstrap remains in legacy module. | Yes. |
| `skg/sensors/__init__.py` | `skg/sensors/__init__.py` (compat shim + deferred runtime) | LEGACY | `rewritten` | Legacy envelope/payload/emit paths now delegate to canonical protocol/service implementations when available. | `BaseSensor`, `SensorLoop`, target loading, and bootstrap semantics remain mixed and deferred. | Partially; full scheduler migration still needed. |
| `skg/sensors/projector.py` | `packages/skg-protocol/src/skg_protocol/contracts/projector.py` | PROTOCOL | `keep` | Projector interface contract stays protocol-owned; runtime logic excluded. | Contract and runtime still loosely coupled through legacy assumptions. | Yes. |
| `skg/sensors/projector.py` | `packages/skg-services/src/skg_services/gravity/projector_runtime.py` | SERVICE | `split` | Runtime projector loading/execution/grouping moved to service layer. | Dynamic imports and projector discovery are still legacy-layout dependent. | Yes, with domain-pack follow-up. |
| `skg/sensors/projector.py` | `skg/sensors/projector.py` (compat shim) | LEGACY | `rewritten` | Legacy module rebinds projector runtime functions to service implementation when package is available. | Fallback implementation duplicates service runtime and can drift. | Yes, temporary only. |
| `skg/core/domain_registry.py` | `packages/skg-registry/src/skg_registry/discovery.py` | REGISTRY | `keep` | Canonical domain discovery/loading is registry-owned and service-neutral. | Legacy inventory row shape still includes runtime hints. | Yes. |
| `skg/core/domain_registry.py` | `packages/skg-registry/src/skg_registry/manifest_loader.py` | REGISTRY | `keep` | Manifest loading/inference remains registry-owned. | Legacy `forge_meta.json` heterogeneity still broad. | Yes. |
| `skg/core/domain_registry.py` | `packages/skg-registry/src/skg_registry/registry.py` | REGISTRY | `keep` | Public registry API is canonical and service-neutral. | Conflict resolution remains basic (name precedence only). | Yes. |
| `skg/core/domain_registry.py` | `packages/skg-services/src/skg_services/gravity/domain_runtime.py` | SERVICE | `split` | Daemon-native runtime selection/defaults moved out of registry boundary. | Default daemon domain policy is still static and legacy-biased. | Yes. |
| `skg/core/domain_registry.py` | `skg/core/domain_registry.py` (compat shim + deferred inventory shape) | LEGACY | `rewritten` | Legacy entrypoints delegate to canonical registry/service modules where possible. | File still computes runtime fields (`bootstrapped`, `cli_available`) in legacy mode. | Yes, with cleanup in 4B. |
| `skg/core/paths.py` | `packages/skg-core/src/skg_core/config/paths.py` | CORE | `keep` | Canonical package-neutral path/config primitives remain core-owned. | Root resolution policy differs from some legacy expectations. | Yes. |
| `skg/core/paths.py` | `packages/skg-services/src/skg_services/gravity/path_policy.py` | SERVICE | `split` | Service path ownership/policy isolated from core primitives. | Service policy still defaults to cwd if env unset. | Yes. |
| `skg/core/paths.py` | `skg/core/paths.py` (legacy compatibility rewrite) | LEGACY | `rewritten` | Removed hardcoded `/opt/skg` install assumptions; now env/cwd-resolved compatibility constants only. | Legacy constants still encode toolchain directory conventions. | Yes. |

## Additional Verification Artifacts Added

| Path | Ownership | Action | Rationale |
|---|---|---|---|
| `packages/skg-protocol/tests/test_observation_mapping.py` | PROTOCOL | `copied` | Added package-local tests for newly extracted observation mapping behavior and admissibility gate. |

## Validation Executed

- `python -m compileall packages/skg-core/src packages/skg-protocol/src packages/skg-registry/src packages/skg-services/src`
- `python -m py_compile skg/kernel/adapters.py skg/substrate/projection.py skg/sensors/__init__.py skg/sensors/projector.py skg/core/domain_registry.py skg/core/paths.py`
- `PYTHONPATH=packages/skg-core/src:packages/skg-protocol/src:packages/skg-registry/src:packages/skg-services/src:$PYTHONPATH pytest packages/skg-core/tests packages/skg-protocol/tests packages/skg-registry/tests`

Result: compile succeeded; package tests passed (`14 passed`).
