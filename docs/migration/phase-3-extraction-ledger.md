# Phase 3 Extraction Ledger

Date: 2026-04-01
Scope: first concrete canonical extraction pass into `packages/skg-core`, `packages/skg-protocol`, and `packages/skg-registry`.
Method: controlled extraction only; no refactor-in-place of legacy trees.

## Extracted Files

| Legacy path | New path | Package classification | Action | Rationale | Unresolved risks |
|---|---|---|---|---|---|
| `skg/substrate/node.py` | `packages/skg-core/src/skg_core/substrate/node.py` | CORE | `split` | Kept `TriState`, `NodeState`, `Node`; removed non-essential service-facing compatibility fields. | Some legacy callers may depend on richer vector/matrix fields not yet ported. |
| `skg/substrate/path.py` | `packages/skg-core/src/skg_core/substrate/path.py` | CORE | `copied` | Canonical path and path-score substrate primitives fit core boundary. | Legacy naming still uses `wicket` semantics elsewhere. |
| `skg/substrate/projection.py` | `packages/skg-core/src/skg_core/substrate/projection.py` | CORE | `split` | Kept pure `project_path` and `classify` mechanics; removed event-loading bridge coupled to kernel/service runtime. | Event-to-state collapse remains in legacy until dedicated extraction. |
| `skg/substrate/state.py` | `packages/skg-core/src/skg_core/substrate/state.py` | CORE | `copied` | Canonical workload snapshot wrapper belongs in core substrate. | Snapshot keys still use legacy naming (`E`, not explicit entropy model object). |
| `skg/substrate/__init__.py` | `packages/skg-core/src/skg_core/substrate/__init__.py` | CORE | `rewritten` | Re-export set rebuilt to only canonical extracted types/functions. | Downstream import compatibility wrappers not provided yet. |
| `skg/identity/__init__.py` | `packages/skg-core/src/skg_core/identity/subject.py` | CORE | `split` | Kept identity/workload subject canonicalization functions; excluded identity journal runtime class. | Identity journal migration path to services/legacy still open. |
| `skg/kernel/observations.py` | `packages/skg-core/src/skg_core/kernel/observations.py` | CORE | `copied` | Observation model and store are protocol-neutral kernel primitives. | Ingestion adapters still legacy-only. |
| `skg/kernel/support.py` + `skg/core/coupling.py` | `packages/skg-core/src/skg_core/kernel/support.py` | CORE | `split` | Preserved support aggregation mechanics; removed dependency on legacy `decay_ttl_hours()` coupling file. | TTL policy source is now local default; external policy wiring not yet extracted. |
| `skg/kernel/state.py` | `packages/skg-core/src/skg_core/kernel/state.py` | CORE | `copied` | Tri-state collapse engine is canonical core logic. | Threshold tuning policy still hardcoded defaults. |
| `skg/temporal/interp.py` | `packages/skg-core/src/skg_core/temporal/interp.py` | CORE | `copied` | Interp payload normalization is temporal core primitive. | Legacy interp schemas beyond JSON/NDJSON still unmanaged. |
| multiple legacy JSONL writer snippets | `packages/skg-core/src/skg_core/serialization/jsonl.py` | CORE | `rewritten` | Introduced canonical serialization primitive to avoid runtime-specific writers in core. | Large-file streaming/performance not tuned yet. |
| `skg/core/paths.py` | `packages/skg-core/src/skg_core/config/paths.py` | CORE | `split` | Replaced hardcoded `/opt/skg` and `/var/lib/skg` assumptions with env/cwd-resolved primitives. | Runtime path policy for production deployments still needs service-layer ownership. |
| `N/A` | `packages/skg-core/src/skg_core/__init__.py` | CORE | `rewritten` | New stable package exports for extracted canon. | API may evolve after deeper extraction. |
| `N/A` | `packages/skg-core/src/skg_core/config/__init__.py` | CORE | `rewritten` | Package-local config exports. | None. |
| `N/A` | `packages/skg-core/src/skg_core/identity/__init__.py` | CORE | `rewritten` | Package-local identity exports. | None. |
| `N/A` | `packages/skg-core/src/skg_core/kernel/__init__.py` | CORE | `rewritten` | Package-local kernel exports. | None. |
| `N/A` | `packages/skg-core/src/skg_core/temporal/__init__.py` | CORE | `rewritten` | Package-local temporal exports. | None. |
| `N/A` | `packages/skg-core/src/skg_core/serialization/__init__.py` | CORE | `rewritten` | Package-local serialization exports. | None. |
| `skg/sensors/__init__.py` (`envelope`, `precondition_payload`) | `packages/skg-protocol/src/skg_protocol/events.py` | PROTOCOL | `split` | Extracted event-envelope and payload contracts; removed sensor registry/runtime loop contamination. | Subject canonicalization duplicated pending cross-package utility consolidation. |
| `skg/core/assistant_contract.py` | `packages/skg-protocol/src/skg_protocol/validation/assistant.py` | PROTOCOL | `copied` | Assistant observation-admissibility guard is protocol validation logic. | Event class policy breadth may need tightening with service feedback. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/contracts/adapter.py` | PROTOCOL | `rewritten` | Introduced universal adapter contract and health/checkpoint DTOs. | No runtime adapters migrated to enforce this yet. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/contracts/projector.py` | PROTOCOL | `rewritten` | Introduced universal projector contract and health DTO. | Projector execution contract not yet wired in services. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/contracts/checkpoint.py` | PROTOCOL | `rewritten` | Added canonical checkpoint record contract. | Checkpoint persistence format not finalized. |
| `skg/core/domain_registry.py` (manifest fields) + `packages/skg-domains/*/domain.yaml` shape | `packages/skg-protocol/src/skg_protocol/contracts/manifest.py` | PROTOCOL | `split` | Normalized manifest contract for both domain packs and legacy toolchains. | Legacy `forge_meta.json` heterogeneity still broad. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/contracts/compatibility.py` | PROTOCOL | `rewritten` | Added explicit protocol compatibility rule (major version match). | Semver pre-release/build metadata not modeled yet. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/validation/envelope.py` | PROTOCOL | `rewritten` | Added envelope schema validation helper to enforce protocol contract. | Validation currently structural, not full semantic constraint validation. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/__init__.py` | PROTOCOL | `rewritten` | Stable package exports for protocol layer. | API may expand as contracts mature. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/contracts/__init__.py` | PROTOCOL | `rewritten` | Package-local contract exports. | None. |
| `N/A` | `packages/skg-protocol/src/skg_protocol/validation/__init__.py` | PROTOCOL | `rewritten` | Package-local validation exports. | None. |
| `skg/core/domain_registry.py` | `packages/skg-registry/src/skg_registry/discovery.py` | REGISTRY | `split` | Extracted domain discovery mechanics into standalone registry module; removed daemon-native control semantics. | Legacy toolchain discovery is still filename-convention based. |
| `skg/core/domain_registry.py` | `packages/skg-registry/src/skg_registry/manifest_loader.py` | REGISTRY | `split` | Extracted manifest loading and legacy inference without service imports. | Requires PyYAML for YAML manifests. |
| `skg/core/domain_registry.py` | `packages/skg-registry/src/skg_registry/models.py` | REGISTRY | `rewritten` | Added explicit `DomainRecord` model for public registry APIs. | Component path existence is validated lazily, not at load time. |
| `skg/core/domain_registry.py` | `packages/skg-registry/src/skg_registry/registry.py` | REGISTRY | `split` | Added public registry resolver APIs for domain/adapters/projectors/policies. | No plugin lifecycle/registration conflict resolution yet. |
| `N/A` | `packages/skg-registry/src/skg_registry/__init__.py` | REGISTRY | `rewritten` | Stable package exports for registry layer. | None. |

## Package Scaffolding and Build Metadata

| Legacy path | New path | Package classification | Action | Rationale | Unresolved risks |
|---|---|---|---|---|---|
| `packages/skg-core/pyproject.toml` scaffold | `packages/skg-core/pyproject.toml` | CORE | `rewritten` | Added setuptools `src` package discovery for installability. | No pinned optional extras yet. |
| `packages/skg-protocol/pyproject.toml` scaffold | `packages/skg-protocol/pyproject.toml` | PROTOCOL | `rewritten` | Added setuptools `src` package discovery for installability. | No pinned optional extras yet. |
| `packages/skg-registry/pyproject.toml` scaffold | `packages/skg-registry/pyproject.toml` | REGISTRY | `rewritten` | Added setuptools `src` package discovery and explicit dependency on `PyYAML` + protocol package. | Monorepo install ordering must include `skg-protocol`. |

## Tests Added for Extracted Canon

| Legacy path | New path | Package classification | Action | Rationale | Unresolved risks |
|---|---|---|---|---|---|
| `N/A` | `packages/skg-core/tests/test_substrate_projection.py` | CORE | `rewritten` | Verifies canonical path projection semantics. | Does not yet cover event-to-state collapse path. |
| `N/A` | `packages/skg-core/tests/test_identity_subject.py` | CORE | `rewritten` | Verifies identity subject canonicalization. | More workload ID edge-cases still needed. |
| `N/A` | `packages/skg-core/tests/test_support_engine.py` | CORE | `rewritten` | Verifies support aggregation compatibility-span behavior. | Decay/TTL boundary tests are minimal. |
| `N/A` | `packages/skg-protocol/tests/test_events_and_validation.py` | PROTOCOL | `rewritten` | Verifies envelope creation/validation and assistant admissibility. | No exhaustive envelope semantic tests yet. |
| `N/A` | `packages/skg-protocol/tests/test_manifest_and_compatibility.py` | PROTOCOL | `rewritten` | Verifies manifest normalization and compatibility rule. | No legacy `forge_meta` fixture matrix yet. |
| `N/A` | `packages/skg-registry/tests/test_registry_discovery.py` | REGISTRY | `rewritten` | Verifies discovery precedence and adapter resolution API. | No tests yet for projector/policy conflict resolution. |

## Explicitly Deferred (Not Migrated in Phase 3)

| Legacy path | Intended target | Package classification | Action | Rationale | Unresolved risks |
|---|---|---|---|---|---|
| `skg/kernel/adapters.py` | `skg-protocol` + `skg-services/gravity` split | PROTOCOL + SERVICE | `deferred` | Contains both useful event mapping and gravity/event-file scanning contamination. | Legacy gravity keeps bypassing clean ingestion boundaries until split. |
| `skg/substrate/projection.py` (`load_states_from_events*`) | `skg-core/kernel` + protocol mapper split | CORE + PROTOCOL | `deferred` | Mixed substrate scoring with kernel-specific event conversion internals. | Duplicate collapse logic remains in legacy runtime. |
| `skg/sensors/__init__.py` (registry, `SensorLoop`, emitters) | `skg-services/gravity` | SERVICE | `deferred` | Runtime orchestration and event I/O do not belong in protocol/core. | Service boundary bypass remains in legacy. |
| `skg/sensors/projector.py` | `skg-services/gravity` + protocol projector contract | SERVICE + PROTOCOL | `deferred` | Dynamic import/runtime execution logic mixed with contract semantics. | Registry/projector boundary still bypassed in legacy runtime. |
| `skg/core/domain_registry.py` (daemon-native defaults, CLI hints) | `skg-services` + `skg-registry` split | REGISTRY + SERVICE | `deferred` | Remaining fields encode daemon/runtime decisions outside registry scope. | Daemon coupling persists until service migration phases. |
| `skg/core/paths.py` (service-specific dirs) | `skg-services/*` | SERVICE | `deferred` | Runtime/process paths must be owned by services, not core. | Legacy `/opt` and `/var` assumptions still active outside extracted core. |

## Validation Results

- Compile check: `python -m compileall packages/skg-core/src packages/skg-protocol/src packages/skg-registry/src`
- Package tests: `PYTHONPATH=packages/skg-core/src:packages/skg-protocol/src:packages/skg-registry/src pytest -q packages/skg-core/tests packages/skg-protocol/tests packages/skg-registry/tests`
- Result: `11 passed`
