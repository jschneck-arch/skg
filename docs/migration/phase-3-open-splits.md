# Phase 3 Open Splits

Date: 2026-04-01
Status: deferred items that must be split before next extraction waves.

## Split Backlog

| Legacy file | Why split is required | Keep slice | Move slice | Deferred risk |
|---|---|---|---|---|
| `skg/kernel/adapters.py` | File mixes protocol mapping (`event_to_observation`) with gravity-specific file scanning and naming conventions. | `event_to_observation`, `_phi_from_event`, `_decay_class` | `load_observations_for_node`, pattern-based filesystem scanning | Ingestion remains coupled to gravity discovery artifacts. |
| `skg/substrate/projection.py` | File mixes pure substrate scoring with kernel event-collapse orchestration. | `project_path`, `classify`, path-level unresolved detail shaping | `load_states_from_events`, `load_states_from_events_priority`, kernel/support engine wiring | Duplicate collapse semantics across layers continue to drift. |
| `skg/sensors/__init__.py` | File mixes envelope contract, payload contract, sensor registry, runtime scheduling, and event file output. | `envelope`/payload contract logic (already extracted to protocol) | `BaseSensor`, `SensorLoop`, emit/write logic to service runtime | Legacy still uses mixed authority planes in one module. |
| `skg/sensors/projector.py` | File mixes discovery hints with dynamic projector execution and fallback runtime invocation. | projector contract assumptions and route metadata | module loading/execution, runtime fallback, events-dir traversal | Services bypass registry/projector boundary until split lands. |
| `skg/core/domain_registry.py` | File mixes registry concerns with daemon-native runtime defaults and CLI assumptions. | manifest normalization/discovery primitives (partially extracted) | daemon-native fields (`cli`, `project_sub`, runtime bootstrap checks) | Registry remains partially contaminated by service semantics. |
| `skg/core/paths.py` | File mixes config primitives with deployment-specific runtime ownership. | env/cwd-resolved path primitives (already extracted) | service-owned directories (`pid`, logs, forge staging, msf, bh paths) | Hardcoded layout assumptions still active in legacy services. |
| `skg/temporal/feedback.py` | File combines projection ingestion with graph mutation and file watchers. | temporal payload normalization (already extracted via `interp`) | feedback ingestion loop and graph propagation logic to services | Interpretation and orchestration planes remain coupled in legacy. |

## Split Sequence Recommendation

1. Split `skg/kernel/adapters.py`
- Target modules:
  - `packages/skg-protocol/src/skg_protocol/observation_mapping.py`
  - `packages/skg-services/gravity/...` for event file scanning
- Gate: no scanning/path logic left in protocol mapping module.

2. Split `skg/substrate/projection.py`
- Target modules:
  - keep path projection in `skg-core`
  - move event-collapse bridge to either `skg-core/kernel` (if protocol-neutral) or service-side ingestion pipeline
- Gate: `skg-core/substrate/projection.py` imports only substrate models.

3. Split `skg/sensors/projector.py`
- Target modules:
  - protocol projector contract metadata in `skg-protocol`
  - runtime execution in `packages/skg-services/gravity`
- Gate: registry only resolves projector locations; services execute.

4. Split residual runtime semantics from `skg/core/domain_registry.py`
- Target modules:
  - `skg-registry` for domain discovery and compatibility
  - `skg-services` for daemon defaults/bootstrapping
- Gate: registry contains no daemon-native decision fields.

## Hard Stop Rules for Next Split Work

- Do not migrate any scanner/parser/toolchain runtime into core/protocol/registry.
- Do not carry forward hardcoded `/opt/skg` or `sys.path` mutation.
- If split boundary is ambiguous, leave file in legacy and log in this document before extracting.
