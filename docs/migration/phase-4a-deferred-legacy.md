# Phase 4A Deferred Legacy Residue

Date: 2026-04-01

This file tracks what was intentionally left in legacy after the Phase 4A split pass.

## Deferred by Source File

### `skg/kernel/adapters.py`

Deferred legacy residue:
- Fallback `event_to_observation` implementation.
- Fallback gravity discovery/event-file scan branch and filename pattern list.
- Legacy `Observation` object construction path in fallback mode.

Why deferred:
- Removing fallback now would break legacy runtime callsites that have not yet switched to canonical package imports.

Unresolved risks:
- Duplicate behavior between legacy and canonical mapping/scanning paths can drift.
- Pattern-based file selection remains brittle and runtime-shape dependent.

Phase 4B action:
- Switch service runtime imports to `skg_services.gravity.observation_loading` + `skg_protocol.observation_mapping` directly.
- Delete fallback code from this module after callsite migration.

### `skg/substrate/projection.py`

Deferred legacy residue:
- Fallback implementations of `load_states_from_events` and `load_states_from_events_priority`.
- Legacy conversions between old/new node state representations.

Why deferred:
- Existing callsites still import these entrypoints from the legacy module.

Unresolved risks:
- Event-collapse behavior exists in two places (legacy + `skg_services.gravity.state_collapse`).
- Hardcoded thresholds in both paths can diverge.

Phase 4B action:
- Route projector/runtime callsites to `skg_services.gravity.state_collapse`.
- Keep `skg_core.substrate.projection` strictly substrate-only.

### `skg/sensors/__init__.py`

Deferred legacy residue:
- `BaseSensor`, `SensorLoop`, sensor module registration/import bootstrap.
- Target loading and scheduler runtime behavior.
- Context injection path.

What was extracted already:
- Contract builders delegated to `skg_protocol.events`.
- Event emission delegated to `skg_services.gravity.event_writer`.

Why deferred:
- Full scheduler extraction would be a broad runtime migration and exceeds this split-only phase.

Unresolved risks:
- Measurement-plane runtime still anchored to a legacy monolith module.
- Mixed authority remains inside one legacy file until scheduler extraction lands.

Phase 4B action:
- Extract scheduler/bootstrap into `packages/skg-services/src/skg_services/gravity`.
- Keep protocol contracts out of this legacy module, then reduce it to a thin compatibility shim.

### `skg/sensors/projector.py`

Deferred legacy residue:
- Entire fallback projector loader/executor implementation remains in file.
- Legacy registry/toolchain aliasing helpers still present as fallback.

What was extracted already:
- Service runtime module `packages/skg-services/src/skg_services/gravity/projector_runtime.py`.
- Legacy function rebinding to service runtime when available.

Why deferred:
- Immediate deletion of fallback would break environments not yet loading canonical service packages.

Unresolved risks:
- Dual implementations create drift risk.
- Dynamic-import execution remains dependent on legacy directory conventions.

Phase 4B action:
- Move all live projector execution callsites to `skg_services.gravity.projector_runtime`.
- Delete fallback runtime logic from this file.

### `skg/core/domain_registry.py`

Deferred legacy residue:
- Legacy default domain registry payload.
- Legacy inventory row enrichment (`bootstrapped`, `cli_available`, `projector_available`).
- Toolchain directory scanning fallback behavior.

What was extracted already:
- Canonical registry package (`skg_registry`).
- Service daemon runtime policy (`skg_services.gravity.domain_runtime`).

Why deferred:
- Runtime callers still consume legacy inventory row shape.

Unresolved risks:
- Registry-like and service-like row fields are still mixed in fallback mode.
- Legacy discovery remains filename-convention based.

Phase 4B action:
- Migrate runtime callers to canonical `DomainRegistry` + service policy composition.
- Constrain this file to compatibility wrappers, then retire it.

### `skg/core/paths.py`

Deferred legacy residue:
- Legacy compatibility constants (`TOOLCHAIN_DIR`, `PID_FILE`, `LOG_DIR`, etc.).
- Runtime directory bootstrap list in `ensure_runtime_dirs()`.

What was extracted already:
- Canonical path primitives in `skg_core.config.paths`.
- Service path ownership policy in `skg_services.gravity.path_policy`.
- Hardcoded `/opt/skg` assumptions removed from legacy module.

Why deferred:
- Legacy runtime code still imports historical constants from this module.

Unresolved risks:
- Compatibility constants still encode old layout conventions.
- `cwd`-based defaults can be wrong for daemonized execution without explicit env.

Phase 4B action:
- Move runtime ownership to service path policy consumers.
- Replace constant imports with resolved path objects from service/core APIs.

## Defer Criteria Used

- If a slice was clearly contract/core/registry/service-owned, it was extracted.
- If removing a legacy fallback would break unresolved runtime callsites, it stayed deferred.
- No unresolved ambiguous runtime logic was forced into core/protocol/registry.
