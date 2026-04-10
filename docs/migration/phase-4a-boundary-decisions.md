# Phase 4A Boundary Decisions

Date: 2026-04-01

## Decisions Applied

1. `skg/kernel/adapters.py`
- Protocol ownership: event->observation mapping moved to `packages/skg-protocol/src/skg_protocol/observation_mapping.py`.
- Service ownership: gravity event-file scanning moved to `packages/skg-services/src/skg_services/gravity/observation_loading.py`.
- Legacy status: `skg/kernel/adapters.py` is now a compatibility shim with fallback code retained.
- Boundary enforcement: protocol module has no filesystem scanning; service module has no kernel state semantics.

2. `skg/substrate/projection.py`
- Core ownership: projection primitives remain canonical in `packages/skg-core/src/skg_core/substrate/projection.py`.
- Service ownership: event-collapse bridge moved to `packages/skg-services/src/skg_services/gravity/state_collapse.py`.
- Legacy status: legacy projection module delegates collapse calls to service bridge when available.
- Boundary enforcement: core projection package remains deterministic/stateless and does not own runtime event ingestion.

3. `skg/sensors/__init__.py`
- Protocol ownership: envelope/payload contracts are owned by `packages/skg-protocol/src/skg_protocol/events.py`.
- Service ownership: runtime event writer extracted to `packages/skg-services/src/skg_services/gravity/event_writer.py`.
- Legacy status: sensor scheduler/bootstrap (`BaseSensor`, `SensorLoop`, target loading) intentionally deferred.
- Boundary enforcement: contract builders are no longer runtime-owned.

4. `skg/sensors/projector.py`
- Protocol ownership: projector interface contract remains in `packages/skg-protocol/src/skg_protocol/contracts/projector.py`.
- Service ownership: projector execution runtime extracted to `packages/skg-services/src/skg_services/gravity/projector_runtime.py`.
- Legacy status: legacy projector module rebinds to service runtime when available; fallback retained.
- Boundary enforcement: projector execution is explicitly service-owned, not core/protocol-owned.

5. `skg/core/domain_registry.py`
- Registry ownership: canonical discovery/loading/resolution remains in `packages/skg-registry/src/skg_registry/{discovery.py,manifest_loader.py,registry.py,models.py}`.
- Service ownership: daemon-domain selection/defaults extracted to `packages/skg-services/src/skg_services/gravity/domain_runtime.py`.
- Legacy status: legacy registry module delegates to canonical registry and service runtime policy if available.
- Boundary enforcement: daemon/service semantics are no longer required for canonical registry APIs.

6. `skg/core/paths.py`
- Core ownership: package-neutral path/config primitives remain in `packages/skg-core/src/skg_core/config/paths.py`.
- Service ownership: service path policy is in `packages/skg-services/src/skg_services/gravity/path_policy.py`.
- Legacy status: compatibility path module rewritten to env/cwd defaults; hardcoded install paths removed.
- Boundary enforcement: no canonical package now relies on `/opt/skg` assumptions.

## Hard Boundary Rules Confirmed

- Core packages do not import domains or service runtimes.
- Protocol packages contain contracts/validation only; no runtime loops or file scanners.
- Registry packages expose discovery/loading/resolution only; no daemon orchestration semantics.
- Service runtime extraction (`skg-services`) consumes core/protocol/registry public APIs.
- No `sys.path` hacks in extracted canonical packages.

## Known Remaining Mixed Areas (Intentional Defer)

- `skg/sensors/__init__.py`: scheduler and bootstrap logic still mixed with legacy sensor registration.
- `skg/sensors/projector.py`: fallback runtime still duplicated in legacy file.
- `skg/kernel/adapters.py`: fallback mapping and scanning remain in the same legacy file until fallback removal.
- `skg/substrate/projection.py`: fallback collapse path duplicates service bridge behavior.
- `skg/core/domain_registry.py`: legacy inventory row still emits runtime-oriented fields.

## Why This Is Acceptable for Phase 4A

- Ownership boundaries are now explicit in canonical packages.
- Legacy modules are shimmed rather than force-moved, preventing contamination into core/protocol/registry.
- Phase 4B can migrate service orchestration from these shimmed legacy modules without reopening core/protocol boundaries.
