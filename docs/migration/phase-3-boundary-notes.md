# Phase 3 Boundary Notes

Date: 2026-04-01

## Boundary Decisions Enforced

1. Core extraction is substrate-only.
- Extracted into `packages/skg-core`: substrate models/projection/state, identity subject primitives, kernel support/collapse, temporal interp normalization, path/config primitives.
- Excluded from core: sensor loops, daemon runtime, projector execution, adapter loading, event file scanning.

2. Protocol extraction is contract-only.
- Extracted into `packages/skg-protocol`: envelope construction, precondition payload contract, assistant admissibility validation, adapter/projector/checkpoint/manifest/compatibility contracts.
- Excluded from protocol: sensor registry, subprocess execution, dynamic module loading, CLI/service orchestration.

3. Registry extraction is discovery/resolution-only.
- Extracted into `packages/skg-registry`: manifest loading, domain discovery (domain packs + legacy toolchains), compatibility filtering, adapter/projector/policy path resolution APIs.
- Excluded from registry: daemon-native orchestration flags, CLI defaults, projector execution, any state mutation.

## Contamination Removed in Extracted Code

- Hardcoded deployment paths removed from extracted core path primitives.
- No `sys.path` mutation in extracted packages.
- No imports from `skg-services`, `skg-gravity`, `skg/cli`, `skg/sensors` runtime loop, or domain adapters in extracted packages.
- Legacy dynamic import patterns (`spec_from_file_location`, runtime path injection) were not carried into core/protocol/registry.

## Known Boundary Violations Still in Legacy (Not Yet Fixed)

1. `skg/kernel/adapters.py`
- Mixed concern: protocol mapping + gravity event file scanning and discovery patterns.
- Effect: ingestion and runtime remain coupled.

2. `skg/sensors/__init__.py`
- Mixed concern: envelope contracts + sensor registry + file emission + orchestrator loop.
- Effect: protocol and service planes still merged in legacy path.

3. `skg/sensors/projector.py`
- Mixed concern: projector contract assumptions + dynamic execution/runtime loading.
- Effect: registry/projector boundary bypass remains.

4. `skg/core/domain_registry.py`
- Mixed concern: registry discovery + daemon-native service defaults and runtime hints.
- Effect: registry and services are still coupled in legacy code.

5. `skg/core/paths.py`
- Mixed concern: config primitives + deployment/runtime layout ownership.
- Effect: legacy runtime still anchored to install assumptions.

## Authority Plane Notes

- Declaration/configuration: moved toward manifest contracts (`skg-protocol`) and path primitives (`skg-core`).
- Measurement/observation: envelope contract extracted, but legacy sensor runtime still writes events directly.
- Interpretation/projection: pure substrate projection extracted; runtime projector execution deferred.
- Orchestration/proposal: intentionally not extracted in Phase 3; remains service scope.

## Duplicate/Conflicting Implementations Identified

- Subject identity canonicalization now exists in both `skg_core.identity.subject` and a minimal mirror inside `skg_protocol.events`.
- Rationale: kept protocol package independent for Phase 3.
- Risk: drift if not unified in later phase.
- Planned fix: move subject key derivation into protocol contract utility or a shared core utility consumed by protocol without circular dependency.

## Immediate Guardrails for Next Phases

- No new core/protocol/registry module may import from `skg/` legacy runtime trees.
- Any migration candidate with both contract and runtime behavior must be split before extraction.
- Registry may resolve component locations only; execution remains service-owned.
