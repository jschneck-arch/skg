# Phase 5A Domain Boundaries (web)

Date: 2026-04-01

## Boundary Decisions Applied

1. Domain ontology is domain-owned.
- Kept in `packages/skg-domains/web/src/skg_domain_web/ontology/*`.
- No ontology state was moved into `skg-core`, `skg-protocol`, or `skg-services`.

2. Adapter behavior is contract-driven and domain-bundled.
- Adapter emits canonical protocol events only through `skg_protocol.events`.
- No adapter imports `skg.core.paths`, daemon modules, or gravity runtime.

3. Projector remains domain-owned.
- Projector implementation lives at `packages/skg-domains/web/src/skg_domain_web/projectors/web/run.py`.
- It consumes `skg-core` substrate projection primitives and domain ontology/policy.

4. Service/runtime policy not moved into domain.
- Scanner execution/runtime orchestration (subprocess, external tool invocation, transport sockets) was not migrated into domain adapters.
- Domain pack only contains deterministic mapping/projector behavior for pilot extraction.

5. Policy artifacts are explicit.
- `policies/adapter_policy.yaml` and `policies/projection_policy.yaml` replace hidden conditionals and hardcoded alias maps.

6. Registry ownership remains in registry.
- Root `packages/skg-domains/web/domain.yaml` now points registry to `src/skg_domain_web/...` component paths.
- Domain package does not implement custom discovery logic.

## Coupling Removed In This Pilot

- Removed `sys.path` manipulation from migrated domain code.
- Removed direct toolchain directory assumptions from migrated domain code.
- Removed implicit policy constants from adapter/projector code by moving to explicit YAML artifacts.

## Known Boundary Limits (Intentional)

- Root `domain.yaml` and in-pack `manifest.yaml` coexist temporarily.
  - Reason: registry currently discovers root `domain.yaml`; in-pack manifest is required by Phase 5A structure.
- Runtime scanner execution remains in legacy toolchain modules.
  - Reason: those modules mix domain semantics with service/runtime concerns and require follow-on split before migration.
