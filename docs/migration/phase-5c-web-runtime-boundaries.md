# Phase 5C Web Runtime Boundaries

Date: 2026-04-01

## Ownership Decisions Enforced

1. Domain pack remains semantic authority.
- Canonical semantic modules used by runtime wrappers:
  - `packages/skg-domains/web/src/skg_domain_web/adapters/web_surface_fingerprint/run.py`
  - `packages/skg-domains/web/src/skg_domain_web/adapters/web_nikto_findings/run.py`
  - associated web domain mappings/policies under `mappings/` and `policies/`

2. Service layer owns runtime execution and orchestration.
- Runtime probing and subprocess execution now lives in:
  - `packages/skg-services/src/skg_services/gravity/web_runtime.py`
- CLI and gravity callsites now execute service wrappers, not legacy toolchain modules.

3. Migrated flows no longer depend on legacy web toolchain modules.
- Migrated flow A: unauthenticated web surface collection (`http_collector`, CLI `instrument=web`)
- Migrated flow B: nikto scan mapping (`nikto` instrument)
- Both now converge through service wrappers into canonical web domain adapter semantics.

## Boundary Violations Removed In Phase 5C

- Removed active runtime import path from gravity to legacy `web_active/collector.py`.
- Removed active runtime import path from gravity to legacy `web_active/nikto_adapter.py`.
- Removed CLI direct subprocess dependence on legacy `collector.py` for standard web observe flow.
- Replaced legacy-file-existence collector availability check with canonical runtime capability check.

## Boundary Risks Still Present (Intentional Deferral)

1. `auth_scanner` path is still legacy runtime-owned.
- `skg-gravity/gravity_field.py::_exec_auth_scanner`
- `skg/cli/commands/target.py` (`instrument=web` with `--auth`)
- This path still imports legacy `auth_scanner.py`, which imports collector helper symbols.

2. Additional web runtime helpers remain legacy for now.
- `skg-web-toolchain/adapters/web_active/gobuster_adapter.py`
- `skg-web-toolchain/adapters/web_active/sqlmap_adapter.py`
- `skg-web-toolchain/adapters/web_active/transport.py`

3. Compatibility wrappers are still present by design.
- `skg-web-toolchain/adapters/web_active/collector.py`
- `skg-web-toolchain/adapters/web_active/nikto_adapter.py`
- These are no longer the active preferred runtime path for migrated flows.

## Follow-On Boundary Work

- Migrate `auth_scanner` runtime path to a service wrapper that consumes canonical domain semantics.
- Migrate remaining web runtime helper adapters (`gobuster`, `sqlmap`) to service-owned wrappers.
- Remove compatibility wrappers once no runtime callsite depends on legacy symbols.
