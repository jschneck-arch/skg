# Phase 5D Web Boundary Status

Date: 2026-04-01

## Current Boundary State

### Service-owned runtime (active)
- `packages/skg-services/src/skg_services/gravity/web_runtime.py`
- Runtime concerns owned here:
  - HTTP probing
  - auth attempt orchestration
  - nikto subprocess execution/parsing
  - runtime call integration for CLI/gravity

### Domain-owned semantics (active)
- `packages/skg-domains/web/src/skg_domain_web/adapters/web_surface_fingerprint/run.py`
- `packages/skg-domains/web/src/skg_domain_web/adapters/web_nikto_findings/run.py`
- `packages/skg-domains/web/src/skg_domain_web/adapters/web_auth_assessment/run.py`
- `packages/skg-domains/web/src/skg_domain_web/policies/*.yaml` (including auth policies)

### Runtime callers (active)
- `skg/cli/commands/target.py`
- `skg-gravity/gravity_field.py`

Both now route through service wrappers for web, auth, and nikto migrated flows.

## Boundary Violations Closed In Phase 5D

1. Auth runtime bypass closed.
- CLI `--auth` path no longer shells directly into legacy auth scanner implementation.
- Gravity `_exec_auth_scanner` no longer imports legacy auth scanner implementation.

2. Legacy-file availability coupling reduced.
- Auth instrument availability no longer depends on `WEB_ADAPTER/auth_scanner.py` file existence.

3. Legacy mixed auth module reduced.
- `skg-web-toolchain/adapters/web_active/auth_scanner.py` converted from mixed runtime+semantics implementation to explicit compatibility wrapper.

## Remaining Deferred Boundary Risks

| Path | Risk | Why deferred |
|---|---|---|
| `skg-web-toolchain/adapters/web_active/gobuster_adapter.py` | mixed runtime + mapping | Not required to complete auth/runtime convergence in this phase. |
| `skg-web-toolchain/adapters/web_active/sqlmap_adapter.py` | mixed runtime + mapping + exploit side effects | Requires separate controlled split due higher coupling and authorization constraints. |
| `skg-web-toolchain/adapters/web_active/transport.py` | runtime transport utility still legacy-local | No active migrated flow requires direct movement in this phase. |

## Net Assessment

For migrated web flows, authority planes are now clean:
- measurement/runtime execution in services
- interpretation semantics in domain pack
- no active in-repo runtime caller bypasses into legacy implementation modules.
