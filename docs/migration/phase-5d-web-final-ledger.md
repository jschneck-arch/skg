# Phase 5D Web Final Ledger

Date: 2026-04-01

## Migrated Remaining Auth/Runtime Callsites

| Caller path | Original target | New target | Action | Safety rationale | Remaining compatibility risk |
|---|---|---|---|---|---|
| `skg/cli/commands/target.py` (`cmd_observe`, `instrument=web --auth`) | legacy subprocess of `skg-web-toolchain/adapters/web_active/auth_scanner.py` | `skg_services.gravity.web_runtime.collect_auth_surface_events_to_file(...)` | rewritten | Runtime execution moved to service layer; semantic mapping emitted through canonical web domain adapters. | Legacy auth scanner file still exists as compatibility wrapper for out-of-repo callers. |
| `skg-gravity/gravity_field.py` (`_exec_auth_scanner`) | legacy `from auth_scanner import auth_scan` call | `skg_services.gravity.web_runtime.collect_auth_surface_events_to_file(...)` | rewritten | Gravity now executes service-owned auth runtime wrapper and consumes canonical events only. | None for in-repo callsites; external wrapper users remain compatibility-only. |
| `skg-gravity/gravity_field.py` (`detect_instruments`, auth scanner availability) | legacy file-existence probe (`WEB_ADAPTER/auth_scanner.py`) | canonical runtime capability (`_canonical_web_runtime_available()`) | rewritten | Instrument availability now follows canonical service/domain readiness, not legacy file layout. | Capability check still depends on canonical package importability. |

## New Canonical Auth Convergence Assets

| Path | Classification | Action | Purpose |
|---|---|---|---|
| `packages/skg-services/src/skg_services/gravity/web_runtime.py` | service runtime | expanded | Added auth runtime orchestration (`collect_auth_surface_events*`) with explicit credential policy loading and canonical adapter invocation. |
| `packages/skg-domains/web/src/skg_domain_web/adapters/web_auth_assessment/run.py` | domain adapter | added | Domain-owned auth outcome semantics (`default credentials` wicket mapping) to canonical events. |
| `packages/skg-domains/web/src/skg_domain_web/policies/auth_assessment_policy.yaml` | domain policy | added | Explicit wicket/confidence policy for auth outcome interpretation. |
| `packages/skg-domains/web/src/skg_domain_web/policies/auth_runtime_policy.yaml` | domain policy | added | Explicit runtime credential attempt policy used by service auth wrapper. |

## Tests Added/Updated

| Path | Coverage |
|---|---|
| `packages/skg-services/tests/test_web_runtime_wrappers.py` | Added auth runtime convergence test and callsite safety assertions (no active legacy auth/collector/nikto callsite bypass). |
| `packages/skg-domains/web/tests/test_web_auth_assessment_adapter.py` | Added domain auth assessment semantic mapping tests. |

## Validation Summary

- `python -m compileall` on canonical packages + web domain: pass.
- `pytest` on required package test suites: pass (`42 passed`).
- `python -m py_compile` on touched runtime/wrapper callsites: pass.
