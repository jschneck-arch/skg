# Phase 5D Web Template Readiness

Date: 2026-04-01

## Template Readiness Criteria

| Criterion | Status | Evidence |
|---|---|---|
| Runtime callsites consume service wrappers, not legacy toolchain implementations | PASS | `target.py` and `gravity_field.py` now call `skg_services.gravity.web_runtime` functions. |
| Domain pack is semantic source of truth for migrated flows | PASS | Service wrappers call canonical web domain adapters (`surface_fingerprint`, `nikto_findings`, `auth_assessment`). |
| Auth path migrated to canonical service/domain path | PASS | CLI auth path + gravity auth path now use `collect_auth_surface_events_to_file`. |
| Wrapper surface reduced to compatibility only | PASS | `collector.py`, `nikto_adapter.py`, and `auth_scanner.py` are delegation wrappers. |
| No active in-repo callsite bypass to migrated legacy web modules | PASS | Static assertions in service tests + code search show no active bypass callsites. |
| Required validation matrix green | PASS | compileall + pytest (42 passing tests) completed. |

## What Is Still Deferred (Non-Blocking For Template)

- `gobuster_adapter.py` split/migration
- `sqlmap_adapter.py` split/migration
- `transport.py` relocation

These are deferred runtime helper cleanups, not blockers for using web as the migration template.

## Template Pattern Captured For Next Domain

1. Build service-owned runtime wrapper(s) first.
2. Extract/author domain-owned adapter semantics and explicit policy files.
3. Rewire runtime callsites (CLI + gravity) to service wrappers.
4. Convert legacy entrypoints to explicit compatibility wrappers.
5. Add service-level convergence tests plus domain adapter tests.
6. Enforce no bypass callsites by test.

## Recommendation

Web pilot is now template-ready for second-domain migration.

Follow-on should apply the same wrapper-first + semantic-extraction pattern to the next domain, starting with the smallest mixed runtime/adapter surface.
