# Phase 5D Web Wrapper Retirement

Date: 2026-04-01

## Compatibility Wrapper Decisions

| Legacy entrypoint | Decision | Current state | Why retained/retired | Retirement readiness |
|---|---|---|---|---|
| `skg-web-toolchain/adapters/web_active/collector.py` | RETAIN (compatibility wrapper) | File reduced to minimal delegation wrapper -> `collect_surface_events_to_file(...)`. | In-repo callers are migrated; retain temporary bridge for external/operator scripts. | Ready for retirement after one compatibility window if no external direct imports remain. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | RETAIN (compatibility wrapper) | Minimal delegation wrapper -> `collect_nikto_events_to_file(...)`. | In-repo gravity `nikto` path migrated; keep explicit bridge for external direct usage. | Ready for retirement after one compatibility window if no external direct imports remain. |
| `skg-web-toolchain/adapters/web_active/auth_scanner.py` | RETAIN (compatibility wrapper) | Reduced to minimal delegation wrapper -> `collect_auth_surface_events_to_file(...)`. | Auth runtime callsites migrated in CLI + gravity; wrapper retained for controlled compatibility only. | Ready for retirement after one compatibility window if no external direct imports remain. |

## Active Runtime Path Check (In-Repo)

Confirmed active runtime callsites now use canonical service wrappers:
- `skg/cli/commands/target.py`
- `skg-gravity/gravity_field.py`

No active in-repo callsite now imports or dynamically loads the legacy web wrapper files for migrated flows.

## Wrapper Safety Guard

Test coverage includes static callsite assertions:
- `packages/skg-services/tests/test_web_runtime_wrappers.py::test_migrated_callsites_do_not_reference_legacy_auth_entrypoints`

This protects against accidental reintroduction of legacy wrapper callsite bypass.
