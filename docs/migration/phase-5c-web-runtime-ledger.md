# Phase 5C Web Runtime Ledger

Date: 2026-04-01

## Migrated Runtime Callsites

| Caller path | Original runtime target | New runtime target | Action | Why migration was safe | Remaining risk |
|---|---|---|---|---|---|
| `skg/cli/commands/target.py` (`cmd_observe`, `instrument == "web"`) | subprocess execution of `skg-web-toolchain/adapters/web_active/collector.py` | `skg_services.gravity.web_runtime.collect_surface_events_to_file(...)` | rewritten | Runtime execution stays in service layer; semantic mapping comes from canonical `skg_domain_web.adapters.web_surface_fingerprint`. | CLI `auth` branch still uses legacy auth scanner stack (out of scope for Phase 5C). |
| `skg-gravity/gravity_field.py` (`_exec_http_collector`) | direct import and execution of `collector.collect(...)` from legacy web toolchain | `skg_services.gravity.web_runtime.collect_surface_events_to_file(...)` | rewritten | Gravity now executes service wrapper and receives canonical domain-emitted events; no legacy collector import in active path. | `auth_scanner` flow still depends on legacy `collector` helper symbols. |
| `skg-gravity/gravity_field.py` (`_exec_nikto`) | dynamic import of `skg-web-toolchain/adapters/web_active/nikto_adapter.py` + fallback subprocess branch | `skg_services.gravity.web_runtime.collect_nikto_events_to_file(...)` | rewritten | Runtime subprocess invocation remains service-owned; finding-to-event semantics are canonical via `skg_domain_web.adapters.web_nikto_findings`. | Requires `nikto` binary for live findings; when unavailable, wrapper returns no events. |
| `skg-gravity/gravity_field.py` (`detect_instruments`) | availability tied to legacy file existence (`web_active/collector.py`) | availability tied to canonical runtime capability (`_canonical_web_runtime_available`) | rewritten | Selection now tracks canonical service/domain readiness instead of legacy file layout assumptions. | Detection depends on canonical package importability in runtime environment. |

## New Service-Owned Runtime Modules

| New path | Classification | Action | Purpose |
|---|---|---|---|
| `packages/skg-services/src/skg_services/gravity/web_runtime.py` | service runtime wrapper | added | Owns web runtime probing/subprocess orchestration and invokes canonical web domain adapters for semantic emission. |
| `packages/skg-services/src/skg_services/gravity/__init__.py` | service API surface | updated | Exposes new web runtime wrapper APIs from the gravity service package. |

## Service Tests Added

| Path | Coverage |
|---|---|
| `packages/skg-services/tests/test_web_runtime_wrappers.py` | Validates runtime wrapper -> canonical web adapter -> canonical event output for surface and nikto flows. |

## Legacy Entry Points Touched (Compatibility Reduction)

| Legacy path | Action | Result |
|---|---|---|
| `skg-web-toolchain/adapters/web_active/collector.py` | reduced | `collect(...)` now delegates to service-owned canonical runtime wrapper. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | reduced/replaced | File is now an explicit compatibility wrapper that delegates to service-owned canonical runtime wrapper. |
