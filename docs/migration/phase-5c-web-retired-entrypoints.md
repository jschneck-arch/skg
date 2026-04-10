# Phase 5C Web Retired Entry Points

Date: 2026-04-01

## Status: Wave 1 Retirement (collector + nikto)

The following legacy web entrypoints were reduced from active runtime ownership to explicit compatibility wrappers.

| Legacy path | Previous behavior | New behavior | Retirement class | Active callsite status | Residual risk |
|---|---|---|---|---|---|
| `skg-web-toolchain/adapters/web_active/collector.py` | Owned runtime probing + semantic emission in one mixed file and acted as direct runtime execution path. | `collect(...)` now delegates to `skg_services.gravity.web_runtime.collect_surface_events_to_file(...)`. Legacy helper symbols remain for `auth_scanner.py` compatibility. | reduced to compatibility wrapper | No active migrated flow directly calls this module (`target.py` and gravity `http_collector` migrated). | File still exports helper symbols imported by `auth_scanner.py`; cannot fully delete yet. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | Owned subprocess + semantic mapping and was dynamically imported by gravity. | Replaced with a compatibility wrapper that delegates to `skg_services.gravity.web_runtime.collect_nikto_events_to_file(...)`. | reduced to compatibility wrapper | No active migrated flow calls this module (gravity `nikto` migrated). | Third-party scripts importing this file now depend on canonical service package availability. |

## Explicit Non-Retired Items (Out Of Scope)

These remain legacy-active in Phase 5C:
- `skg-web-toolchain/adapters/web_active/auth_scanner.py`
- `skg-web-toolchain/adapters/web_active/gobuster_adapter.py`
- `skg-web-toolchain/adapters/web_active/sqlmap_adapter.py`
- `skg-web-toolchain/adapters/web_active/transport.py`

## Deletion Readiness For These Two Entry Points

- `nikto_adapter.py`: ready for deletion after one release cycle once no external operator scripts import it directly.
- `collector.py`: not deletion-ready until `auth_scanner.py` no longer imports collector helper symbols and auth runtime path is service-owned.
