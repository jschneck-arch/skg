# Phase 5C Web Deferred Runtime

Date: 2026-04-01

## Deferred Runtime Residue After Convergence

| Path | Classification | Why deferred | Exact next step | Removal phase target |
|---|---|---|---|---|
| `skg-web-toolchain/adapters/web_active/auth_scanner.py` | deferred runtime | Auth session orchestration still uses legacy scanner flow and imports collector helper symbols. | Build service wrapper for authenticated runtime flow and consume canonical web domain semantics; then sever collector helper dependency. | Phase 5D or Phase 6 |
| `skg-web-toolchain/adapters/web_active/transport.py` | deferred runtime | Raw socket/TLS/proxy transport utility still legacy-local. | Move transport runtime utility into `skg-services` shared runtime component; update auth scanner/service wrappers to consume it. | Phase 5D |
| `skg-web-toolchain/adapters/web_active/gobuster_adapter.py` | deferred runtime | Runtime invocation + mapping are still mixed in legacy adapter. | Split runtime execution to service wrapper and preserve mapping semantics in canonical web domain pack. | Phase 5D |
| `skg-web-toolchain/adapters/web_active/sqlmap_adapter.py` | deferred runtime | Runtime exploit execution and mixed cross-domain side-effects are still legacy-coupled. | Split runtime orchestration to services and isolate domain-safe mapping semantics before migration. | Phase 5D+ |
| `skg-gravity/gravity_field.py` (`_exec_auth_scanner`) | deferred callsite | Still imports legacy `auth_scanner` module through legacy web adapter path assumptions. | Migrate to service-owned auth runtime wrapper and canonical adapter emission path. | Phase 5D |
| `skg/cli/commands/target.py` (`instrument=web` with `--auth`) | deferred callsite | Still shells into legacy `auth_scanner.py`. | Redirect CLI auth path to service-owned auth runtime wrapper. | Phase 5D |

## Legacy Compatibility Wrappers Retained In Phase 5C

| Path | Why retained | Blocking dependency |
|---|---|---|
| `skg-web-toolchain/adapters/web_active/collector.py` | Collector helper symbols still imported by auth scanner. | `auth_scanner.py` imports collector constants/functions. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | Controlled compatibility bridge for external scripts during migration. | Potential external direct imports outside canonical runtime callsites. |

## Safety Assessment

- Migrated flows (`http_collector`, `nikto`, CLI unauthenticated web observe) now converge to service wrappers + canonical domain semantics.
- Deferred residue is explicit and bounded.
- Remaining cleanup is concentrated in authenticated flow and auxiliary web runtime adapters.
