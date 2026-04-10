# Phase 5B Web Deferred Residue

Date: 2026-04-01

## Residue Still Deferred After Consolidation

| Legacy path | Classification | Why retained | Exact next step | Unresolved risk |
|---|---|---|---|---|
| `skg-web-toolchain/adapters/web_active/collector.py` | deferred | File still mixes active runtime probing, transport usage, HTML crawling/probing, and direct event writing. Only domain mapping subset was extracted in Phase 5B. | Split into service runtime collector (`skg-services/gravity` or harness-owned runtime) + domain mapper invocation (`skg_domain_web.adapters.web_surface_fingerprint`). | Legacy caller paths may continue bypassing canonical domain adapter logic. |
| `skg-web-toolchain/adapters/web_active/transport.py` | deferred | Pure runtime transport implementation (socket/TLS/proxy). Out of domain ownership. | Migrate to service/runtime transport utility package and update runtime callsites. | If left in legacy long-term, service/runtime drift will continue. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | deferred | Subprocess execution, filesystem output handling, fallback envelope logic, and `sys.path` mutation remain mixed with mapping concerns. Mapping portion was extracted in Phase 5B. | Split runtime scan execution into service module; make it call `map_nikto_findings_to_events` from domain package; then retire mapping logic in legacy file. | Dual behavior can diverge between legacy runtime and canonical mapper if not cut over quickly. |
| `skg-web-toolchain/adapters/web_active/auth_scanner.py` | deferred | Runtime scanner/auth orchestration concerns are still interleaved with finding logic. | Extract reusable finding schema + domain mapping rules; keep runtime scanner in services. | Continued runtime/domain coupling blocks clean domain-pack expansion. |
| `skg-web-toolchain/adapters/web_active/sqlmap_adapter.py` | deferred | Cross-domain side effects and exploitation runtime behavior are mixed into adapter file. | Split web-domain mapping from runtime execution and from data-domain side effects; migrate in separate controlled pass. | High coupling risk across web/data domains if moved prematurely. |
| `skg-web-toolchain/adapters/ssh_collect/parse.py` | deferred | Legacy wicket model and SSH runtime coupling are not canonical web-domain semantics. | Rewrite or archive under legacy quarantine; do not migrate into canonical web pack as-is. | Ontology mismatch can pollute canonical web domain if reused. |
| `skg-web-toolchain/projections/run.py` | deferred | Legacy wrapper path; canonical projector already exists in domain pack. | Remove once all runtime callsites resolve projector through registry/domain-pack paths. | Wrapper may remain accidentally active in old operator scripts. |
| `skg-web-toolchain/adapters/web_active/__init__.py` | deferred | Legacy package bootstrap convenience only. | Remove with the remaining legacy runtime adapter package cleanup wave. | Minimal risk, but keeps stale import path alive. |
| `skg-web-toolchain/forge_meta.json` | deferred | Legacy toolchain metadata; no longer authoritative for web domain-pack manifest. | Keep until toolchain archival or explicit compatibility adapter is added for legacy discovery consumers. | Old tooling may still read this as if it were canonical. |

## Consolidation Effect

- Deferred surface is smaller than Phase 5A for `collector.py` and `nikto_adapter.py` because domain-owned mapping/policy artifacts now exist in the web pack.
- Remaining residue is runtime-heavy and intentionally excluded from domain ownership.

## Remaining Live Legacy Callsites

| Caller path | Live legacy target | Why still live | Required follow-on step |
|---|---|---|---|
| `skg/cli/commands/target.py` | `skg-web-toolchain/adapters/web_active/collector.py` | CLI web observe flow still shells into legacy runtime collector path. | Move web observe runtime flow to a service-owned runtime module that feeds canonical web domain adapters. |
| `skg-gravity/gravity_field.py` | `skg-web-toolchain/adapters/web_active/collector.py` and `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | Gravity runtime still imports legacy web runtime adapters directly for execution. | Replace with registry-resolved domain adapter mappings plus service runtime wrappers, then remove direct legacy imports. |
