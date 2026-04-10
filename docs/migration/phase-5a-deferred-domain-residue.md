# Phase 5A Deferred Domain Residue (web)

Date: 2026-04-01

## Deferred Legacy Files

| Legacy path | Classification | Why deferred | Exact next split/removal step |
|---|---|---|---|
| `skg-web-toolchain/adapters/web_active/collector.py` | deferred | Mixed domain semantics + runtime execution + network transport probing + CLI orchestration in one file. | Split into: (a) service-owned scanner runtime module, (b) domain adapter mapping module, then migrate mapping-only parts to domain pack. |
| `skg-web-toolchain/adapters/web_active/transport.py` | deferred | Runtime transport implementation (socket/TLS/proxy) is service concern, not domain semantics. | Move to `skg-services` runtime transport layer or dedicated harness utility before any domain migration. |
| `skg-web-toolchain/adapters/web_active/auth_scanner.py` | deferred | Runtime scanner execution and target auth orchestration; not contract-only adapter mapping. | Extract finding schema + mapping logic to domain; keep runtime scanner in services. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | deferred | External tool invocation and fallback branches mixed with event mapping. | Split subprocess runner (service) from finding-to-event mapper (domain adapter). |
| `skg-web-toolchain/adapters/web_active/sqlmap_adapter.py` | deferred | External exploitation runtime and cross-domain (`data`) side effects mixed with adapter semantics. | Split web-domain mapping from data-domain emission and move runtime orchestration to service module. |
| `skg-web-toolchain/adapters/ssh_collect/parse.py` | deferred | Legacy wicket model (`W-*`) and SSH runtime coupling; explicitly marked legacy in-file. | Archive or rewrite entirely using WB-* ontology and domain-pack adapter contracts. |
| `skg-web-toolchain/projections/run.py` | deferred | Wrapper/runtime indirection; not canonical domain-owned projection logic. | Remove once all callers resolve `projectors/web/run.py` via registry/service runtime. |
| `skg-web-toolchain/adapters/web_active/__init__.py` | deferred | Legacy package bootstrap only. | Remove or archive with remaining runtime adapters after service split. |
| `skg-web-toolchain/forge_meta.json` | deferred | Legacy toolchain manifest; duplicates domain-pack manifest authority. | Keep until toolchain tree is archived or re-pointed to domain pack metadata in later phase. |

## Residue Not Treated As Canonical Source

The following were explicitly excluded from canonical extraction authority in Phase 5A:
- `skg_deploy/**`
- `skg-gravity/**`
- `.claude/worktrees/**`

## Removal Readiness Summary

- Ready now: keep deferred files in legacy unchanged; canonical pilot does not depend on them.
- Not ready now: deleting legacy web toolchain files outright would break existing legacy runtime paths.
- Recommended next targeted split: `collector.py` + `nikto_adapter.py` runtime/mapping decomposition.
