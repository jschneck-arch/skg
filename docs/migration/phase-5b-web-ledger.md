# Phase 5B Web Ledger

Date: 2026-04-01

## Migrated And Split Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-web-toolchain/adapters/web_active/collector.py` | `packages/skg-domains/web/src/skg_domain_web/mappings/surface_fingerprint_rules.yaml` | mapping | split | Extracted domain-owned header/TLS/CORS signal mapping rules from mixed runtime collector logic. | Rules are a curated subset of collector behavior; deep probe coverage remains deferred. |
| `skg-web-toolchain/adapters/web_active/collector.py` | `packages/skg-domains/web/src/skg_domain_web/policies/surface_fingerprint_policy.yaml` | policy | split | Moved wicket and confidence policy out of inline conditionals and into explicit domain policy artifact. | Confidence values are calibrated for pilot behavior, not full production parity. |
| `skg-web-toolchain/adapters/web_active/collector.py` | `packages/skg-domains/web/src/skg_domain_web/adapters/web_surface_fingerprint/run.py` | adapter | split | Preserved domain mapping semantics (`surface profile` -> canonical `obs.attack.precondition`) while excluding transport/runtime scanning. | Caller must provide pre-collected profile input; runtime collection still lives in legacy/service space. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | `packages/skg-domains/web/src/skg_domain_web/mappings/nikto_patterns.yaml` | mapping | split | Lifted regex-to-wicket map into domain-owned mapping file. | Pattern map may need tuning to match nikto output variants across versions. |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | `packages/skg-domains/web/src/skg_domain_web/policies/nikto_adapter_policy.yaml` | policy | split | Externalized evidence/source policy from hardcoded values. | Policy currently assumes a single source kind (`nikto`). |
| `skg-web-toolchain/adapters/web_active/nikto_adapter.py` | `packages/skg-domains/web/src/skg_domain_web/adapters/web_nikto_findings/run.py` | adapter | split | Rebuilt as mapping-only adapter from normalized findings to canonical protocol envelopes. | Legacy subprocess runner is still required for runtime scan execution until service migration of nikto runtime occurs. |
| `packages/skg-domains/web/domain.yaml` + `packages/skg-domains/web/src/skg_domain_web/manifest.yaml` (dual authority in Phase 5A) | `packages/skg-domains/web/src/skg_domain_web/manifest.yaml` | manifest | rewritten | Consolidated web domain manifest authority to a single canonical source. | Non-updated external scripts that directly read `domain.yaml` may fail until switched to registry APIs. |
| `packages/skg-registry/src/skg_registry/discovery.py` | `packages/skg-registry/src/skg_registry/discovery.py` | manifest | rewritten | Registry now discovers in-package manifests first and resolves component paths relative to manifest location. | Cross-domain packs with nonstandard layout can still expose discovery edge cases; legacy fallback remains for compatibility. |

## Additional New Canonical Assets (No Direct Legacy Source)

- `packages/skg-domains/web/src/skg_domain_web/fixtures/web_surface_profile.json`
- `packages/skg-domains/web/src/skg_domain_web/fixtures/web_nikto_findings.json`
- `packages/skg-domains/web/tests/test_web_surface_fingerprint_adapter.py`
- `packages/skg-domains/web/tests/test_web_nikto_adapter_mapping.py`
- `packages/skg-registry/tests/test_registry_discovery.py::test_discovery_prefers_in_package_manifest_authority`

These support deterministic validation of the new split logic and manifest authority behavior.
