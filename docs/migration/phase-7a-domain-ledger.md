# Phase 7A Domain Ledger

Date: 2026-04-02

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_privileged_membership/run.py` | adapter | split + rewritten | Extracted only AD-owned privilege-group and membership semantics into canonical domain adapter contract; removed non-slice AD attack semantics and runtime concerns. | Input normalization currently targets BloodHound-like snapshots; additional source-shape variants deferred. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `packages/skg-domains/ad/src/skg_domain_ad/mappings/privileged_group_aliases.yaml` | mapping | split | Externalized privileged-group alias semantics into explicit domain artifact. | Alias list may require enterprise-specific tuning. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | ontology | split + rewritten | Isolated one AD semantic slice and removed ad-lateral attack-chain breadth from ontology authority. | Wider AD wicket universe still deferred. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` | ontology | split + rewritten | Defined minimal AD paths for the selected privilege-membership slice only. | Additional AD paths deferred pending corrective splits. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | ontology | split + rewritten | Created canonical AD catalog scoped to migrated slice, preserving evidence-hint intent without lateral-chain overload. | Catalog coverage intentionally incomplete for broader AD semantics. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py` | projector | rewritten | Replaced legacy projector path-hacks/import hacks with canonical core projection API usage and package-local ownership. | Projector currently supports selected AD slice only. |
| `packages/skg-domains/host/src/skg_domain_host/policies/projection_policy.yaml` (template pattern) | `packages/skg-domains/ad/src/skg_domain_ad/policies/projection_policy.yaml` | policy | rewritten | Reused canonical domain projection policy pattern for AD score/classification semantics. | None for migrated slice. |
| `skg-ad-lateral-toolchain/tests/golden/events/bloodhound/users.json` + `groups.json` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_privileged_membership_inventory.json` | fixture | split + rewritten | Built focused fixture covering only selected privilege-membership slice. | Fixture does not represent full AD dataset variants. |
| `N/A (new canonical package authority)` | `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml` | manifest | rewritten | Established single canonical manifest authority under src-pack layout. | None. |
| `N/A (new canonical package)` | `packages/skg-domains/ad/tests/test_ad_privilege_adapter.py` | tests | added | Added package-local adapter tests for migrated AD slice behavior. | None. |
| `N/A (new canonical package)` | `packages/skg-domains/ad/tests/test_ad_projector_e2e.py` | tests | added | Added required AD end-to-end adapter -> canonical events -> AD projector coverage and registry discovery assertion. | None. |

## Manifest Authority

- Removed legacy scaffold manifest: `packages/skg-domains/ad/domain.yaml`
- Canonical authority: `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml`
