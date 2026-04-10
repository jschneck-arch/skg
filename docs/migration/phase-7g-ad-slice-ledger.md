# Phase 7G AD Slice Ledger

Date: 2026-04-02

## Selected Slice

- Slice: Kerberoast baseline exposure normalization (AD-01 / AD-02 core only)
- Canonical attack path: `ad_kerberoast_exposure_baseline_v1`

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` (AD-01 / AD-02 portion only) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_kerberoast_exposure/run.py` | adapter | split + rewritten | Migrated only Kerberoast baseline semantics (enabled SPN-linked account exposure + RC4-permitted subset). | Source inventory variants may require additional normalization in future service wrappers. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` Kerberoast branch (`servicePrincipalName` + encryption types) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_kerberoast_exposure/run.py` | adapter | split + rewritten | Added parser-shape-tolerant SPN and encryption evaluation without migrating ldap runtime orchestration. | Legacy parser remains active for non-canonical runtime paths. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` + `ldapdomaindump/parse.py` duplicated account/encryption semantics | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/account_semantics.py` | helper | reused | Reused canonical helper layer (`is_account_enabled`, `encryption_allows_rc4`) to avoid semantic duplication. | Helper may need extension for additional encryption flag encodings. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (AD-01 / AD-02 evidence intent only) | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | ontology | split + rewritten | Added canonical Kerberoast baseline wickets without AD-03/AD-23 coupling. | No formal legacy-to-canonical ID crosswalk artifact yet. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` | ontology | split + rewritten | Added narrow path `ad_kerberoast_exposure_baseline_v1` for AD-01/AD-02 core only. | Follow-on AD-03 and AD-23 semantics remain deferred. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | ontology | split + rewritten | Extended canonical AD catalog authority with Kerberoast baseline slice entries. | Catalog version remains static while slice count increases. |
| `N/A (new canonical policy artifact)` | `packages/skg-domains/ad/src/skg_domain_ad/policies/kerberoast_exposure_policy.yaml` | policy | added | Added explicit policy controls for this slice (`exclude_machine_accounts`, confidence/rank). | Default policy values may require environment-specific calibration. |
| `N/A (new canonical fixture)` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_kerberoast_exposure_inventory.json` | fixture | added | Added focused fixture for Kerberoast baseline semantics across SPN/encryption combinations. | Fixture does not include all source/export edge cases. |
| `N/A (new canonical example)` | `packages/skg-domains/ad/src/skg_domain_ad/examples/kerberoast_exposure_slice.md` | example | added | Documented canonical usage and explicit exclusions for this slice. | Example is static and not a runtime integration path. |
| `N/A (existing canonical projector reused)` | `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py` | projector | reused | Existing projector supports new slice via required wicket path definition. | Path-level scoring strategy may need refinement as additional high-coupling slices land. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_kerberoast_exposure_adapter.py` | adapter test | added | Added realized/blocked/unknown behavior tests for AD-01/AD-02 baseline slice semantics. | Tests intentionally exclude AD-03/AD-23 semantics in this phase. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_kerberoast_exposure_e2e.py` | projector test | added | Added required adapter -> canonical events -> projector end-to-end coverage for Kerberoast baseline slice. | Uses fixture inventory rather than runtime collector path. |
| `N/A (package updates)` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/policies/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml`, `packages/skg-domains/ad/README.md` | helper | rewritten | Updated canonical exports and metadata to include Phase 7G slice. | Metadata drift risk if future slice updates do not keep exports/docs aligned. |
