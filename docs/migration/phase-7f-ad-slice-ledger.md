# Phase 7F AD Slice Ledger

Date: 2026-04-02

## Selected Slice

- Slice: AS-REP baseline exposure normalization (AD-04 core only)
- Canonical attack path: `ad_asrep_exposure_baseline_v1`

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_asrep` (AD-04 portion only) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_asrep_exposure/run.py` | adapter | split + rewritten | Migrated baseline AS-REP exposure semantics only (enabled + pre-auth disabled) and excluded AD-05 privilege/value coupling. | Source inventory variance may require additional normalization in future service wrappers. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` AD-04 branch | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_asrep_exposure/run.py` | adapter | split + rewritten | Added UAC- and explicit-flag-based pre-auth evaluation using canonical helper layer. | Mixed parser code in legacy still active for non-canonical runtime paths. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` + `ldapdomaindump/parse.py` duplicated account-state logic | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/account_semantics.py` | helper | reused (from Phase 7E) | Reused extracted helper for `is_account_enabled` and `has_dont_require_preauth`; avoided duplicate semantics in new slice. | Flag interpretation may need extension for additional directory export formats. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (AD-04 evidence intent only) | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | ontology | split + rewritten | Added canonical AS-REP wickets: observation seam and baseline exposure seam. | No formal legacy-to-canonical ID crosswalk artifact yet (`AD-04` to `AD-AS-*`). |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` | ontology | split + rewritten | Added narrow path `ad_asrep_exposure_baseline_v1` for AD-04 core semantics only. | Follow-on AD-05/value coupling path remains deferred. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | ontology | split + rewritten | Extended canonical AD catalog with AS-REP baseline slice authority. | Catalog version still static while adding slices; future versioning policy needed. |
| `N/A (new canonical policy artifact)` | `packages/skg-domains/ad/src/skg_domain_ad/policies/asrep_exposure_policy.yaml` | policy | added | Made AS-REP slice behavior explicit (`exclude_machine_accounts`, confidence/evidence rank). | Default machine-account policy may need tuning by environment. |
| `N/A (new canonical fixture)` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_asrep_exposure_inventory.json` | fixture | added | Added focused fixture for AS-REP baseline semantics across explicit and UAC-driven cases. | Fixture does not cover all edge-case account representations. |
| `N/A (new canonical example)` | `packages/skg-domains/ad/src/skg_domain_ad/examples/asrep_exposure_slice.md` | example | added | Documented canonical usage for this narrow slice. | Example is static and not a runtime integration path. |
| `N/A (existing canonical projector reused)` | `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py` | projector | reused | Existing projector already supports new slice via ontology-required wickets. | Path-level score tuning may be needed as additional high-coupling slices land. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_asrep_exposure_adapter.py` | adapter test | added | Added behavior tests for realized/blocked/unknown status handling. | Tests focus on AD-04 core only by design. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_asrep_exposure_e2e.py` | projector test | added | Added required adapter -> events -> projector end-to-end coverage for AS-REP baseline slice. | Uses fixture inventory rather than runtime collector path. |
| `N/A (package updates)` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/policies/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml`, `packages/skg-domains/ad/README.md` | helper | rewritten | Updated exports and package metadata to include the Phase 7F slice. | Metadata drift risk if future slice updates miss mirrored docs/exports. |
