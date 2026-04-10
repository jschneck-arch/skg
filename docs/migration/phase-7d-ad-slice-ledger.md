# Phase 7D AD Slice Ledger

Date: 2026-04-02

## Selected Slice

- Slice: weak password policy normalization
- Canonical attack path: `ad_weak_password_policy_v1`

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_weak_password_policy` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_weak_password_policy/run.py` | adapter | split + rewritten | Migrated only weak minimum-password-length semantics into canonical AD adapter; removed legacy file/event runtime coupling. | Current normalization focuses on min-length signal; broader policy semantics remain deferred. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` (`AD-24` policy branch) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_weak_password_policy/run.py` | adapter | split + rewritten | Added source-shape tolerant policy extraction (`domains`, `domain_policy`, `policy`) without migrating ldap runtime flows. | Additional directory-export variants may require future parser wrapper adjustments. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` + `ldapdomaindump/parse.py` | `packages/skg-domains/ad/src/skg_domain_ad/policies/weak_password_policy.yaml` | policy | rewritten | Externalized threshold/confidence/evidence settings as explicit domain policy artifact. | Threshold defaults may require environment-level calibration. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | ontology | split + rewritten | Added canonical AD weak-policy wickets without importing broad ad-lateral ontology. | No formal legacy-to-canonical wicket crosswalk artifact yet. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` | ontology | split + rewritten | Added narrow canonical path `ad_weak_password_policy_v1` for this slice only. | Additional password policy semantics (complexity/history/lockout) remain deferred. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | ontology | split + rewritten | Extended canonical AD catalog to include weak policy slice authority. | Catalog growth needs strict versioning discipline as more slices land. |
| `N/A (new canonical fixture)` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_weak_password_policy_inventory.json` | fixture | added | Added focused weak-policy fixture for canonical tests. | Fixture is representative, not exhaustive for all source export variants. |
| `N/A (new canonical example)` | `packages/skg-domains/ad/src/skg_domain_ad/examples/weak_password_policy_slice.md` | example | added | Documented canonical invocation for weak-policy slice. | Example is static and not a service runtime wrapper. |
| `N/A (existing canonical projector reused)` | `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py` | projector | reused | Existing projector already handles new slice via required wickets from ontology path definition. | Future slice-specific score shaping may require path-level policy controls. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_weak_password_policy_adapter.py` | adapter test | added | Added slice-specific behavior tests (realized/blocked/unknown). | Tests currently emphasize minimum-length semantics only. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_weak_password_policy_e2e.py` | projector test | added | Added required adapter -> canonical events -> projector end-to-end coverage for weak-policy slice. | End-to-end test uses fixture inventory rather than live collection path. |
| `N/A (package metadata updates)` | `packages/skg-domains/ad/src/skg_domain_ad/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/adapters/__init__.py`, `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml`, `packages/skg-domains/ad/README.md` | helper | rewritten | Updated canonical exports and package metadata to include the third AD slice. | Metadata drift risk if future slice additions are not updated consistently. |
