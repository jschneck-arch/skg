# Phase 7C AD Slice Ledger

Date: 2026-04-02

## Selected Slice

- Slice: password description / credential-hint normalization
- Canonical attack path: `ad_password_hint_exposure_v1`

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_passwords_in_descriptions` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_credential_hints/run.py` | adapter | split + rewritten | Migrated only the credential-hint semantic slice into canonical AD adapter; removed legacy event writer and file runtime coupling. | Input remains inventory-shape dependent; future source-specific wrappers must keep normalization contracts stable. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py::description_has_password` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/text_semantics.py` | helper | extracted (Phase 7B reuse) | Reused canonical helper instead of duplicating lexical hint logic in new slice adapter. | Keyword-based semantics remain heuristic and may require environment-specific tuning. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | `packages/skg-domains/ad/src/skg_domain_ad/policies/credential_hint_policy.yaml` | policy | rewritten | Externalized evidence/confidence policy for this slice as explicit domain artifact. | Confidence defaults may require calibration against real inventories. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | ontology | split + rewritten | Added canonical AD-owned wickets for credential-hint exposure without importing broad ad-lateral ontology. | No canonical crosswalk file yet between `AD-*` legacy IDs and `AD-CH-*` canonical IDs. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` | ontology | split + rewritten | Added single canonical path for this slice only (`ad_password_hint_exposure_v1`). | Additional password-related paths remain deferred until separate slices are defined. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | ontology | split + rewritten | Extended canonical AD catalog with credential-hint slice wickets and path. | Catalog now spans two slices; needs versioning discipline as more slices land. |
| `N/A (new canonical fixture)` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_credential_hint_inventory.json` | fixture | added | Added focused fixture covering source-agnostic credential-hint semantics. | Fixture does not cover all legacy parser edge cases. |
| `N/A (new canonical example)` | `packages/skg-domains/ad/src/skg_domain_ad/examples/credential_hint_slice.md` | example | added | Documented invocation boundary for the new slice. | Example is static and not a runtime wrapper. |
| `N/A (existing canonical projector reused)` | `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py` | projector | reused (no runtime migration) | Existing canonical AD projector already projects by required wickets; no service/runtime logic added. | Future slice-specific projection policy may require per-path configuration. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_credential_hint_adapter.py` | adapter test | added | Added package-local adapter tests for wicket status behavior. | Tests currently cover positive and no-hint baseline only. |
| `N/A (new canonical tests)` | `packages/skg-domains/ad/tests/test_ad_credential_hint_e2e.py` | projector test | added | Added required adapter -> events -> projector end-to-end coverage for the new slice. | End-to-end test uses fixture inventory, not live runtime collection. |

## Additional Canonical Updates

- Updated package exports:
  - `packages/skg-domains/ad/src/skg_domain_ad/__init__.py`
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/__init__.py`
- Updated manifest metadata:
  - `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml`
