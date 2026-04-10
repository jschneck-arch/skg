# Phase 7I AD Slice Ledger

Date: 2026-04-02

## Selected Slice

- Slice: LAPS baseline coverage normalization (AD-25 core only)
- Canonical attack path: `ad_laps_coverage_baseline_v1`

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_laps` (AD-25 baseline seam only) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_laps_coverage/run.py` | adapter | split + rewritten | Migrated only non-DC enabled host LAPS baseline semantics; excluded event writer/runtime orchestration. | Source inventories with sparse LAPS fields can remain indeterminate and require service wrapper enrichment. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` AD-25 attribute seam (`ms-Mcs-AdmPwd`, `msLAPS-Password`) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_laps_coverage/run.py` | adapter | split + rewritten | Added source-shape-tolerant attribute interpretation without migrating ldap parser/runtime `main()`. | Exporter-specific variants of LAPS attributes may require additional canonical key mapping later. |
| `Phase 7H helper extraction seam` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/laps_semantics.py` | helper | rewritten + reused | Reused canonical helper APIs and extended `resolve_laps_presence` to accept mapped attribute-key lists from domain mappings. | Helper currently uses legacy non-`None` attribute-present interpretation; richer quality checks may be needed later. |
| `N/A (new canonical adapter package)` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_laps_coverage/__init__.py` | adapter | added | Exposes canonical AD LAPS adapter entrypoint. | None for current scope. |
| `N/A (canonical export wiring)` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/__init__.py` | adapter | rewritten | Registers `map_laps_coverage_to_events` in public adapter exports. | Export list must stay synchronized as future slices land. |
| `N/A (canonical package export wiring)` | `packages/skg-domains/ad/src/skg_domain_ad/__init__.py` | adapter | rewritten | Promotes AD LAPS adapter as public domain-pack API. | Same export drift risk as above. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` AD-25 intent only | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | mapping | split + rewritten | Added canonical LAPS wickets (`AD-LP-01`, `AD-LP-02`) for baseline semantics only. | No explicit legacy-to-canonical ID crosswalk artifact yet. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` AD-25 path evidence only | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` | mapping | split + rewritten | Added narrow canonical path `ad_laps_coverage_baseline_v1` without AD-22 coupling. | Future higher-coupling paths may need separate canonical value/path layers. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | mapping | split + rewritten | Extended canonical AD catalog for LAPS baseline slice authority only. | Catalog version remains static while adding slices; versioning policy remains pending. |
| `N/A (new canonical policy artifact)` | `packages/skg-domains/ad/src/skg_domain_ad/policies/laps_coverage_policy.yaml` | policy | added | Added explicit policy for source identity, pointer prefix, and wicket confidence/rank. | Default confidence values may need environment calibration. |
| `N/A (policy loader wiring)` | `packages/skg-domains/ad/src/skg_domain_ad/policies/__init__.py` | policy | rewritten | Added `load_laps_coverage_policy` for canonical adapter usage. | None for current scope. |
| `N/A (new domain mapping artifact)` | `packages/skg-domains/ad/src/skg_domain_ad/mappings/laps_semantics.yaml` | mapping | added | Added explicit domain-owned key mapping for LAPS explicit flags, domain-controller keys, and LAPS password attributes. | Mapping may need extension for additional exporter key variants. |
| `N/A (mapping loader wiring)` | `packages/skg-domains/ad/src/skg_domain_ad/mappings/__init__.py` | mapping | rewritten | Added `load_laps_semantics_mapping` and wired adapter use to avoid hardcoded key sprawl. | Loader currently returns untyped dict and relies on adapter-level key validation. |
| `N/A (new canonical fixture)` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_laps_coverage_inventory.json` | fixture | added | Added representative fixture with mixed explicit and attribute-driven LAPS signals. | Fixture does not cover every exporter edge case. |
| `N/A (new canonical example)` | `packages/skg-domains/ad/src/skg_domain_ad/examples/laps_coverage_slice.md` | example | added | Documents slice usage and wickets. | Static documentation only; no runtime guarantees. |
| `N/A (manifest metadata update)` | `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml` | mapping | rewritten | Updated manifest metadata to include Phase 7I slice. | Metadata drift risk if future phases skip manifest updates. |
| `N/A (domain package readme update)` | `packages/skg-domains/ad/README.md` | example | rewritten | Updated AD pack scope statement and implemented slices list. | Documentation can drift from runtime scope if not maintained. |
| `N/A (new adapter tests)` | `packages/skg-domains/ad/tests/test_ad_laps_coverage_adapter.py` | adapter | added | Added realized/blocked/unknown coverage for AD-25 baseline semantics. | Test fixtures remain synthetic snapshots. |
| `N/A (new e2e tests)` | `packages/skg-domains/ad/tests/test_ad_laps_coverage_e2e.py` | projector | added | Added required adapter -> canonical events -> projector end-to-end validation for LAPS baseline slice. | E2E uses fixture data, not runtime transport collectors. |
