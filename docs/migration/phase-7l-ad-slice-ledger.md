# Phase 7L AD Slice Ledger

Date: 2026-04-02

## Selected Slice

- Slice: AD-22 core privileged-session tiering posture only
- Canonical attack path: `ad_privileged_session_tiering_baseline_v1`

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_stale_privileged` (AD-22 static branch semantics only) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/run.py` | adapter | split + rewritten | Replaced legacy static AD-22 output with canonical AD-owned interpretation of the AD-22 sidecar summary contract. | Sidecar summary quality still depends on service-side evidence completeness. |
| `Phase 7K runtime sidecar contract` (`ad22_tiering_input.json`) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/run.py` | adapter | rewritten | Consumes canonical AD-shaped sidecar input (`skg.ad.tiering_input.v1`) and emits domain-owned AD-22 core events. | Contract versioning for future schema changes is not yet formalized beyond policy `schema`. |
| `N/A (new canonical adapter package)` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/__init__.py` | adapter | added | Exposes canonical AD-22 adapter entrypoints for mapping from in-memory payloads and sidecar files. | None for current scope. |
| `N/A (canonical export wiring)` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/__init__.py` | adapter | rewritten | Registers AD-22 adapter in public domain adapter exports. | Export drift risk if future slices are added without export updates. |
| `N/A (canonical package export wiring)` | `packages/skg-domains/ad/src/skg_domain_ad/__init__.py` | adapter | rewritten | Promotes AD-22 adapter in public domain-pack API. | Same export drift risk as above. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::AD-22` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | mapping | split + rewritten | Added canonical AD-22 core wickets (`AD-TI-01`, `AD-22`) with baseline-only semantics. | Legacy-to-canonical crosswalk remains implicit and undocumented in machine-readable form. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` AD-22 posture intent only | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` | mapping | split + rewritten | Added canonical baseline path `ad_privileged_session_tiering_baseline_v1` with no path/value coupling. | Path-level coupling may reappear if legacy path requirements are reintroduced without decomposition. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` AD-22 wicket metadata seam | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | mapping | split + rewritten | Extended canonical AD catalog with AD-22 core semantics and path entry only. | Catalog version remains static despite scope expansion. |
| `N/A (new canonical policy artifact)` | `packages/skg-domains/ad/src/skg_domain_ad/policies/tiering_posture_policy.yaml` | policy | added | Added explicit policy for source identity, schema, pointer prefix, and confidence/rank for AD-22 core wickets. | Confidence/rank defaults may need calibration after live runtime data accumulation. |
| `N/A (policy loader wiring)` | `packages/skg-domains/ad/src/skg_domain_ad/policies/__init__.py` | policy | rewritten | Added `load_tiering_posture_policy` for canonical adapter usage. | None for current scope. |
| `Phase 7K runtime seam sidecar output` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_tiering_posture_input.json` | fixture | added | Added representative AD-22 sidecar fixture for canonical adapter/projector tests. | Fixture does not cover all unknown-tier permutations. |
| `N/A (new canonical slice documentation)` | `packages/skg-domains/ad/src/skg_domain_ad/examples/tiering_posture_slice.md` | example | added | Documents AD-22 core slice entrypoints, path, and wickets. | Documentation-only artifact; runtime guarantees come from tests. |
| `Phase 7K runtime seam route` (`ad22_tiering_input.json`) | `packages/skg-services/src/skg_services/gravity/ad_runtime.py` | service wrapper | rewritten | Added `map_ad22_sidecar_to_events` for canonical invocation of the AD-22 domain adapter from service runtime. | Wrapper currently supports sidecar-file invocation only. |
| `skg/sensors/adapter_runner.py::run_bloodhound` | `skg/sensors/adapter_runner.py` | service wrapper | rewritten | Added conditional canonical AD-22 mapping when `attack_path_id=ad_privileged_session_tiering_baseline_v1` and preserved legacy AD-22 quarantine. | Default BloodHound path remains legacy-focused unless configured for AD-22 slice path. |
| `N/A (new canonical adapter tests)` | `packages/skg-domains/ad/tests/test_ad_tiering_posture_adapter.py` | adapter | added | Added realized/blocked/unknown coverage for AD-22 core mapping semantics. | Tests are fixture-based and do not validate external runtime transport. |
| `N/A (new AD-22 e2e tests)` | `packages/skg-domains/ad/tests/test_ad_tiering_posture_e2e.py` | projector | added | Added adapter -> canonical events -> AD projector e2e validation for AD-22 baseline path. | E2E path uses synthetic snapshots and does not validate ad-lateral projector integration. |
| `N/A (runtime seam integration tests)` | `packages/skg-services/tests/test_ad_runtime_wrappers.py` | service wrapper | rewritten | Added assertion that `run_bloodhound()` emits canonical AD-22 events when AD-22 baseline path is requested. | Broader daemon orchestration flows remain out of Phase 7L scope. |
