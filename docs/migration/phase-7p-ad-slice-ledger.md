# Phase 7P AD Slice Ledger

Date: 2026-04-03

## Scope

- Canonical AD delegation posture-core slice (`AD-06` + `AD-08`) only.
- Contract consumed: `skg.ad.delegation_input.v1`.
- Deferred in this phase: `AD-07`, `AD-09`, sensitive-target/value/path reasoning.

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-06 branch | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py` | adapter | split + rewritten | Migrated unconstrained non-DC delegation posture interpretation into canonical AD adapter. | Legacy source still contains mixed AD-07/AD-09 logic outside canonical path. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-08 branch | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py` | adapter | split + rewritten | Migrated protocol-transition constrained delegation posture interpretation into canonical AD adapter. | Legacy source still co-locates AD-08 with AD-09 sensitivity/value logic. |
| `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/delegation_semantics.py` (Phase 7N helper seam) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py` | helper -> adapter use | copied by composition | Canonical adapter consumes existing structural helper layer instead of re-embedding legacy parser semantics. | Helper layer has no runtime context semantics by design; AD-07 requires separate service policy if migrated later. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/__init__.py` | adapter | added | Exposes canonical adapter entrypoints for delegation posture-core mapping. | None. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/policies/delegation_posture_policy.yaml` | policy | added | Makes delegation posture thresholds/contracts explicit and versioned as domain policy artifact. | Future policy evolution may require compatibility notes if confidence/evidence rules change. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` AD-06/AD-08 wicket semantics | `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json` | ontology | split + rewritten | Establishes canonical AD-owned baseline wording for AD-06/AD-08 posture-core semantics. | Legacy ad-lateral catalog still exists and must remain non-authoritative for canonical slice evolution. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_unconstrained_delegation_v1` and `::ad_constrained_delegation_s4u_v1` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml` + `.../catalogs/attack_preconditions_catalog.ad.v1.json` (`ad_delegation_posture_baseline_v1`) | projector path definition | split + rewritten | Canonical path now requires only AD-06 + AD-08 posture-core wickets. | No path/value coupling is carried; higher-coupling semantics remain deferred. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml` | ontology | rewritten | Registers AD-06 and AD-08 labels/descriptions in canonical AD ontology. | Ensure future IDs remain collision-free with quarantined legacy branches. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/fixtures/ad_delegation_posture_input.json` | fixture | added | Provides canonical sidecar fixture for adapter and e2e projection tests. | Fixture reflects baseline-only semantics; does not represent deferred context/value branches. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/examples/delegation_posture_slice.md` | example | added | Documents canonical use and explicit scope exclusions for this slice. | None. |
| `skg/sensors/adapter_runner.py` legacy delegation branch execution output (`AD-06..AD-09`) | `skg/sensors/adapter_runner.py` canonical delegation path filtering + sidecar mapping | service wrapper | rewritten | For `ad_delegation_posture_baseline_v1`, legacy AD-06..AD-09 events are dropped and replaced by canonical AD-06/AD-08 sidecar-mapped events. | Legacy branch still executes for other legacy attack paths and remains migration residue. |
| `N/A` | `packages/skg-services/src/skg_services/gravity/ad_runtime.py::map_ad0608_sidecar_to_events` | service wrapper | added | Adds canonical service invocation path from sidecar contract to AD delegation adapter. | Runtime callers must explicitly choose canonical delegation path id to activate this flow. |
| `N/A` | `packages/skg-services/tests/test_ad_runtime_wrappers.py` + `packages/skg-domains/ad/tests/test_ad_delegation_posture_adapter.py` + `packages/skg-domains/ad/tests/test_ad_delegation_posture_e2e.py` | tests | added | Verifies contract handoff, canonical adapter behavior, and adapter->projector e2e for delegation posture-core. | No tests for deferred AD-07/AD-09 by design. |

## Manifest Update

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml` prior metadata description | `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml` | manifest | rewritten | Updated metadata to include Phase 7P delegation posture-core slice ownership. | Manifest version remains `1.0.0`; version bump policy remains deferred at repo governance level. |
