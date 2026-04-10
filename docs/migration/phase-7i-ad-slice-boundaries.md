# Phase 7I AD Slice Boundaries

Date: 2026-04-02

## Slice Boundary

Migrated in Phase 7I:
- LAPS baseline coverage normalization only (AD-25 core semantics)
- canonical attack path: `ad_laps_coverage_baseline_v1`

Explicitly not migrated in Phase 7I:
- AD-22 tiering coupling
- AD-03 / AD-23 semantics
- delegation, ACL abuse, DCSync, AdminSDHolder
- BloodHound/ldap parser loading and runtime execution/orchestration
- broad ad-lateral projector/path reasoning

## Ownership Decisions

1. AD domain owns LAPS baseline semantic normalization.
- Adapter:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_laps_coverage/run.py`
- Ontology/catalog/path artifacts:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json`
- Policy:
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/laps_coverage_policy.yaml`
- Mapping:
  - `packages/skg-domains/ad/src/skg_domain_ad/mappings/laps_semantics.yaml`

2. Canonical helper reuse is enforced.
- Reused:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/laps_semantics.py`
- Helper interface now supports mapping-driven LAPS attribute keys.
- No duplicate LAPS signal logic was introduced.

3. Service/runtime ownership preserved.
- No parser/file-loading/runtime-orchestration code was migrated from:
  - `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`
  - `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py`
- No scheduler/transport/emission runtime logic was introduced into AD domain modules.

## Boundary Risks Remaining

| Area | Risk | Status |
|---|---|---|
| AD-22 coupling | Legacy path definitions still bind LAPS posture to tiering assumptions in ad-lateral catalog. | deferred |
| Parser/runtime split | Legacy ldapdomaindump branch remains monolithic outside canonical adapters. | deferred |
| Legacy-to-canonical crosswalk | Explicit AD-25 -> AD-LP-* crosswalk artifact is not yet formalized. | deferred |

## Boundary Check Outcome

- AD domain remained semantic-only for this slice.
- Runtime/orchestration concerns stayed out of canonical AD modules.
- No path/value/redteam coupling was imported into the AD-25 baseline slice.
