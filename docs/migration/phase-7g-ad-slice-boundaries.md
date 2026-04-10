# Phase 7G AD Slice Boundaries

Date: 2026-04-02

## Slice Boundary

Migrated in Phase 7G:
- Kerberoast baseline exposure normalization only (AD-01 / AD-02 core semantics).

Explicitly not migrated in Phase 7G:
- AD-03 detection/absence coupling
- AD-23 privilege/value coupling
- AD-05 and other AS-REP path/value semantics
- delegation, ACL, DCSync, AdminSDHolder, and broad ad-lateral path reasoning
- BloodHound/ldapdomaindump parser loading, runtime execution, scheduling, and emission orchestration

## Ownership Decisions

1. AD domain owns Kerberoast baseline semantics.
- Adapter:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_kerberoast_exposure/run.py`
- Ontology:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json`
- Policy:
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/kerberoast_exposure_policy.yaml`

2. Canonical helper reuse preserved.
- Reused shared helper layer:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/account_semantics.py`
- No duplicate UAC/encryption interpretation logic was introduced.

3. Service/runtime ownership preserved.
- No runtime collector/orchestrator modules were migrated into AD domain package.
- No parser/schema loading, scheduler, or emission runtime logic was added to domain modules.

## Boundary Risks Remaining

| Area | Risk | Status |
|---|---|---|
| AD-03/AD-23 coupling residue | Legacy Kerberoast function still co-locates AD-01/02 with AD-03/23 reasoning. | deferred |
| Runtime seam coupling | Source parsing and emission seams still live in legacy adapters for non-canonical runtime paths. | deferred |
| Legacy ID crosswalk | Canonical `AD-KR-*` wickets are not yet mapped through explicit crosswalk artifacts to legacy AD-01/02 IDs. | deferred |

## Boundary Check Outcome

- AD domain remained semantic-only.
- Runtime/orchestration concerns stayed out of canonical AD modules.
- No `sys.path` hacks or install-shape assumptions were introduced by this migration.
