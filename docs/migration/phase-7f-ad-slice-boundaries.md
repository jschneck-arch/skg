# Phase 7F AD Slice Boundaries

Date: 2026-04-02

## Slice Boundary

Migrated in Phase 7F:
- AS-REP baseline exposure normalization only (AD-04 core semantics).

Explicitly not migrated in Phase 7F:
- AD-05 privilege/value/path coupling
- Kerberoast coupling branches
- delegation, ACL, DCSync, AdminSDHolder, and broad ad-lateral path semantics
- BloodHound/ldapdomaindump runtime parsing, execution, scheduling, and emission orchestration

## Ownership Decisions

1. AD domain owns AS-REP semantic normalization.
- Adapter:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_asrep_exposure/run.py`
- Ontology:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json`
- Policy:
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/asrep_exposure_policy.yaml`

2. Canonical helper reuse is preserved.
- Reused shared helper layer:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/account_semantics.py`
- No new duplicate UAC/pre-auth bit logic introduced.

3. Services/runtime ownership remains unchanged.
- No code moved from runtime collectors or orchestrators.
- No parser/file-loading/scheduler/orchestration logic added to AD domain package.

## Boundary Risks Remaining

| Area | Risk | Status |
|---|---|---|
| AD-05 coupling residue | Legacy AD-04 and AD-05 remain co-located in legacy functions, creating residual dual-authority pressure. | deferred |
| Runtime seam coupling | Source parsing and emission seams remain in legacy adapters for non-canonical runtime paths. | deferred |
| Legacy ID crosswalk | Canonical `AD-AS-*` wickets are not yet linked via explicit crosswalk to legacy AD-04 identifiers. | deferred |

## Boundary Check Outcome

- AD domain remained semantic-only.
- Runtime/orchestration concerns stayed out of canonical AD modules.
- No `sys.path` hacks or layout assumptions were introduced by this slice migration.
