# Phase 7C AD Slice Boundaries

Date: 2026-04-02

## Slice Boundary

Migrated in Phase 7C:
- Description-field credential-hint semantics only.

Not migrated in Phase 7C:
- LDAP/BloodHound transport execution
- scheduler/state/runtime orchestration
- delegation, ACL abuse, DCSync, AdminSDHolder, and broad ad-lateral attack-chain semantics

## Ownership Decisions

1. AD domain owns slice semantics.
- Adapter:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_credential_hints/run.py`
- Ontology:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json`
- Policy:
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/credential_hint_policy.yaml`
- Mapping/helper reuse:
  - `packages/skg-domains/ad/src/skg_domain_ad/mappings/password_description_keywords.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/text_semantics.py`

2. Projector ownership remains canonical AD domain.
- Reused:
  - `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py`
- No runtime orchestration added to projector code.

3. Service/runtime ownership preserved.
- No code moved from:
  - `skg/sensors/bloodhound_sensor.py`
  - `skg-gravity/adapters/ldap_enum.py`
- No subprocess/network/runtime collection logic introduced in AD domain package.

## Boundary Risks Remaining

| Area | Risk | Status |
|---|---|---|
| Legacy AD runtime callsites | Runtime wrappers still route non-migrated AD flows through legacy ad-lateral modules. | deferred |
| Legacy ID crosswalk | Legacy `AD-17/AD-18` concepts now canonicalized as `AD-CH-01/AD-CH-02` without explicit crosswalk artifact. | deferred |
| Parser coupling | Source-shape normalization for BloodHound/LDAP remains in legacy/runtime modules. | deferred |

## Boundary Check Outcome

- Core/protocol remained domain-neutral.
- AD domain pack remains semantic-only.
- No `sys.path` hacks or hardcoded `/opt/skg` assumptions were introduced in new slice modules.
