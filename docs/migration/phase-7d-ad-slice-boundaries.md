# Phase 7D AD Slice Boundaries

Date: 2026-04-02

## Slice Boundary

Migrated in Phase 7D:
- Weak password policy normalization (minimum password length threshold semantics).

Not migrated in Phase 7D:
- LDAP/BloodHound runtime collection
- scheduler/daemon/orchestration behavior
- delegation, ACL abuse, DCSync, AdminSDHolder, and broad ad-lateral path reasoning

## Ownership Decisions

1. AD domain owns weak-policy semantics.
- Adapter:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_weak_password_policy/run.py`
- Ontology:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json`
- Policy:
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/weak_password_policy.yaml`

2. Projector remains domain-owned and runtime-free.
- Reused:
  - `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py`
- No runtime logic or service execution was introduced into projector modules.

3. Services continue owning runtime collection/orchestration.
- No code moved from:
  - `skg/sensors/bloodhound_sensor.py`
  - `skg-gravity/adapters/ldap_enum.py`
- No network transport, scheduler, subprocess, or daemon semantics were added to domain modules.

## Remaining Boundary Risks

| Area | Risk | Status |
|---|---|---|
| Legacy runtime dependency | Non-migrated AD flows still transitively depend on legacy ad-lateral runtime adapters. | deferred |
| Legacy ID crosswalk | Legacy `AD-24` concept now canonicalized as `AD-WP-*` without dedicated crosswalk artifact. | deferred |
| Scope narrowness | Current weak-policy slice evaluates minimum length only; richer policy semantics remain outside canonical slice. | deferred |

## Boundary Check Outcome

- Core/protocol/registry boundaries remained intact.
- AD domain stayed semantic-only and slice-scoped.
- No hardcoded layout assumptions or `sys.path` hacks were introduced in new canonical code.
