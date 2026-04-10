# Phase 7L AD Slice Boundaries

Date: 2026-04-02

## Slice Boundary

Migrated in Phase 7L:
- AD-22 core privileged-session tiering posture semantics only
- canonical attack path: `ad_privileged_session_tiering_baseline_v1`
- canonical sidecar input contract: `skg.ad.tiering_input.v1` (`ad22_tiering_input.json`)

Explicitly not migrated in Phase 7L:
- AD-03 / AD-23 semantics
- delegation, ACL abuse, DCSync, AdminSDHolder
- ad-lateral path/value/redteam coupling
- broad ad-lateral projector ownership
- BloodHound/LDAP runtime transport/orchestration redesign

## Ownership Decisions

1. Services own runtime collection and sidecar routing.
- `skg/sensors/bloodhound_sensor.py` (collection)
- `skg/sensors/adapter_runner.py` (runtime bridge + canonical AD-22 invocation gate)
- `packages/skg-services/src/skg_services/gravity/ad_runtime.py` (sidecar route + map wrapper)

2. AD domain owns AD-22 core semantic interpretation.
- Adapter:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/run.py`
- Ontology/catalog/path artifacts:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json`
- Policy:
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/tiering_posture_policy.yaml`

3. Legacy conflicting AD-22 semantics remain quarantined.
- `skg-gravity/adapters/ldap_enum.py` keeps `AD-22-LDAP-LEGACY` quarantine semantics.
- Legacy BloodHound `AD-22` static output stays filtered from active runtime output.

## Boundary Risks Remaining

| Area | Risk | Status |
|---|---|---|
| Sidecar schema evolution | Contract version is policy-checked but not centrally version-negotiated. | deferred |
| Runtime default path behavior | Default BloodHound path remains non-AD-22; operators must request `ad_privileged_session_tiering_baseline_v1` for canonical AD-22 runtime emission. | deferred |
| Legacy path coupling | ad-lateral catalog still couples AD-22 to other path/value semantics outside this slice. | deferred |

## Boundary Check Outcome

- AD-22 core interpretation moved into domain-owned canonical adapter/policy/ontology artifacts.
- Runtime remained service-owned and only bridges canonical sidecar contract into domain adapter invocation.
- No path/value/redteam coupling was pulled into the AD-22 core slice.
