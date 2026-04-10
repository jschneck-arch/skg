# Phase 7O Delegation Boundaries

Date: 2026-04-03

## Boundary Decisions

### Protocol ownership

Protocol now owns canonical delegation input shape and validation:

- schema: `skg.ad.delegation_input.v1`
- filename: `ad_delegation_input.json`
- allowed canonical wickets in this handoff: `AD-06`, `AD-08` only

Module:
- `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_input.py`

### Service ownership

Services own runtime routing and sidecar production:

- build delegation posture-core sidecar from BloodHound inventory (`users` + `computers`)
- validate against protocol contract before write
- keep runtime collection/orchestration in service layer

Modules:
- `packages/skg-services/src/skg_services/gravity/ad_runtime.py`
- `skg/sensors/adapter_runner.py`

### AD domain ownership

AD domain remains limited to structural semantics only:

- normalize delegation principals
- extract unconstrained non-DC posture candidates
- extract protocol-transition delegation posture candidates
- extract raw delegation SPN edges (no sensitivity/value interpretation)

Module:
- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/delegation_semantics.py`

### Explicitly deferred boundaries

Deferred from canonical delegation ownership in Phase 7O:

- AD-07 (reachability/recency context)
- AD-09 (sensitive-target/value semantics)
- attacker usefulness and privilege-escalation interpretation
- path chaining and ad-lateral projector authority

Deferred legacy authority remains in:
- `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json`
- `skg-ad-lateral-toolchain/projections/lateral/run.py`

## Quarantine boundary

Conflicting legacy AD-06 semantics are quarantined and no longer emitted as canonical AD-06:

- `skg-gravity/adapters/ldap_enum.py` -> `AD-06-LDAP-LEGACY`
- `skg-gravity/adapters/impacket_post.py` -> `AD-06-IMPACKET-LEGACY`

This keeps delegation posture meaning authoritative in canonical protocol/service/domain seams.
