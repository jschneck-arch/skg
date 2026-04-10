# Phase 7P AD Slice Boundaries

Date: 2026-04-03

## Slice Decision

Migrated canonical AD delegation posture-core only:
- AD-06 unconstrained delegation non-DC posture signal
- AD-08 constrained delegation protocol-transition posture signal

## Ownership Boundaries

### Protocol-owned

- Delegation input contract and validation:
  - schema: `skg.ad.delegation_input.v1`
  - file: `ad_delegation_input.json`
  - contract module: `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_input.py`

### Service-owned

- Collection and routing of delegation evidence sidecar:
  - `packages/skg-services/src/skg_services/gravity/ad_runtime.py`
  - `skg/sensors/adapter_runner.py`
- Canonical invocation wrapper from sidecar to AD delegation adapter:
  - `map_ad0608_sidecar_to_events(...)`
- Runtime path guardrail for canonical delegation path:
  - drops legacy AD-06..AD-09 delegation events when `attack_path_id=ad_delegation_posture_baseline_v1`

### AD domain-owned

- Delegation posture-core semantic mapping and event emission:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py`
- Explicit policy:
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/delegation_posture_policy.yaml`
- Canonical ontology/path entries:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/wickets.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/attack_paths.yaml`
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/catalogs/attack_preconditions_catalog.ad.v1.json`

## Explicitly Deferred Boundaries

Still deferred and not migrated in Phase 7P:
- AD-07 freshness/reachability context semantics
- AD-09 sensitive-target semantics
- attacker usefulness and escalation/path-value reasoning
- broad ad-lateral projector semantics

## Legacy Quarantine Boundary

Conflicting legacy AD-06 meanings remain quarantined and non-canonical:
- `skg-gravity/adapters/ldap_enum.py` emits `AD-06-LDAP-LEGACY`
- `skg-gravity/adapters/impacket_post.py` emits `AD-06-IMPACKET-LEGACY`

Canonical AD-06 meaning for delegation posture is now domain-owned through the AD domain slice and protocol-governed service handoff.
