# Phase 7N Delegation Boundaries

Date: 2026-04-03

## Per-Branch Delegation Classification (AD-06..AD-09)

| Branch | Legacy meaning | Required classification | Canonical ownership | Phase 7N decision |
|---|---|---|---|---|
| AD-06 | unconstrained delegation on non-DC hosts | AD semantic fact -> candidate for extraction | AD domain | Candidate is safe as posture-only semantic normalization. Helper extracted; full slice migration deferred. |
| AD-07 | unconstrained host reachability/activity via recency | context-dependent logic | service/runtime + deferred path reasoning | Deferred. Not domain-owned until runtime context contract is explicit and separate from posture facts. |
| AD-08 | constrained delegation with protocol transition enabled | AD semantic fact -> candidate for extraction | AD domain | Candidate is safe as posture-only semantic normalization. Helper extracted; full slice migration deferred. |
| AD-09 | constrained delegation target sensitivity/value | path/value reasoning | deferred redteam-lateral/path/value | Deferred. No canonical AD migration in this phase. |

## Ownership Guardrails Applied

### AD domain may express

- delegation configuration facts (raw AD object state)
- structural relationships (`account -> allowed_to_delegate SPN`)
- static posture states derived from those facts

### AD domain must not express

- attacker usefulness
- path chaining
- privilege escalation utility scoring
- target value or sensitivity ranking

### Services may express

- collection and transport behavior (`bloodhound_sensor` / runtime wrappers)
- orchestration and file/schema routing
- evidence delivery into canonical domain input contracts

### Services must not express

- delegation semantic interpretation as canonical truth

## Canonical Surface Introduced In Phase 7N

- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/delegation_semantics.py`
  - `normalize_delegation_principals(...)`
  - `extract_unconstrained_non_dc_hosts(...)`
  - `extract_protocol_transition_principals(...)`
  - `extract_delegation_spn_edges(...)`

This surface is strictly structural and intentionally excludes AD-07/AD-09 context reasoning.

## Protocol Contract Requirement

No canonical delegation runtime input shape was introduced in Phase 7N, so no new protocol contract was added yet.

Before any delegation slice migration (beyond helper-level semantics), add a protocol contract for delegation evaluation input and require service runtime wrappers to emit that shape explicitly.

## Legacy Authority Constraint

`skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` and `skg-ad-lateral-toolchain/projections/lateral/run.py` remain design evidence and compatibility residue for delegation work, not canonical AD domain authority.
