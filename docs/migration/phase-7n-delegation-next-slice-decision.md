# Phase 7N Delegation Next Slice Decision

Date: 2026-04-03

## Decision

Recommended next move: **do not migrate full delegation slice yet**. Proceed with a narrow delegation posture-core migration only after a protocol-governed service input contract is added.

## Safe Delegation Semantic Surface (Canonical Candidate)

The minimum canonical delegation semantic surface is limited to:

1. AD-06 posture core:
- enabled non-DC principal has unconstrained delegation enabled.

2. AD-08 posture core:
- enabled principal has non-empty `allowed_to_delegate` and `trusted_to_auth_for_delegation=true`.

3. Structural relationship inventory:
- account to SPN edges (`service`, `target`) without sensitivity/value interpretation.

These are implemented as helper-level semantics in:
- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/delegation_semantics.py`

## Deferred Delegation Components

1. AD-07 reachability/freshness branch.
- Depends on recency windows, environment policy, and runtime context quality.

2. AD-09 sensitive-target branch.
- Depends on target value/sensitivity interpretation and attack-usefulness framing.

3. Legacy path coupling.
- `ad_unconstrained_delegation_v1` and `ad_constrained_delegation_s4u_v1` in the ad-lateral catalog remain non-canonical path authority.

4. Symbol-collision residues.
- `AD-06` meaning collisions in `skg-gravity/adapters/ldap_enum.py` and `skg-gravity/adapters/impacket_post.py` remain quarantined/deferred.

## Ranked Next Options

| Rank | Option | Readiness | Notes |
|---|---|---|---|
| 1 | Add delegation runtime input contract in protocol + service wrapper handoff | MEDIUM | Required before any canonical delegation adapter/projector migration. |
| 2 | Migrate AD-06 + AD-08 posture-only slice into AD domain | MEDIUM | Safe only after option 1 defines canonical input shape and validation. |
| 3 | Attempt full AD-06..AD-09 migration now | LOW | Not safe; would pull AD-07/AD-09 context/path logic into AD domain. |
| 4 | Pause AD delegation work and move to another domain | MEDIUM | Safe fallback if delegation seam is deprioritized. |

## Blockers For Full Delegation Slice Migration

- AD-07 has no canonical runtime context contract.
- AD-09 has no clean separation from target-value/path reasoning.
- Legacy path catalog still binds delegation wickets to coupled lateral semantics.
- Wicket ID collision (`AD-06`) still exists in deferred legacy gravity adapters.
