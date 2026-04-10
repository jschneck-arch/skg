# Phase 7T Delegation Boundaries

Date: 2026-04-03

## Boundary Outcome

Phase 7T further shrinks legacy delegation authority while preserving canonical ownership:

- AD domain: posture semantics only (`AD-06`, `AD-08`) unchanged.
- Protocol/services: AD-07 context unchanged as service-owned contract/handoff.
- Legacy collision outputs: AD-06 collision branches retired.
- AD-09: still deferred and non-canonical.

## Runtime Boundary Enforcement (Post-7T)

| Boundary | Enforcement path | Status |
|---|---|---|
| Legacy delegation branch explicit path-gating only | `skg/sensors/adapter_runner.py` `LEGACY_DELEGATION_ATTACK_PATH_IDS` | ENFORCED |
| AD-07 not treated as canonical domain semantics | AD-07 sidecar contract path + legacy AD-07 event dropping | ENFORCED |
| AD-06 collision legacy outputs must not appear | `ldap_enum.py` and `impacket_post.py` collision emissions removed | ENFORCED |
| Coverage advertisement must match runtime outputs | `gravity_field.py` removed AD-06 collision wavelengths | ENFORCED |

## Contained Non-Canonical Residue

Still retained as non-canonical:
- ad-lateral delegation catalog path/value coupling (`ad_unconstrained_delegation_v1`, `ad_constrained_delegation_s4u_v1`)
- legacy delegation branch implementation for explicit legacy path IDs only
- AD-22 LDAP legacy quarantine branch (`AD-22-LDAP-LEGACY`)

