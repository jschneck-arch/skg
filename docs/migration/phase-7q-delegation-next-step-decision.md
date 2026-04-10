# Phase 7Q Delegation Next Step Decision

Date: 2026-04-03

## Executive Decision

AD-07 and AD-09 are not both valid AD-domain follow-on slices.

- AD-07 may be canonically expanded only as a **service-context slice** (not AD-domain semantic authority).
- AD-09 should remain **deferred outside AD domain** because it is sensitive-target/value/attacker-usefulness reasoning.

## AD-07 Decision

| Question | Decision | Why |
|---|---|---|
| Can AD-07 become a future canonical slice? | Yes, but service-owned only | AD-07 depends on runtime freshness evidence quality (`lastlogontimestamp`, recency window, unknown handling), which is context policy not static AD posture semantics. |
| Can AD-07 be migrated into AD domain now? | No | Would force runtime assumptions into domain semantics and violate ownership rules. |
| What is required before migration of AD-07 context logic? | protocol/service context contract + explicit policy versioning | Prevents hidden threshold drift and keeps interpretation in service layer. |

## AD-09 Decision

| Question | Decision | Why |
|---|---|---|
| Can AD-09 become a canonical AD-domain slice? | No (under current architecture rules) | AD-09 logic is target sensitivity/value/path reasoning (`SENSITIVE_DELEGATION_SVCS`) and attacker-usefulness framing. |
| Should AD-09 be migrated now? | No | Violates non-negotiable boundary: path/value/sensitivity reasoning must not be forced into AD domain posture semantics. |
| Recommended ownership | deferred redteam-lateral/policy layer (outside AD domain) | Keeps canonical AD pack posture-only. |

## Ranked Next Options

| Rank | Option | Readiness | Notes |
|---|---|---|---|
| 1 | Migrate one narrow next slice: AD-07 service-context contract/handoff (protocol + services only) | MEDIUM | Reuse `skg_services.gravity.delegation_context.classify_ad07_unconstrained_activity` as implementation seed; keep AD domain unchanged. |
| 2 | Pause AD delegation expansion and move to another domain | MEDIUM | Safe if delegation context contract is not a near-term priority. |
| 3 | Attempt AD-09 migration into AD domain | LOW | Not ownership-safe; would reintroduce value/path contamination. |
| 4 | Migrate AD-07 and AD-09 together as AD domain slice | LOW | Explicitly unsafe; recreates mixed authority. |

## Exact Blockers

1. `skg/sensors/adapter_runner.py` still executes legacy `check_delegation` monolith for non-canonical path ids.
2. `skg-gravity/gravity_field.py` still advertises AD-07/AD-09 as broad BloodHound wavelengths, implying broader canonical support than exists.
3. `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` still couples AD-06/08 posture with AD-07/09 context/value logic.
4. Quarantined AD-06 collisions (`AD-06-LDAP-LEGACY`, `AD-06-IMPACKET-LEGACY`) still exist and require controlled retirement.

## Recommendation

Proceed with **one narrow next slice**: protocol/service AD-07 context contract + handoff hardening, while keeping AD-09 deferred outside AD domain and executing retirement Wave 1 prerequisites in parallel.
