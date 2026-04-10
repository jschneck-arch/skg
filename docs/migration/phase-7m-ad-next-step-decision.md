# Phase 7M AD Next Step Decision

Date: 2026-04-03

## Decision

Recommended next move: **perform one more corrective split pass** before migrating another coupled AD slice.

## Why

1. Remaining seams are still high-coupling:
- AD-03/AD-23 remain mixed heuristic/value-impact semantics.
- delegation family mixes baseline posture with path-context assumptions.
- ACL/DCSync/AdminSDHolder family remains entangled with high-value/path authority.

2. Governance is now tightened for AD-22 sidecar flow:
- protocol contract exists and is enforced at runtime/domain boundaries.
- this reduced one class of boundary drift, but does not resolve higher-coupling semantic seams.

3. Premature migration risk remains high:
- moving coupled branches now would likely reintroduce redteam-lateral/path-value authority into canonical AD slices.

## Ranked Immediate Options

| Rank | Option | Readiness | Notes |
|---|---|---|---|
| 1 | Corrective split pass: delegation family (AD-06..AD-09) | MEDIUM | Most plausible next family if posture-only facts are split from freshness/sensitive-target coupling first. |
| 2 | Corrective split pass: ACL/DCSync/AdminSDHolder family (AD-10..AD-16, AD-19/20) | LOW-MEDIUM | Highest coupling and strongest path/value contamination risk; needs explicit decomposition map first. |
| 3 | Migrate next coupled AD slice immediately | LOW | Not recommended; seam cleanliness is insufficient. |
| 4 | Pause AD and move to another domain | MEDIUM | Safe alternative if AD coupling remediation is deprioritized. |

## Explicit Blockers For Immediate Coupled Slice Migration

- No clean ownership split between delegation posture facts and path-priority context branches.
- No clean ownership split between ACL-edge normalization and high-value/path impact framing.
- AD-03 confidence semantics and AD-23 DA-impact semantics still lack explicit canonical policy contracts.

## Execution Recommendation

Run one focused split pass next with strict scope:
1. delegation family only (AD-06..AD-09),
2. isolate posture-only semantics into candidate AD domain helpers,
3. defer freshness/sensitive-target/path-value reasoning,
4. produce ranked migration-ready candidate slice after that pass.
