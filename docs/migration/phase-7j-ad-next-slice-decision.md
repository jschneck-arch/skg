# Phase 7J AD Next Slice Decision

Date: 2026-04-02

## Decision

Recommended next AD slice candidate: **AD-22 baseline privileged-session tiering posture**, but only after one focused runtime seam split pass.

This phase does **not** migrate AD-22 as a full slice.

## Why

1. AD-22 semantic core is now helper-isolated:
   - session normalization
   - computer tier baseline classification
   - non-tier0 privileged-session posture summary
2. AD-22 currently has unresolved runtime evidence routing:
   - sessions collected by sensor are not consumed by legacy adapter runtime path
3. Legacy AD-22 has conflicting semantics in `ldap_enum.py` and path-coupled authority in ad-lateral catalog.

## Ranked Next-Slice Options

| Rank | Candidate | Cleanliness | Required pre-migration step |
|---|---|---|---|
| 1 | AD-22 baseline privileged-session tiering posture (core only) | MEDIUM | Runtime seam split: route session evidence into canonical AD adapter path; retire conflicting AD-22 legacy branch semantics. |
| 2 | AD-03 heuristic separation | LOW | Define explicit confidence/ownership contract for detection-absence heuristic before migration. |
| 3 | AD-23 DA-impact separation | LOW | Separate value-impact semantics from baseline Kerberoast semantics with explicit policy artifact. |

## Explicit Non-Decision

- Do not migrate AD-03 or AD-23 next by default.
- Do not migrate AD-22 from legacy branches without runtime seam correction.

## Immediate Follow-On Recommendation

Execute one focused corrective split pass to:
1. connect session evidence flow from service runtime to canonical adapter inputs,
2. isolate conflicting AD-22 legacy semantics,
3. keep catalog/path coupling out of the AD baseline slice.
