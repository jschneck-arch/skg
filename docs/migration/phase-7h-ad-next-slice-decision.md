# Phase 7H AD Next Slice Decision

Date: 2026-04-02

## Decision

Recommended next AD migration slice: **LAPS baseline coverage normalization (AD-25 core semantics only)**.

## Why

1. LAPS core seam is now helper-extracted and ownership-clean:
   - workstation eligibility (`enabled` + non-DC)
   - LAPS signal normalization (`haslaps` or `ms-Mcs-AdmPwd` / `msLAPS-Password`)
2. Runtime/parser/orchestration behavior for source loading remains clearly separable in services.
3. AD-03/AD-23 seam is still more coupled to redteam-path/value semantics than LAPS core.

## Required Scope Guardrails For Next Slice

- Migrate only baseline LAPS coverage semantics.
- Do not import `AD-22` tiering coupling into LAPS baseline slice.
- Keep runtime collection/orchestration in services.
- Keep projector/path coupling broad semantics deferred.

## Ranked Immediate Options

| Rank | Candidate | Cleanliness | Notes |
|---|---|---|---|
| 1 | LAPS baseline coverage normalization (AD-25 core only) | MEDIUM-HIGH | Helper seam now extracted and test-locked; path coupling is avoidable with narrow slice scope. |
| 2 | AD-03 heuristic separation from Kerberoast baseline | LOW-MEDIUM | Detection-absence heuristic is low-confidence and not purely domain semantic. |
| 3 | AD-23 DA-impact separation from Kerberoast baseline | LOW-MEDIUM | Value/impact coupling still tied to path framing and privileged-membership context. |

## Not Recommended Next

- Do not migrate AD-03 and AD-23 as a combined slice.
- Do not migrate AD-03 as canonical baseline AD semantics without explicit confidence and ownership redesign.
