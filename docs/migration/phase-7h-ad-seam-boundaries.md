# Phase 7H AD Seam Boundaries

Date: 2026-04-02

## Boundary Classification Summary

### LAPS Core Seam (priority 1)

- AD domain semantics:
  - workstation eligibility normalization (`enabled` and not DC)
  - LAPS signal normalization from either explicit `haslaps` or LDAP attribute presence keys
- service/runtime parser or orchestration behavior:
  - BloodHound/ldapdomaindump source loading and shape coercion
  - adapter CLI argument handling and NDJSON file emission
- redteam-lateral/path/value reasoning:
  - legacy path coupling of `AD-25` with `AD-22` in `ad_laps_absent_v1`
- decision:
  - LAPS core seam is clean enough for helper-level extraction now.
  - Full LAPS slice migration remains pending to avoid pulling parser/runtime or path-coupled requirements.

### AD-03 / AD-23 Separation Seam (priority 2)

- AD domain semantics:
  - AD-01/AD-02 baseline Kerberoast account exposure semantics (already canonicalized)
- service/runtime parser or orchestration behavior:
  - legacy `check_kerberoastable` still sits in runtime adapter with direct emit flow
- redteam-lateral/path/value reasoning:
  - AD-03 detection-absence heuristic (honeypot/alerting inference)
  - AD-23 DA-value coupling (SPN on DA account impact framing)
- decision:
  - seam is identifiable but not extraction-clean yet as a canonical AD helper beyond already-migrated baseline semantics.
  - AD-03 and AD-23 remain deferred until dedicated split into distinct semantic artifacts.

## Ownership Decisions Applied

1. Extracted only LAPS semantic helpers that are source-agnostic and package-local.
2. Did not migrate any runtime parser/orchestration logic.
3. Did not migrate any redteam/path/value semantics in this pass.
4. Preserved prior AD baseline slice boundaries (AD-01/02 and AD-04 already canonicalized separately).

## Blockers For Premature Migration

- `check_kerberoastable` still co-locates baseline, heuristic, and impact semantics in one branch.
- legacy ad-lateral catalog still binds LAPS and Kerberoast paths to non-baseline requirements.
- lateral projector path IDs and fallback behavior remain legacy-oriented and not canonical AD authority.
