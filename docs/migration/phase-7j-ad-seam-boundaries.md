# Phase 7J AD Seam Boundaries

Date: 2026-04-02

## Boundary Classification Summary

### AD-22 Seam (priority 1)

- AD domain semantic normalization:
  - privileged-session row normalization
  - computer tier baseline classification (tier0 vs non-tier0 vs unknown)
  - posture summary (`realized`/`blocked`/`unknown`) for non-tier0 privileged sessions
- service/runtime parser or orchestration behavior:
  - BloodHound/Neo4j collection and `sessions.json` write (`bloodhound_sensor.py`)
  - adapter runtime call graph (`adapter_runner.run_bloodhound`) that currently does not route sessions into AD-22 evaluation
  - runtime LDAP adapter behavior (`ldap_enum.py`) with conflicting AD-22 semantics
- deferred redteam-lateral/path/value reasoning:
  - ad-lateral catalog coupling of AD-22 into `ad_unconstrained_delegation_v1` and `ad_laps_absent_v1`
  - legacy path/projector ownership in `projections/lateral/run.py`

Decision:
- AD-22 has an extractable semantic core at helper level.
- Full AD-22 slice migration remains blocked by runtime evidence-routing seams and legacy catalog path coupling.

### AD-03 / AD-23 Reassessment (after AD-22)

- status: unchanged from prior split passes.
- AD-03 remains detection-absence heuristic, not clean baseline domain semantic.
- AD-23 remains DA-impact/value coupling branch.
- both remain deferred pending separate, explicit semantic decomposition.

## Ownership Decisions Applied

1. Extracted only helper-level AD-22 semantic primitives.
- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/tiering_semantics.py`

2. Did not migrate runtime/session transport or parser/emitter flow.
- no runtime code moved from `skg/sensors/*`, `skg-gravity/*`, or legacy toolchain adapters.

3. Did not migrate path-coupled AD-22 definitions from ad-lateral catalog/projector.

4. Did not migrate AD-03/AD-23 in this phase.

## Blockers For Premature AD-22 Migration

- `run_bloodhound` does not pass session evidence into a canonical AD-22 adapter path.
- legacy BloodHound adapter AD-22 branch is static `unknown` and not evidence-driven.
- legacy `ldap_enum.py` emits an incompatible AD-22 meaning and includes non-canonical runtime/path hacks.
- ad-lateral catalog ties AD-22 to cross-slice path/value conditions.
