# Phase 7E AD Next Slice Options

Date: 2026-04-02

## Ranking Basis

Ranking was computed after seam classification using:
1. ownership cleanliness (semantic-only extractability)
2. parser/runtime coupling level
3. redteam/path-coupling risk

## Ranked Higher-Coupling Candidate Slices

| Rank | Candidate slice | Primary legacy seams | Cleanliness | Why this rank | Required pre-migration split |
|---|---|---|---|---|---|
| 1 | AS-REP baseline exposure normalization (AD-04 core only) | `bloodhound/parse.py::check_asrep`, `ldapdomaindump/parse.py` UAC/pre-auth branch | MEDIUM-HIGH | UAC/pre-auth semantics are now helper-extracted and source-agnostic; remaining work is separating AD-04 from AD-05 path/value coupling. | Split AD-04 account-exposure semantics from AD-05 privilege/value semantics and map to canonical AD wickets. |
| 2 | Kerberoast account exposure normalization (AD-01/AD-02 core only) | `bloodhound/parse.py::check_kerberoastable`, `ldapdomaindump/parse.py` SPN/encryption branch | MEDIUM | Shared account/encryption semantics now extracted; still coupled to AD-03/AD-23 path/value heuristics in legacy function. | Split SPN/encryption exposure semantics from detection-absence and DA-impact branches. |
| 3 | LAPS deployment coverage normalization (AD-25-like core semantics) | `bloodhound/parse.py::check_laps`, `ldapdomaindump/parse.py` computer policy branch | MEDIUM | Slice is domain-relevant but parser-source variance and host/runtime coupling are still mixed in legacy branches. | Isolate workstation-class filtering and LAPS-attribute interpretation into canonical AD adapter without runtime collectors. |
| 4 | Delegation exposure normalization (AD-06..AD-09 family) | `bloodhound/parse.py::check_delegation` | LOW-MEDIUM | Semantics are meaningful but bundled with freshness/sensitivity assumptions and attack-path framing. | Split static delegation posture from reachability/freshness/path-priority logic. |
| 5 | ACL-family/DCSync/AdminSDHolder normalization (AD-10..AD-16, AD-19/20) | `bloodhound/parse.py::check_acls`, `check_dcsync_accounts_enabled`, `check_adminsdholder` | LOW | Highest graph/path-coupling and strongest redteam-lateral contamination risk. | Dedicated graph-semantics corrective split pass before any canonical migration. |

## Recommended Next Slice

Recommended next slice: **AS-REP baseline exposure normalization (AD-04 core only)**.

Reason:
- Best ownership cleanliness after helper extraction.
- Lower cross-domain contamination than delegation/ACL families.
- Can be defined as pure semantic normalization before privilege/path value coupling.

## Explicitly Not Next

- Do not migrate ACL/DCSync/AdminSDHolder next.
- These remain too path-coupled and require one more dedicated split pass first.
