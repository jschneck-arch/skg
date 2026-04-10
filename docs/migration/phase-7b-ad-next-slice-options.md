# Phase 7B AD Next-Slice Options

Date: 2026-04-02

## Ranking Method

Ranking is based on:
1. semantic cleanliness (lowest runtime coupling)
2. lowest cross-domain contamination risk
3. smallest decomposition effort from current mixed files

## Ranked Candidate Slices

| Rank | Candidate slice | Primary legacy sources | Cleanliness | Why this rank | Required pre-migration split |
|---|---|---|---|---|---|
| 1 | Password description / credential-hint normalization (`AD-17`, `AD-18`-like semantics) | `bloodhound/parse.py::check_passwords_in_descriptions`, `ldapdomaindump/parse.py::description_has_password/main` | HIGH | Core semantic primitive is now extracted; remaining work is separating source-parser input from semantic mapper and canonical wicket IDs. | Isolate source readers from semantic evaluator and define canonical AD wicket mapping independent of ad-lateral IDs. |
| 2 | Weak password policy normalization (`AD-24`-like semantics) | `ldapdomaindump/parse.py` policy branch, `bloodhound/parse.py::check_weak_password_policy` | MEDIUM-HIGH | Semantics are domain-owned and mostly configuration-plane; moderate parsing variance across sources. | Split policy extraction/parsing from semantic classification and move thresholds/policy into explicit AD policy artifact. |
| 3 | AS-REP inventory normalization (`AD-04`, `AD-05`-like semantics) | `bloodhound/parse.py::check_asrep`, `ldapdomaindump/parse.py` UAC branch | MEDIUM | Clear AD semantics but currently tied to legacy privilege heuristics and ad-lateral attack path assumptions. | Separate privilege-membership resolver from roastability mapper; align to canonical AD ontology. |
| 4 | Delegation exposure mapping (`AD-06`..`AD-09`-like semantics) | `bloodhound/parse.py::check_delegation`, `bloodhound_sensor.py` queries | LOW-MEDIUM | Strong AD semantics but high runtime freshness assumptions and attack-path coupling. | Split transport/query freshness logic into services; define domain-only delegation semantics with explicit evidence contracts. |
| 5 | ACL/DCSync/AdminSDHolder graph semantics (`AD-10`..`AD-16`, `AD-19`, `AD-20`) | `bloodhound/parse.py::check_acls/check_dcsync_accounts_enabled/check_adminsdholder` | LOW | Highest contamination risk and strongest redteam-lateral coupling; requires graph semantics redesign. | Dedicated corrective split pass for graph-edge semantics, privilege context, and path-specific exploit assumptions. |

## Recommended Next AD Slice

Recommended next slice: **Password description / credential-hint normalization**.

Reason:
- Shared non-runtime semantic primitive is already canonicalized in Phase 7B (`description_has_password_hint`).
- Lowest coupling to host/runtime orchestration.
- Minimal risk of dragging delegation/ACL/redteam semantics into AD package.

## Explicitly Not Recommended Next

- ACL/DCSync/AdminSDHolder should not be next.
- It remains too entangled with ad-lateral exploit-path assumptions and requires a separate graph-semantics split before safe migration.
