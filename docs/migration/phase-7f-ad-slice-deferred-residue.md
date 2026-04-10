# Phase 7F AD Slice Deferred Residue

Date: 2026-04-02

## Deferred Residue After AS-REP Baseline Slice Migration

| Legacy path | Deferred classification | Why deferred | Exact next step |
|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_asrep` (AD-05 portion) | deferred redteam-lateral/path reasoning | AD-05 ties AS-REP accounts to privilege/value reasoning and path-level attack prioritization. | Migrate later as separate slice only after dedicated AD-05 decomposition. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` | mixed AD semantic + deferred path reasoning | AD-01/02 core is mixed with AD-03 detection-absence and AD-23 DA-impact coupling. | Split AD-01/02 core from AD-03/23 branches before migration. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | deferred redteam-lateral/path reasoning | Delegation logic remains coupled to sensitivity/freshness path assumptions. | Split static delegation posture from path-priority heuristics. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_acls` / `check_dcsync_accounts_enabled` / `check_adminsdholder` | deferred redteam-lateral/path reasoning | Graph/path-coupled ACL-family semantics remain monolithic and high-risk. | Perform dedicated ACL-family corrective split pass before migration. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` monolithic `main` | service/runtime + mixed semantics | Parser/file loading/emission and slice semantics remain fused. | Isolate parser/runtime module and route to canonical domain adapters by slice. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | deferred redteam-lateral/path reasoning | Broad ad-lateral projector still coupled to legacy catalog breadth and fallback behavior. | Defer until more high-coupling slices are canonicalized and runtime convergence is planned. |

## Current Canonical AD Scope

- Phase 7A: privileged-membership / privilege-assignment mapping
- Phase 7C: credential-hint normalization
- Phase 7D: weak password policy normalization
- Phase 7F: AS-REP baseline exposure normalization (AD-04 core only)

All AD-05 coupling and broader lateral/path semantics remain deferred.
