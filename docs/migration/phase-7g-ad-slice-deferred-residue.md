# Phase 7G AD Slice Deferred Residue

Date: 2026-04-02

## Deferred Residue After Kerberoast Baseline Slice Migration

| Legacy path | Deferred classification | Why deferred | Exact next step |
|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` (AD-03 and AD-23 portions) | deferred redteam-lateral/path reasoning | AD-03 and AD-23 branches encode detection/value/path coupling beyond baseline exposure semantics. | Migrate later as separate slices only after dedicated decomposition of AD-03 and AD-23 assumptions. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_asrep` (AD-05 portion) | deferred redteam-lateral/path reasoning | AD-05 couples AS-REP exposure to privilege/value path reasoning. | Keep AD-05 separate from AD-04 baseline slice and migrate only after focused split pass. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | deferred redteam-lateral/path reasoning | Delegation logic remains mixed with freshness/sensitivity path assumptions. | Split static delegation posture from path-priority heuristics before migration. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_acls` / `check_dcsync_accounts_enabled` / `check_adminsdholder` | deferred redteam-lateral/path reasoning | ACL-family semantics remain graph/path-coupled and monolithic. | Perform dedicated ACL-family corrective split pass before migration. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` monolithic `main` | service/runtime + mixed semantics | Parser/file loading/emission and multiple slice semantics are still fused in one flow. | Isolate parser/runtime module and route per-slice semantics through canonical AD adapters. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | deferred redteam-lateral/path reasoning | Broad ad-lateral projector remains tied to legacy catalog breadth and fallback behavior. | Defer until additional high-coupling slices are canonicalized and runtime convergence is planned. |

## Current Canonical AD Scope

- Phase 7A: privileged-membership / privilege-assignment mapping
- Phase 7C: credential-hint normalization
- Phase 7D: weak password policy normalization
- Phase 7F: AS-REP baseline exposure normalization (AD-04 core only)
- Phase 7G: Kerberoast baseline exposure normalization (AD-01 / AD-02 core only)

AD-03, AD-05, AD-23, delegation-family, ACL-family, and broad ad-lateral path reasoning remain deferred.
