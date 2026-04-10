# Phase 7L AD Slice Deferred Residue

Date: 2026-04-02

## Deferred Residue After AD-22 Core Slice Migration

| Legacy path | Deferred classification | Why deferred | Exact next step |
|---|---|---|---|
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_unconstrained_delegation_v1` (`AD-22` coupling) | deferred redteam-lateral/path/value reasoning | AD-22 appears as attack-path prerequisite with delegation path coupling, outside AD-22 core baseline scope. | Keep canonical AD-22 baseline path independent; split coupled path reasoning in a separate higher-coupling pass. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_laps_absent_v1` (`AD-25` + `AD-22`) | deferred redteam-lateral/path/value reasoning | LAPS + tiering path coupling is out of this slice boundary. | Preserve separate canonical AD-25 and AD-22 baseline paths; evaluate coupling only after dedicated path/value decomposition. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | deferred broad projector semantics | Legacy projector remains path-centric and includes fallback substrate behavior. | Revisit only after additional AD high-coupling seams are canonically split. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` monolithic runtime checks beyond AD-22 core | service/runtime parser or orchestration + mixed semantics | Remaining checks are mixed with runtime parsing/emission orchestration and non-AD-22 semantics. | Continue focused slice-by-slice extraction; do not broad-migrate monolithic parser. |
| `skg-gravity/adapters/ldap_enum.py` (`AD-22-LDAP-LEGACY`) | legacy compatibility shim | Legacy account-enumeration signal is intentionally quarantined and not canonical AD-22 authority. | Retire once no caller requires this compatibility signal. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` AD-03/AD-23 portions | deferred redteam-lateral/path/value reasoning | AD-03 heuristic and AD-23 value impact remain coupled outside AD-22 core boundary. | Keep deferred until dedicated AD-03/AD-23 corrective migration pass. |

## Scope Confirmation

Phase 7L migrated only AD-22 core privileged-session tiering posture semantics.
No delegation, ACL, DCSync, AdminSDHolder, AD-03, AD-23, or broad path/value coupling was migrated.
