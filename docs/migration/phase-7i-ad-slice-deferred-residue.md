# Phase 7I AD Slice Deferred Residue

Date: 2026-04-02

## Deferred Residue After LAPS Baseline Slice Migration

| Legacy path | Deferred classification | Why deferred | Exact next step |
|---|---|---|---|
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_laps_absent_v1` (`AD-25` + `AD-22`) | deferred redteam-lateral/path coupling | Path requires AD-22 tiering semantics not part of AD-25 baseline. | Keep canonical LAPS baseline path independent; migrate AD-22 only via dedicated slice if warranted. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` runtime load/emit and monolithic check orchestration | service/runtime parser or orchestration | Runtime CLI + emission flow is out of AD domain ownership. | Route runtime invocation through service wrappers that call canonical AD adapters only. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` monolithic `main()` | service/runtime parser or orchestration + mixed semantics | Parser loading, semantic mapping, and emission remain fused. | Split parser/runtime wrapper from per-slice canonical semantic adapters in a focused follow-on pass. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` broad path projector | deferred broad projector semantics | Projector is still legacy path-centric and not canonical AD path authority. | Revisit only after additional higher-coupling slices are decomposed and canonicalized. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` AD-03/AD-23 portions | deferred redteam-lateral/path/value reasoning | Detection/value impact coupling remains outside baseline semantic ownership. | Keep deferred until dedicated AD-03 and AD-23 corrective split/migration decisions. |

## Scope Confirmation

Phase 7I migrated only AD-25 baseline semantics into canonical AD domain artifacts.
No AD-22, AD-03, AD-23, delegation, ACL, DCSync, or AdminSDHolder semantics were migrated.
