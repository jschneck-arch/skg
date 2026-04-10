# Phase 7H AD Deferred Residue

Date: 2026-04-02

## Deferred Residue After Seam Split Pass

| Legacy path | Deferred seam | Classification | Why deferred | Exact future step |
|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` (AD-03 branch) | no-detection heuristic (`honeypot`/alerting absence) | redteam-lateral/path/value reasoning | Not baseline AD inventory semantic; confidence model remains heuristic and exploitation-framed. | Create separate AD-03 artifact with explicit confidence policy or keep out of canonical AD if it remains purely adversary heuristic. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` (AD-23 branch) | DA-impact coupling (`is_da_member` + SPN) | redteam-lateral/path/value reasoning | Impact/value coupling is not equivalent to baseline Kerberoast exposure semantics. | Split AD-23 into separate impact slice only after explicit value-policy and privilege-correlation boundaries are defined. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `ad_laps_absent_v1` requiring `AD-25` + `AD-22` | mixed AD semantics + path-coupled residue | Path requirement still mixes LAPS posture with tiering heuristic. | Define canonical AD LAPS baseline path independent of tiering heuristic preconditions. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `ad_kerberoast_v1` / `ad_kerberoast_da_v1` coupling to `AD-03` / `AD-23` | redteam-lateral/path/value reasoning | Legacy catalog keeps mixed semantic authority and exploit-path framing. | Continue canonical AD catalog expansion slice-by-slice; keep legacy catalog as evidence only. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | broad ad-lateral projector fallback and path-centric projection | deferred broad projector semantics | Projector still keyed to legacy path IDs and fallback imports. | Revisit only after additional higher-coupling AD slices are canonicalized and path authority is redesigned. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | parser+semantic+emit monolithic `main()` | service/runtime parser or orchestration + mixed semantics | No ownership-safe module boundaries yet between parse/orchestration and per-slice semantics. | Split runtime parser wrapper from per-slice semantic mappers before any further canonical extraction from this file. |

## Newly Extracted In This Phase

- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/laps_semantics.py`
- `packages/skg-domains/ad/tests/test_ad_laps_semantics_helpers.py`

No full new AD semantic slice was migrated in Phase 7H.
