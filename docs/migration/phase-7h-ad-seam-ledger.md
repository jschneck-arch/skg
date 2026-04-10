# Phase 7H AD Seam Split Ledger

Date: 2026-04-02

## Scope

- `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`
- `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py`
- `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (classification only)
- `skg-ad-lateral-toolchain/projections/lateral/run.py` (classification only)

## Seam Analysis Ledger

| Legacy path | Seam/slice identified | Ownership classification | Recommended action | Rationale | Risk if migrated prematurely |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_laps` workstation eligibility (`enabled` + `not isdc`) | AD domain semantics | extract now (helper only) | Workstation eligibility is a narrow AD normalization seam and not transport/runtime behavior. | If moved as full branch, legacy emission and attack-path IDs leak into canonical AD. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_laps` `haslaps` signal interpretation | AD domain semantics | extract now (helper only) | `haslaps` interpretation is domain semantic mapping independent from orchestration. | Full-function migration would preserve legacy event writer and adapter CLI coupling. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | AD-25 attribute presence seam (`ms-Mcs-AdmPwd`, `ms-mcs-admpwd`, `msLAPS-Password`) | AD domain semantics | extract now (helper only) | Attribute-key interpretation is source semantics and can be normalized in canonical helpers without runtime code. | Pulling `main()` branch whole would import parser/file loading/emission coupling into AD domain. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | JSON loading + key coercion + monolithic `main()` execution | service/runtime parser or orchestration | split later | Parser orchestration remains runtime-owned and should be wrapped by services. | Canonical domain becomes tied to ldapdomaindump file shape and IO execution model. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_kerberoastable` AD-01/AD-02 baseline with AD-03 and AD-23 in one function | mixed: AD domain semantics + redteam-lateral/path/value reasoning | split later | AD-03 detection-absence and AD-23 DA-impact remain coupled to baseline branch in one function. | Migrating combined function reintroduces path/value coupling into canonical AD. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | AD-03 heuristic branch (honeypot/detection absence) | redteam-lateral/path/value reasoning | defer | Heuristic is adversary/detection narrative, not baseline AD inventory semantics. | Canonical AD would encode low-confidence absence logic as domain truth. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | AD-23 DA-SPN impact branch (`is_da_member` coupling) | redteam-lateral/path/value reasoning | split later | This branch is impact/value coupling, not baseline Kerberos exposure semantics. | Premature migration collapses baseline and impact semantics into one AD slice again. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `ad_laps_absent_v1` requiring `AD-25` + `AD-22` | mixed AD semantics + redteam-lateral path coupling | defer | Catalog path couples LAPS posture with tiering heuristic (`AD-22`), which is not LAPS core semantics. | Canonical AD LAPS slice would inherit unrelated path prerequisites. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | `ad_kerberoast_v1` and `ad_kerberoast_da_v1` coupling (`AD-03`, `AD-23`) | redteam-lateral/path/value reasoning | defer | Path definitions still bundle baseline exposure with detection and DA-impact semantics. | Canonical AD Kerberoast model would lose slice isolation and reintroduce dual authority. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | lateral projection fallback and sheaf classification over legacy path IDs | deferred broad projector semantics | defer | Broad projector remains path-centric and legacy-catalog keyed. | AD domain projector ownership would be polluted by ad-lateral path/runtime assumptions. |

## Safe Helper Extraction Performed

| Legacy semantic origin | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `bloodhound/parse.py::check_laps` (`enabled`, `isdc`, `haslaps`) + `ldapdomaindump/parse.py` AD-25 attribute seam (`ms-Mcs-AdmPwd`, `msLAPS-Password`) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/laps_semantics.py` | helper | extracted now | Consolidates LAPS core signal interpretation into a canonical AD helper without runtime/orchestration migration. | Attribute-present semantics still follow legacy non-`None` convention and may need hardening for sparse exporter variants. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/__init__.py` | helper export | rewritten | Exposes LAPS helper APIs for future AD slice adapters. | None for current helper-only usage. |
| `N/A` | `packages/skg-domains/ad/tests/test_ad_laps_semantics_helpers.py` | tests | added | Locks seam behavior for explicit `haslaps`, workstation eligibility, and LDAP attribute-driven signal normalization. | Does not yet validate full adapter/projector flow because no new slice was migrated in this phase. |
