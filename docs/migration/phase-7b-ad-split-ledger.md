# Phase 7B AD Corrective Split Ledger

Date: 2026-04-02

## Scope

- `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`
- `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py`
- `skg/sensors/bloodhound_sensor.py`
- `skg-gravity/adapters/ldap_enum.py`

## Split Ledger

| Legacy path | Identified slice | Ownership classification | Recommended action | Rationale | Risk if migrated prematurely |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | Schema normalization (`detect_version`, `normalize_node`, `load_bh_file`, `load_bh_dir`) | service/runtime (source-parser boundary) | split later | Source-shape parsing is adapter/runtime-facing collection logic, not canonical AD semantic authority. | Domain pack would absorb source-format coupling and lock semantic layer to BloodHound file formats. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | Kerberoast/AS-REP checks (`check_kerberoastable`, `check_asrep`, `is_da_member`) | deferred/redteam-lateral | defer | Current checks are tied to ad-lateral attack-path assumptions and legacy wicket IDs (`AD-01..AD-05`, `AD-23`). | Pulls redteam-lateral path semantics into AD prematurely; creates dual ontology authority. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | Delegation checks (`check_delegation`) | deferred/redteam-lateral | defer | Constrained/unconstrained delegation semantics are broader than current AD domain slice and cross into attack-chain behavior. | AD pack would absorb exploitation-oriented assumptions and transport-derived freshness heuristics. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | ACL/DCSync/AdminSDHolder checks (`check_acls`, `check_dcsync_accounts_enabled`, `check_adminsdholder`) | shared/cross-domain + deferred/redteam-lateral | defer | ACL graph semantics overlap AD security semantics and redteam pathing; requires dedicated slice-by-slice decomposition first. | High chance of contaminating AD domain with privilege-escalation chain logic and incomplete evidence rules. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | Password description / weak policy / LAPS / stale account checks (`check_passwords_in_descriptions`, `check_weak_password_policy`, `check_laps`, `check_stale_privileged`) | AD domain (semantic candidates) + shared/cross-domain | extract now (helpers only), split later (full slice migration) | These contain legitimate AD semantic primitives but are bundled with legacy envelope emission and ad-lateral IDs. | Copying whole checks would carry legacy envelope writer + wicket ID coupling and duplicate authority. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | LDAP dump loading and attribute coercion (`load_json`, `get_attr`) | service/runtime (source-parser boundary) | split later | Parser shape normalization belongs at source adapter/service boundary, not in canonical AD semantic core. | Canonical domain would become coupled to ldapdomaindump export format and key casing quirks. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | Password description keyword semantics (`description_has_password`) | AD domain | extract now | This is source-agnostic AD semantic text logic duplicated in BloodHound and LDAP adapters. | Leaving duplicated semantics increases drift and inconsistent future slice behavior. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | Event emission and wicket mapping in `main()` (`AD-01/02/04/17/18/24/25`) | mixed AD domain + deferred/redteam-lateral + service/runtime | split later | One function conflates parser IO, semantic evaluation, and envelope emission. | Premature migration creates one more mixed canonical module and repeats Phase 3 drift. |
| `skg/sensors/bloodhound_sensor.py` | REST/Neo4j clients, auth, pagination, state, cache, adapter execution (`BloodHoundCEClient`, `Neo4jClient`, `collect_via_*`, `BloodHoundSensor.run`) | service/runtime | defer (service-owned) | This is runtime transport/orchestration and belongs in services/harness path, not AD domain. | Moving into AD would violate service/runtime boundary and make domain package network-execution aware. |
| `skg/sensors/bloodhound_sensor.py` | BH->legacy adapter normalization helpers (`_normalize_bh_ce_*`) | service/runtime + shared/cross-domain | split later | Normalization is currently shaped to legacy ad-lateral adapter contracts; should be redirected to canonical service wrappers for domain adapters. | Continued coupling to legacy schema keeps dual execution path alive. |
| `skg-gravity/adapters/ldap_enum.py` | LDAP bind/query orchestration and event writing in `run()` | service/runtime | defer (service-owned) | Pure runtime execution with transport, credentials, and output file orchestration. | AD domain contamination with runtime concerns and hardcoded fallback behavior. |
| `skg-gravity/adapters/ldap_enum.py` | Privileged group matching and machine account checks embedded in runtime branch | AD domain (semantic primitive) | extract now (helper only), split later | Semantic predicates are valid AD-domain logic but currently embedded in runtime adapter body. | Reusing runtime module as semantic source would preserve `sys.path` hacks and host-scoped assumptions. |

## Safe Preliminary Extraction Performed

| Legacy semantic origin | New canonical path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `bloodhound/parse.py` + `ldapdomaindump/parse.py` duplicated password keyword semantics | `packages/skg-domains/ad/src/skg_domain_ad/mappings/password_description_keywords.yaml` | AD domain mapping | extracted now | Centralized source-agnostic AD password-hint vocabulary for future slice migrations. | Keyword list may require enterprise tuning; still lexical-only heuristic. |
| `bloodhound/parse.py` + `ldapdomaindump/parse.py` duplicated text predicate (`description_has_password`) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/text_semantics.py::description_has_password_hint` | AD domain helper | extracted now | Removes duplicated semantic primitive from legacy parsers without migrating runtime code. | Heuristic may need false-positive suppression rules in later slices. |
| legacy machine-account checks (`name.endswith("$")`) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/text_semantics.py::is_machine_account_principal` | AD domain helper | extracted now | Normalized machine-account predicate with realm-safe handling (`WS01$@DOMAIN`). | Non-AD principal naming edge cases may need additional normalization. |
| existing AD canonical adapter internal function | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_privileged_membership/run.py` | AD domain adapter | rewritten (helper adoption) | AD canonical adapter now uses shared AD semantic helper rather than local duplicate. | None for current slice coverage. |

## No Runtime Extraction Performed

- No code from `skg/sensors/bloodhound_sensor.py` or `skg-gravity/adapters/ldap_enum.py` was moved into the AD domain pack.
- No transport, subprocess, network client, or orchestration logic was migrated.
