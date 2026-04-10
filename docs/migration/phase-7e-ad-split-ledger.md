# Phase 7E AD Corrective Split Ledger

Date: 2026-04-02

## Scope

- `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`
- `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py`
- `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (classification only)
- `skg-ad-lateral-toolchain/projections/lateral/run.py` (classification only)

## Split Ledger By Seam

| Legacy path | Identified slice/seam | Ownership classification | Recommended action | Rationale | Migration risk if done too early |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `detect_version` / `normalize_node` / `load_bh_file` / `load_bh_dir` | service/runtime collection or orchestration | split later | Source-shape normalization and file discovery are runtime/parser seams, not canonical AD semantic authority. | Domain package becomes format-coupled to BloodHound export layouts. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `emit` and NDJSON write behavior | service/runtime collection or orchestration | split later | Legacy envelope emission and file append IO are execution concerns. | Re-introduces runtime leakage and duplicate event contract ownership in domain adapters. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | account-state and encryption predicates used by `check_kerberoastable` / `check_asrep` | shared/cross-domain semantic helper | extract now | UAC/pre-auth/encryption flag interpretation is domain-owned semantic normalization reused across sources. | Leaving duplicated predicates causes semantic drift between adapters and future slices. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_asrep` (AD-04 + AD-05 combined) | mixed AD domain semantic normalization + deferred redteam-lateral/path reasoning | split later | AD-04 baseline roastability is domain semantic; AD-05 privilege/value coupling is path-oriented. | Migrating combined function would pull path/value assumptions into AD canonical slice. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_kerberoastable` (AD-01/02/03/23 combined) | mixed AD domain semantic normalization + deferred redteam-lateral/path reasoning | split later | SPN/encryption semantics are reusable; AD-03 (detection absence) and AD-23 (DA impact variant) are path/value-coupled. | Canonical AD could inherit brittle static heuristics and DA impact assumptions. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_delegation` | deferred redteam-lateral/path reasoning | defer | Logic bundles exposure with reachability/freshness and sensitive target exploit assumptions. | Premature migration would mix runtime freshness and attack-chain reasoning into domain pack. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_acls` / `check_dcsync_accounts_enabled` / `check_adminsdholder` | deferred redteam-lateral/path reasoning | defer | ACL family and DCSync/AdminSDHolder semantics are graph/path-coupled and currently monolithic. | High contamination risk and likely ontology churn in canonical AD. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `check_stale_privileged` (AD-21/22) | mixed AD domain semantic normalization + deferred redteam-lateral/path reasoning | defer | Stale account state is semantic; tiering absence and session assumptions are path/runtime-coupled. | Pulls observational gaps and heuristic assumptions into canonical semantics. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | legacy AD-17/18 and AD-24 branches still present | AD domain semantic normalization (already canonicalized elsewhere) | split later | These are now superseded by canonical AD slices (`AD-CH-*`, `AD-WP-*`). | Keeping live duplicates as semantic authorities can cause contract divergence. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | `load_json` / `get_attr` source coercion | service/runtime collection or orchestration | split later | Source parser and key-case coercion belong in service wrappers. | Domain layer becomes coupled to ldapdomaindump-specific schema quirks. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | monolithic `main` (parse + evaluate + emit) | service/runtime collection or orchestration + mixed semantics | split later | All slice logic is fused into one execution function with no ownership seams. | Any direct migration would drag runtime and unrelated semantics across boundaries. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | AD-04 predicate branch (UAC pre-auth) | AD domain semantic normalization | split later (candidate next slice) | Clear semantic core once separated from runtime parser and AD-05 coupling. | Migrating the combined branch with emissions keeps legacy path IDs/contracts entangled. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | AD-17/18 and AD-24 branches | AD domain semantic normalization (already canonicalized elsewhere) | defer for removal in runtime-convergence phase | Canonical replacements already exist in AD pack; legacy branches should become compatibility-only. | Dual-authority risk while both legacy and canonical semantics stay active. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | attack-path-level coupling (`ad_*_v1`) | deferred redteam-lateral/path reasoning | defer | Catalog still encodes exploit-path objectives and multi-slice coupling. | Copying paths directly would re-import redteam-lateral authority into AD domain. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | lateral projector and sheaf fallback pathing | deferred redteam-lateral/path reasoning | defer | Projector is tied to broad ad-lateral catalog and legacy fallback import behavior. | Canonical AD projection contracts would be polluted with lateral runtime fallback semantics. |

## Safe Extraction Performed

| Legacy semantic origin | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `bloodhound/parse.py` UAC + pre-auth + encryption checks, `ldapdomaindump/parse.py` UAC + encryption checks | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/account_semantics.py` | shared/cross-domain semantic helper | extracted now | Consolidated domain-owned account-state and Kerberos flag semantics into reusable canonical helper module. | Future sources may expose additional flag encodings needing extension. |
| existing canonical AD credential-hint adapter internal enabled-state logic | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_credential_hints/run.py` | AD domain adapter | rewritten (helper adoption) | Active caller now consumes canonical helper, reducing duplicate bit/flag logic. | None for covered paths. |
| existing canonical weak-policy adapter integer coercion | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_weak_password_policy/run.py` | AD domain adapter | rewritten (helper adoption) | Reused canonical scalar coercion helper from shared account semantics. | Minimal; helper semantics must remain backward compatible. |
| N/A | `packages/skg-domains/ad/tests/test_ad_account_semantics_helpers.py` | tests | added | Added direct tests for extracted helper behavior before higher-coupling slice migration. | Coverage does not yet include all enterprise-specific flag variants. |
