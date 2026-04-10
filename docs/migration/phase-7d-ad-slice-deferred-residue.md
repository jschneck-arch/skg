# Phase 7D AD Slice Deferred Residue

Date: 2026-04-02

## Deferred Residue After Weak Password Policy Slice Migration

| Legacy path | Deferred classification | Why deferred | Exact next step |
|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` (`check_delegation`, `check_acls`, `check_dcsync_accounts_enabled`, `check_adminsdholder`, `check_stale_privileged`) | deferred/redteam-lateral + shared/cross-domain | Out of scope for weak-policy slice; contains broader ad-lateral and exploit-path semantics. | Continue slice-by-slice extraction with dedicated decomposition per semantic cluster. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` (`detect_version`, `normalize_node`, `load_bh_file`, `load_bh_dir`) | service/runtime | Source parsing and file-shape normalization belong to service runtime wrappers. | Build service-owned source wrappers that invoke canonical AD adapters. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` (`main` orchestration and non-AD-24 branches) | mixed runtime + deferred/redteam-lateral | Module still bundles parser IO, envelope emission, and multi-slice logic. | Split parser/runtime from semantic mapping; migrate remaining slices independently. |
| `skg/sensors/bloodhound_sensor.py` | service/runtime | Owns collection/auth/state/scheduling and adapter invocation runtime behavior. | Later runtime-convergence pass to route canonical AD adapters through services. |
| `skg-gravity/adapters/ldap_enum.py` | service/runtime + mixed semantics | Runtime LDAP execution and host-scoped integration still mixed with AD semantics. | Separate transport orchestration from semantic mapping and route semantics to canonical AD modules. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | deferred/redteam-lateral | Broad ad-lateral projector still coupled to full legacy catalog/path breadth. | Defer until enough AD slices are canonicalized to define controlled projection convergence. |

## Current Canonical AD Scope

- Slice 1 (Phase 7A): privileged membership / privilege assignment mapping
- Slice 2 (Phase 7C): password-description / credential-hint normalization
- Slice 3 (Phase 7D): weak password policy normalization (minimum length threshold)

All delegation/ACL/DCSync/AdminSDHolder and broad ad-lateral runtime semantics remain deferred.
