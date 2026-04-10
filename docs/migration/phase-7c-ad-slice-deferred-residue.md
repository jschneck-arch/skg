# Phase 7C AD Slice Deferred Residue

Date: 2026-04-02

## Deferred Residue After Credential-Hint Slice Migration

| Legacy path | Deferred classification | Why deferred | Exact next step |
|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` (`check_delegation`, `check_acls`, `check_dcsync_accounts_enabled`, `check_adminsdholder`, `check_stale_privileged`) | deferred/redteam-lateral + shared/cross-domain | Out of scope for credential-hint slice; still mixed with attack-chain reasoning and legacy IDs. | Split by semantic slice and migrate one canonical AD slice at a time. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` (`detect_version`, `normalize_node`, `load_bh_file`, `load_bh_dir`) | service/runtime | Source parsing belongs to runtime/service wrappers, not domain semantics. | Build service-owned normalization wrappers that feed canonical domain adapters. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` (`main` orchestration and multi-slice wicket emission) | mixed runtime + deferred/redteam-lateral | Still combines parser IO, slice logic, and envelope emission in one function. | Isolate parser module and map each remaining slice into canonical AD adapters separately. |
| `skg/sensors/bloodhound_sensor.py` | service/runtime | Owns API auth, scheduling, cache, and orchestration; not domain semantic code. | Migrate runtime calls later to service wrappers that invoke canonical AD adapters. |
| `skg-gravity/adapters/ldap_enum.py` | service/runtime + mixed semantics | Owns LDAP execution/runtime with legacy side effects and mixed host/ad semantics. | Split runtime transport from semantic mapping and route semantic outputs through canonical AD adapters. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | deferred/redteam-lateral | Broad lateral projector remains tied to full ad-lateral catalog breadth. | Defer until additional AD slices are canonicalized and a controlled projector strategy is defined. |

## Current Canonical AD Scope

- Slice 1 (Phase 7A): privileged membership / privilege-assignment mapping
- Slice 2 (Phase 7C): password-description / credential-hint normalization

All other AD-lateral and redteam-oriented semantics remain deferred.
