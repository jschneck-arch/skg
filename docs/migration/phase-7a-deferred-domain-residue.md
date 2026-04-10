# Phase 7A Deferred Domain Residue

Date: 2026-04-02

## Deferred Legacy Material

| Legacy path | Classification | Why deferred | Exact next step |
|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` (non-membership checks) | deferred | Contains many additional AD slices (Kerberoast, AS-REP, delegation, ACL abuse, DCSync, AdminSDHolder, LAPS) in one module. | Split by semantic slice and migrate one slice at a time into `skg_domain_ad.adapters.*`. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | deferred | Mixed source parser + multi-slice AD wicket emission; overlaps with bloodhound-derived semantics. | Extract a dedicated LDAP inventory normalization slice with source parser isolated in service wrapper or source adapter module. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | deferred | Legacy projector still tied to ad_lateral catalog breadth and legacy compatibility behavior. | Migrate additional AD slice projectors into canonical `skg_domain_ad.projectors` as slices land. |
| `skg/sensors/bloodhound_sensor.py` | deferred | Runtime API transport/orchestration plus data normalization coupled to legacy adapter contracts. | Build service-owned AD runtime wrapper(s) that call canonical AD domain adapters. |
| `skg-gravity/adapters/ldap_enum.py` | deferred | Runtime LDAP execution mixed with ad_lateral wicket semantics and legacy import/path behavior. | Split runtime transport into services and map resulting inventory through canonical AD domain adapter contracts. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (full breadth) | deferred | Catalog covers many attack-chain semantics outside selected Phase 7A slice. | Migrate catalog sections incrementally as dedicated AD slices become canonical. |

## Current Safe Canonical Scope

- AD privileged-group and membership relationship mapping only.
- AD projector paths:
  - `ad_privilege_relationship_mapping_v1`
  - `ad_human_admin_assignment_v1`

All broader AD-lateral and redteam-coupled semantics remain intentionally deferred.
