# Phase 7T Delegation Consumer Map

Date: 2026-04-03

## Target IDs

- `AD-06-LDAP-LEGACY`
- `AD-06-IMPACKET-LEGACY`

## In-Repo Consumer Discovery

Search basis:
- `rg -n "AD-06-LDAP-LEGACY|AD-06-IMPACKET-LEGACY" /opt/skg -g '!**/__pycache__/**'`

### Active runtime consumers (before 7T changes)

| Path | Consumer type | Dependency role | 7T action |
|---|---|---|---|
| `skg-gravity/gravity_field.py` | runtime coverage advertisement | Advertised legacy collision IDs as instrument wavelengths | migrated: removed legacy AD-06 collision IDs from wavelength advertisement |
| `skg-gravity/adapters/ldap_enum.py` | legacy output producer | Emitted `AD-06-LDAP-LEGACY` event branch | retired: removed emission branch |
| `skg-gravity/adapters/impacket_post.py` | legacy output producer | Emitted `AD-06-IMPACKET-LEGACY` event branch | retired: removed emission branch |

### Test-only consumers (before 7T changes)

| Path | Consumer type | Dependency role | 7T action |
|---|---|---|---|
| `packages/skg-services/tests/test_phase7s_delegation_authority.py` | test assertion | Expected collision IDs in wavelengths/constants | migrated: assertions updated to retirement state |

### Docs-only references

References in `docs/migration/**` remain design history and are not runtime consumers.

## Current Consumer Status (post-7T)

| ID | Active runtime consumers | Active test consumers | Status |
|---|---|---|---|
| `AD-06-LDAP-LEGACY` | none | none (positive dependency removed) | retired from runtime output and coverage advertisement |
| `AD-06-IMPACKET-LEGACY` | none | none (positive dependency removed) | retired from runtime output and coverage advertisement |

## Retained Compatibility Signals

Still retained in legacy LDAP adapter:
- `AD-22-LDAP-LEGACY` quarantine branch (unrelated to AD-06 delegation collision retirement scope).

