# Phase 7U Delegation Authority Boundaries

Date: 2026-04-03

## Canonical Ownership (Unchanged)

| Ownership | Scope | Canonical path |
|---|---|---|
| AD domain | posture semantics only (`AD-06`, `AD-08`) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py` |
| protocol/services | AD-07 context contract + handoff | `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_context.py`, `packages/skg-services/src/skg_services/gravity/ad_runtime.py` |
| deferred non-canonical | AD-09/path-value delegation reasoning | legacy ad-lateral sources only |

## Legacy Delegation Execution Boundary (Post-7U)

Legacy `check_delegation` execution is now constrained by two gates:
1. attack path id must be one of:
   - `ad_unconstrained_delegation_v1`
   - `ad_constrained_delegation_s4u_v1`
2. compatibility env must be enabled:
   - `SKG_ENABLE_LEGACY_DELEGATION_COMPAT=1`

Without both gates, legacy delegation branch remains dormant.

## Non-Canonical Residue Containment

| Residue | Boundary status | Note |
|---|---|---|
| ad-lateral delegation catalog (`attack_preconditions_catalog.ad_lateral.v1.json`) | non-canonical only | retained as legacy compatibility/design evidence |
| ad-lateral delegation projector residue | non-canonical only | not used as canonical AD authority |
| legacy delegation branch code (`check_delegation`) | compatibility-only | retained temporarily for explicit legacy workflows only |

## Retired Collision Boundary

Retired and not reintroduced:
- `AD-06-LDAP-LEGACY`
- `AD-06-IMPACKET-LEGACY`

These are no longer active runtime outputs or active coverage advertisement.

