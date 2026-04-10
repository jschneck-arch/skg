# Phase 7K AD-22 Readiness

Date: 2026-04-02

## Readiness Check

Status: **ready for AD-22 core migration** with scoped constraints.

## What Is Now True

1. Session evidence is routed from runtime collection into canonical AD-shaped input:
- `sessions.json` (runtime collection) -> `ad22_tiering_input.json` (canonical sidecar)
- routing function: `skg_services.gravity.ad_runtime.route_bloodhound_ad22_evidence`

2. Active runtime path no longer treats legacy static-unknown AD-22 as authoritative:
- legacy `AD-22` output from BloodHound parser is filtered in `run_bloodhound()`

3. Conflicting AD-22 meaning in legacy LDAP adapter is quarantined:
- `AD-22` -> `AD-22-LDAP-LEGACY`

## Remaining Deferred Residue

- No canonical AD-22 adapter/policy/projector slice exists yet in `packages/skg-domains/ad`.
- ad-lateral catalog/path coupling remains deferred.
- Runtime still runs most AD legacy parser checks pending broader AD migration.

## Next Phase Recommendation

Proceed to **AD-22 core migration** with strict scope:
1. Add canonical AD domain adapter/policy/mapping for AD-22 baseline tiering posture only.
2. Consume `ad22_tiering_input.json` (or equivalent in-memory payload) as canonical adapter input.
3. Keep path/value/redteam coupling and broad ad-lateral projector semantics deferred.
