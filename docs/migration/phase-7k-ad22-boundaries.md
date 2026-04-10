# Phase 7K AD-22 Boundaries

Date: 2026-04-02

## Ownership Decisions

1. Service/runtime ownership (kept in runtime layer):
- BloodHound session collection (`skg/sensors/bloodhound_sensor.py`)
- runtime routing and callsite wiring (`skg/sensors/adapter_runner.py`)
- canonical AD-22 input sidecar generation (`skg_services.gravity.ad_runtime`)

2. AD domain ownership (consumed, not reimplemented in runtime):
- session normalization semantics (`normalize_privileged_session_rows`)
- tiering posture summary semantics (`summarize_privileged_tiering_exposure`)
- helper source: `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/tiering_semantics.py`

3. Legacy compatibility ownership (quarantined, non-canonical):
- LDAP legacy account-enumeration signal in `skg-gravity/adapters/ldap_enum.py`
- quarantined wicket ID: `AD-22-LDAP-LEGACY`

## Boundary Enforcement Applied

- `run_bloodhound()` now routes session evidence into canonical AD-shaped input before returning events.
- `run_bloodhound()` now drops legacy `AD-22` output from the legacy BloodHound parser path to prevent static-unknown semantics from being active runtime authority.
- `ldap_enum.py` no longer emits canonical `AD-22` to avoid conflicting meaning.

## Explicitly Deferred In This Pass

- Full AD-22 canonical adapter/event slice migration (adapter, policy, projector integration).
- ad-lateral catalog/path coupling (`ad_unconstrained_delegation_v1`, `ad_laps_absent_v1` coupling).
- AD-03 / AD-23 corrective migration.
- broad projector/runtime redesign.
