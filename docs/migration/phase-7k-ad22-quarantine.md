# Phase 7K AD-22 Quarantine

Date: 2026-04-02

## Quarantined Legacy Semantics

| Legacy source | Quarantined branch/symbol | Old meaning | Quarantine action | Canonical replacement path | Notes |
|---|---|---|---|---|---|
| `skg/sensors/adapter_runner.py` (legacy BloodHound parser output) | returned legacy `payload.wicket_id == "AD-22"` from `check_stale_privileged` | static `unknown` placeholder when tiering sessions are not wired | filtered from active runtime output with `_drop_legacy_ad22_events()` | canonical AD-22 input sidecar via `skg_services.gravity.ad_runtime.route_bloodhound_ad22_evidence()` | AD-21 output from same legacy check remains active; only AD-22 is quarantined. |
| `skg-gravity/adapters/ldap_enum.py` | legacy `wicket_id="AD-22"` branch | account enumeration was mislabeled as AD-22 | renamed to `AD-22-LDAP-LEGACY` with explicit quarantine detail | future canonical AD-22 domain slice (tiering posture) | Prevents semantic collision with AD domain AD-22 meaning. |

## Non-Quarantined (Deferred, Still Legacy-Owned)

| Path | Why retained |
|---|---|
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | Path/value coupling remains deferred; not modified in Phase 7K by design. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | Broad legacy projector scope remains deferred; no AD-22 canonical authority moved here. |

## Removal Conditions

1. Legacy BloodHound AD-22 filtering can be removed only after canonical AD-22 domain adapter emits authoritative AD-22 events on the active runtime path.
2. `AD-22-LDAP-LEGACY` can be retired when no runtime caller depends on that legacy signal and LDAP enumeration no longer needs compatibility output.
