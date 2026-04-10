# Phase 7S Delegation Boundaries

Date: 2026-04-03

## Boundary Status

Phase 7S preserves canonical delegation ownership:

- AD domain: delegation posture facts only (`AD-06`, `AD-08`) on canonical path.
- Protocol/services: AD-07 context contract and service-owned routing.
- AD-09: deferred non-canonical path/value semantics.

## Runtime Boundary Enforcement

| Boundary | Enforcement path | Status |
|---|---|---|
| Legacy delegation branch must not run by default | `skg/sensors/adapter_runner.py` conditional insertion of `check_delegation` only for `LEGACY_DELEGATION_ATTACK_PATH_IDS` | ENFORCED |
| Canonical delegation path must not use legacy delegation outputs | `skg/sensors/adapter_runner.py::_drop_legacy_delegation_slice_events(...)` for `ad_delegation_posture_baseline_v1` | ENFORCED |
| AD-07 must remain service-context only | `skg/sensors/adapter_runner.py::_drop_legacy_ad07_events(...)` + AD-07 sidecar routing | ENFORCED |
| AD-09 must remain deferred/non-canonical | legacy delegation gate restricted to explicit legacy path IDs only | ENFORCED |

## Coverage Advertisement Boundary

| Path | Prior implied boundary | New boundary |
|---|---|---|
| `skg-gravity/gravity_field.py` BloodHound instrument wavelength | Included `AD-07` and `AD-09`, implying broad canonical delegation coverage | Removed `AD-07`/`AD-09`; delegated canonical coverage signals only AD-06/AD-08 posture ownership |
| `skg-gravity/gravity_field.py` `ldap_enum` / `impacket_post` wavelengths | Advertised `AD-06`, colliding with canonical AD-06 meaning | Advertise `AD-06-LDAP-LEGACY` / `AD-06-IMPACKET-LEGACY` quarantine IDs |

## Explicit Deferred Boundary

Still deferred after Phase 7S:
- AD-09 sensitive-target/value semantics
- ad-lateral path/value reasoning
- full legacy delegation branch deletion
- full collision output deletion

