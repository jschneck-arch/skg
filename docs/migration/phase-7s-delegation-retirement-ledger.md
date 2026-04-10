# Phase 7S Delegation Retirement Ledger

Date: 2026-04-03

## Scope

- Runtime gating hardening for legacy delegation branches
- De-authorization of implied canonical AD-07/AD-09 coverage in runtime inventory
- Quarantine progress for legacy AD-06 collision surfaces

## Changes

| Path | Change | Classification | Action | Rationale | Residual risk |
|---|---|---|---|---|---|
| `skg/sensors/adapter_runner.py` | Added explicit legacy gating (`LEGACY_DELEGATION_ATTACK_PATH_IDS`) and path-based branch enable check (`_legacy_delegation_enabled_for_path`) | runtime gating | rewritten | Legacy delegation (`check_delegation`) now executes only for explicit legacy path IDs (`ad_unconstrained_delegation_v1`, `ad_constrained_delegation_s4u_v1`). | Legacy branch code still exists for compatibility paths. |
| `skg/sensors/adapter_runner.py` | Removed unconditional `check_delegation` execution from default checks list; inserted conditionally for legacy path IDs only | runtime gating | rewritten | Prevents accidental non-canonical delegation emissions on non-legacy paths. | External callers still using legacy path IDs can trigger legacy delegation outputs by design. |
| `skg/sensors/adapter_runner.py` | Kept explicit legacy AD-07 drop (`_drop_legacy_ad07_events`) and canonical delegation filter for canonical path (`_drop_legacy_delegation_slice_events`) | runtime de-authorization | keep + reinforce | Ensures AD-07 remains service-context sidecar and canonical path remains AD-06/AD-08 only. | AD-09 still emitted on explicit legacy path IDs. |
| `skg-gravity/gravity_field.py` | BloodHound wavelength de-authorized for AD-07/AD-09 (removed from advertised coverage) | authority advertisement | rewritten | Stops runtime inventory from implying canonical AD-07/AD-09 coverage. | Legacy delegation paths remain available through explicit legacy IDs. |
| `skg-gravity/gravity_field.py` | Updated `impacket_post` wavelength `AD-06 -> AD-06-IMPACKET-LEGACY` | collision quarantine | rewritten | Aligns advertised coverage to quarantined legacy output, avoiding canonical AD-06 collision implication. | Consumer expectations for legacy IDs must be managed during future retirement. |
| `skg-gravity/gravity_field.py` | Updated `ldap_enum` wavelength `AD-06 -> AD-06-LDAP-LEGACY` | collision quarantine | rewritten | Aligns advertised coverage to quarantined legacy output, avoiding canonical AD-06 collision implication. | Same as above. |
| `packages/skg-services/tests/test_ad_runtime_wrappers.py` | Added non-legacy and legacy delegation gating tests | runtime tests | updated | Verifies legacy delegation disabled on non-legacy paths and enabled only on explicit legacy path IDs. | Tests cover runner behavior, not all external consumers. |
| `packages/skg-services/tests/test_phase7s_delegation_authority.py` | Added authority/advertisement/quarantine tests | authority tests | added | Verifies AD-07/AD-09 de-authorization in coverage advertisement and AD-06 collision quarantine IDs remain explicit. | Imports legacy gravity modules directly; behavior outside test surface still possible. |

## Wave 1 Retirement Progress

Completed in this phase:
- Legacy delegation execution is now explicit-path-gated.
- AD-07/AD-09 canonical coverage implication removed from BloodHound wavelength advertisement.
- Legacy AD-06 collision advertisement now uses quarantined IDs.

Not completed in this phase:
- Full removal of legacy delegation branch implementation.
- Full removal of quarantined collision outputs (`AD-06-LDAP-LEGACY`, `AD-06-IMPACKET-LEGACY`).

