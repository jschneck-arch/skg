# Phase 7S Delegation Authority Map

Date: 2026-04-03

## Canonical Authority Map

| Concern | Canonical authority | Canonical path |
|---|---|---|
| AD-06/AD-08 delegation posture semantics | AD domain | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py` |
| AD-06/AD-08 delegation input contract | protocol | `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_input.py` |
| AD-06/AD-08 evidence routing | services/runtime | `packages/skg-services/src/skg_services/gravity/ad_runtime.py`, `skg/sensors/adapter_runner.py` |
| AD-07 context contract | protocol | `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_context.py` |
| AD-07 context computation + routing | services/runtime | `packages/skg-services/src/skg_services/gravity/delegation_context.py`, `packages/skg-services/src/skg_services/gravity/ad_runtime.py`, `skg/sensors/adapter_runner.py` |

## Non-Canonical / Deferred Authority

| Concern | Current owner | Status |
|---|---|---|
| AD-09 sensitive-target/value logic | legacy ad-lateral delegation branch (`check_delegation`) | deferred (legacy path only) |
| Legacy delegation family path composition | `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | non-canonical authority |
| AD-06 collision semantics from LDAP / post-exploitation | `skg-gravity/adapters/ldap_enum.py`, `skg-gravity/adapters/impacket_post.py` | quarantined legacy outputs |

## Runtime Coverage Advertisement Map (Post-7S)

| Instrument | Delegation-related advertised wavelengths | Authority interpretation |
|---|---|---|
| `bloodhound` | `AD-06`, `AD-08` (no `AD-07`, no `AD-09`) | canonical delegation posture-only coverage |
| `ldap_enum` | `AD-06-LDAP-LEGACY` | quarantined, non-canonical collision output |
| `impacket_post` | `AD-06-IMPACKET-LEGACY` | quarantined, non-canonical collision output |

## Guardrail Summary

1. Canonical delegation meaning is no longer advertised as AD-07/AD-09 coverage.
2. Collision-producing instruments no longer advertise canonical AD-06.
3. Legacy delegation branch execution is explicit-path gated and non-default.

