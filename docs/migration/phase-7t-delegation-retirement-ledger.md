# Phase 7T Delegation Retirement Ledger

Date: 2026-04-03

## Objective

Retire legacy AD-06 collision compatibility outputs after consumer map confirmation, without broadening AD semantics or re-authorizing legacy delegation branches.

## Retirement Changes

| Path | Legacy behavior | New behavior | Classification | Action | Rationale | Residual risk |
|---|---|---|---|---|---|---|
| `skg-gravity/adapters/ldap_enum.py` | emitted `AD-06-LDAP-LEGACY` when privileged AD users discovered | no AD-06 collision event emitted; stores adapter-local telemetry fields in result (`retired_ad06_ldap_legacy_suppressed`, `privileged_accounts_detected`) | legacy collision output | retired output | Zero active runtime consumers in repo; removes collision-producing legacy delegation output. | External out-of-repo tooling that parsed this legacy event ID may lose that signal. |
| `skg-gravity/adapters/impacket_post.py` | emitted `AD-06-IMPACKET-LEGACY` when Administrator hash detected in secretsdump output | no AD-06 collision event emitted | legacy collision output | retired output | Zero active runtime consumers in repo; eliminates post-exploitation AD-06 semantic collision path. | External out-of-repo tooling that parsed this legacy event ID may lose that signal. |
| `skg-gravity/gravity_field.py` (`ldap_enum` instrument) | advertised `AD-06-LDAP-LEGACY` wavelength | no AD-06 collision wavelength advertised | runtime authority advertisement | rewritten | Coverage advertisement now matches retired output behavior. | None in repo scope. |
| `skg-gravity/gravity_field.py` (`impacket_post` instrument) | advertised `AD-06-IMPACKET-LEGACY` wavelength | no AD-06 collision wavelength advertised | runtime authority advertisement | rewritten | Coverage advertisement now matches retired output behavior. | None in repo scope. |
| `packages/skg-services/tests/test_phase7s_delegation_authority.py` | expected collision IDs to remain advertised/quarantined | now asserts collision IDs are not advertised and not present as runtime authority references | test migration | rewritten | Aligns tests with wave-2 retirement state. | Test filename still phase7s-prefixed, but assertions reflect current state. |

## Confirmed Non-Changes (Intentional)

| Area | Status | Reason |
|---|---|---|
| AD domain delegation semantics (`AD-06`/`AD-08`) | unchanged | no new AD slice migration allowed in phase |
| AD-07 context contract/handoff | unchanged | remains protocol/service-owned |
| AD-09 semantics | unchanged/deferred | remains non-canonical path/value logic |
| ad-lateral delegation catalog/projector residue | unchanged and explicitly non-canonical | out of scope for wave-2 retirement |

