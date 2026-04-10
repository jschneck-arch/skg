# Phase 7U Delegation Containment Ledger

Date: 2026-04-03

## Objective

Finalize containment of legacy delegation authority so legacy delegation branches are dormant by default, compatibility-only when explicitly enabled, and clearly separated from canonical AD ownership.

## Containment Changes

| Path | Classification | Action | Change | Rationale | Residual risk |
|---|---|---|---|---|---|
| `skg/sensors/adapter_runner.py` | runtime gating | rewritten | Added `LEGACY_DELEGATION_COMPAT_ENV=SKG_ENABLE_LEGACY_DELEGATION_COMPAT`; legacy delegation branch now runs only when: (1) path id is one of explicit legacy ids and (2) env opt-in is enabled. | Moves remaining legacy delegation behavior to dormant compatibility mode by default. | External operators relying on legacy path IDs must set explicit compat env to keep behavior. |
| `skg/sensors/adapter_runner.py` | runtime containment | rewritten | Added explicit warning when legacy path id is requested without compat mode; keeps canonical and non-legacy path behavior unchanged. | Prevents silent re-activation of non-canonical delegation logic. | Legacy branch implementation still exists for compatibility-only mode. |
| `packages/skg-services/tests/test_ad_runtime_wrappers.py` | containment tests | updated | Added/updated tests proving: legacy path IDs are dormant without compat flag; legacy branch only executes with compat flag; canonical path behavior unchanged. | Verifies containment behavior in active runtime path. | Does not test out-of-repo callers. |
| `packages/skg-services/tests/test_phase7s_delegation_authority.py` | authority containment tests | updated | Added test ensuring legacy path list remains explicit and `_legacy_delegation_enabled_for_path(...)` is false by default. | Guards against accidental widening of legacy compatibility surface. | Test file name is historical (`phase7s`) but assertions track current containment state. |
| `skg-gravity/gravity_field.py` | coverage messaging | updated | BloodHound description now explicitly states legacy delegation paths are compatibility-only. | Keeps inventory narrative aligned with containment model. | Messaging does not enforce behavior; enforcement remains in adapter runner. |

## Remaining Legacy Delegation Paths (Post-7U)

| Path id | Execution status | Why retained |
|---|---|---|
| `ad_unconstrained_delegation_v1` | compatibility-only, dormant unless `SKG_ENABLE_LEGACY_DELEGATION_COMPAT=1` | temporary legacy compatibility for explicit legacy workflows |
| `ad_constrained_delegation_s4u_v1` | compatibility-only, dormant unless `SKG_ENABLE_LEGACY_DELEGATION_COMPAT=1` | temporary legacy compatibility for explicit legacy workflows |

## Explicitly Not Changed

- No new AD slice migration.
- No AD semantic expansion.
- No revival of retired AD-06 collision outputs.
- AD-09 remains deferred and non-canonical.

