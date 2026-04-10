# Phase 7R AD-07 Boundaries

Date: 2026-04-03

## Boundary Decision

AD-07 remains a protocol-governed **service context layer**.

- AD-07 is not AD-domain semantic authority.
- AD-07 is not part of AD ontology migration.
- AD-07 routing is service-owned and contract-validated.

## Ownership Classification

| Concern | Ownership | Canonical path |
|---|---|---|
| AD-07 context contract schema/validation | protocol | `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_context.py` |
| AD-07 recency computation and unknown-handling policy application | services | `packages/skg-services/src/skg_services/gravity/delegation_context.py` |
| AD-07 runtime evidence routing and sidecar persistence | services | `packages/skg-services/src/skg_services/gravity/ad_runtime.py` |
| AD-07 runtime callsite invocation | services/runtime | `skg/sensors/adapter_runner.py` |
| AD-07 domain semantics/projector interpretation | not allowed | `packages/skg-domains/ad/**` (no AD-07 migration) |

## Explicit Non-Ownership

### AD domain must not own

- recency threshold policy for AD-07 context
- unknown last-logon handling policy
- AD-07 activity-state interpretation

### Services must not own

- AD-09 sensitive-target/value interpretation
- attacker/path/value delegation reasoning

## Bypass Control

| Legacy behavior | New control |
|---|---|
| Legacy `check_delegation` AD-07 output could appear directly in runtime event stream. | `skg/sensors/adapter_runner.py::_drop_legacy_ad07_events(...)` removes legacy AD-07 runtime emissions. |
| Context shaping risk via implicit defaults. | AD-07 helper now requires explicit policy fields (`stale_days`, `unknown_last_logon_is_active`). |

## Contract Surface (Minimal/Explicit)

Schema: `skg.ad.delegation_context.v1`

Required explicit sections:
- `recency_policy`
  - `stale_days`
  - `stale_threshold_seconds`
- `unknown_handling_policy`
  - `unknown_last_logon_is_active`
- `activity_classification`
  - `active_unconstrained`
  - `stale_unconstrained`
  - `unknown_last_logon`
  - explicit `activity_state` values

No implicit policy defaults are accepted by contract validation.

