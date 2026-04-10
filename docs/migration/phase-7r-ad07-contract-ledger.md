# Phase 7R AD-07 Contract Ledger

Date: 2026-04-03

## Objective

Define a canonical AD-07 service-context contract and enforce contract-governed routing through service wrappers, without migrating AD-07 into AD domain semantics.

## Contract Additions (Protocol-Owned)

| Path | Classification | Action | Details | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_context.py` | protocol contract | added | Added schema `skg.ad.delegation_context.v1`, filename `ad07_delegation_context.json`, wicket id `AD-07`, and strict validation API. | AD-07 context shape is now explicit and versioned. | Future v2 policy evolution will require compatibility handling. |
| `packages/skg-protocol/src/skg_protocol/contracts/__init__.py` | protocol export surface | updated | Exported AD-07 context constants and validators. | Avoids private imports by runtime/services. | Export surface must remain tightly scoped. |
| `packages/skg-protocol/tests/test_ad_delegation_context_contract.py` | protocol tests | added | Validates canonical payload acceptance and rejects missing explicit policy fields. | Enforces explicit recency and unknown-handling fields with no implicit defaults. | Contract tests do not cover runtime I/O behavior (service tests handle that). |

## Service Wrapper and Routing Changes

| Path | Classification | Action | Details | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `packages/skg-services/src/skg_services/gravity/delegation_context.py` | service context helper | updated | Removed implicit defaults from `classify_ad07_unconstrained_activity`; requires explicit `stale_days` and `unknown_last_logon_is_active`; unknown rows now carry `activity_state=\"unknown\"`. | Eliminates ad-hoc/implicit context shaping. | Legacy callers outside canonical runtime could break if not updated (none observed in repo). |
| `packages/skg-services/src/skg_services/gravity/ad_runtime.py` | service wrapper | updated | Added `build_ad07_delegation_context(...)` and `route_bloodhound_ad07_context(...)`; payload validated against protocol contract before write. | All active AD-07 context computation now flows through contract + wrapper path. | AD-07 remains sidecar/context-only; no canonical event mapping by design. |
| `packages/skg-services/src/skg_services/gravity/__init__.py` | service API surface | updated | Exported AD-07 context wrapper APIs. | Maintains canonical service entrypoints. | Public surface growth should be monitored. |
| `skg/sensors/adapter_runner.py` | runtime callsite | updated | Added `_route_ad07_runtime_context(...)`; routes explicit AD-07 policy values into wrapper; added `_drop_legacy_ad07_events(...)` to remove legacy AD-07 event bypass. | Enforces service-owned handoff and removes active legacy AD-07 emission path. | Legacy toolchain still computes AD-07 internally, but active runtime output bypass is removed. |
| `packages/skg-services/tests/test_ad_runtime_wrappers.py` | service integration tests | updated | Added tests for AD-07 sidecar contract output and runtime no-bypass behavior. | Proves routing consistency and wrapper ownership. | Tests validate canonical runner path only. |
| `packages/skg-services/tests/test_delegation_context_helpers.py` | service helper tests | updated | Updated for explicit-policy call signatures. | Locks no-implicit-default rule in tests. | None. |

## Routing Consistency Outcome

- AD-07 context evaluation now routes through:
  - `skg.sensors.adapter_runner._route_ad07_runtime_context(...)`
  - `skg_services.gravity.ad_runtime.route_bloodhound_ad07_context(...)`
  - `skg_protocol.contracts.validate_ad_delegation_context(...)`
- Legacy AD-07 event emissions are dropped from runtime output by:
  - `skg.sensors.adapter_runner._drop_legacy_ad07_events(...)`

