# Phase 7O Delegation Contract Ledger

Date: 2026-04-03

## Objective

Define protocol-governed delegation handoff input and route runtime delegation evidence through services without migrating AD-07/AD-09 or path/value reasoning.

## Contract Additions

| Path | Classification | Action | Details | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_input.py` | protocol contract | added | Introduces `skg.ad.delegation_input.v1`, sidecar filename `ad_delegation_input.json`, strict wicket set `AD-06` + `AD-08`, and validation APIs. | Establishes single canonical shape for delegation posture-core input. | Future versioning (`v2`) still requires compatibility plan once full delegation slices expand. |
| `packages/skg-protocol/src/skg_protocol/contracts/__init__.py` | protocol export surface | updated | Exports delegation contract constants and validators. | Makes contract available to services/callers without private imports. | Export growth must remain controlled to avoid contract sprawl. |
| `packages/skg-protocol/tests/test_ad_delegation_input_contract.py` | protocol tests | added | Validates accepted canonical payload and rejection of AD-07/AD-09 coupling or missing deferred flags. | Enforces separation between posture-core and deferred context/path semantics. | Tests are contract-level only; no projector semantics covered yet by design. |

## Service Handoff Changes

| Path | Classification | Action | Details | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `packages/skg-services/src/skg_services/gravity/ad_runtime.py` | service runtime handoff | updated | Added `build_ad0608_delegation_input(...)`, `route_bloodhound_delegation_evidence(...)`, and availability/helper wiring for delegation semantics. | Services now own evidence routing and contract validation for delegation posture-core handoff. | No canonical delegation event mapping yet (intentionally deferred to next slice migration). |
| `skg/sensors/adapter_runner.py` | service runtime callsite | updated | Added `_route_ad0608_runtime_evidence(...)` and invoked it in `run_bloodhound(...)` using users+computers inventory. | Ensures live runtime path writes canonical delegation sidecar consistently. | Legacy `check_delegation` still runs in parallel for compatibility until delegation slice migration. |
| `packages/skg-services/tests/test_ad_runtime_wrappers.py` | service tests | updated | Added direct sidecar handoff test and runtime callsite test asserting delegation sidecar schema/wickets/deferred flags. | Proves delegation evidence reaches canonical contract shape. | Does not yet assert canonical AD-06/08 event emission because full slice migration is out of scope. |

## Legacy Semantic Quarantine

| Path | Old behavior | New behavior | Ownership decision | Rationale |
|---|---|---|---|---|
| `skg-gravity/adapters/ldap_enum.py` | emitted `AD-06` for privileged-account exposure | now emits `AD-06-LDAP-LEGACY` with explicit quarantine note | legacy compatibility residue | Removes semantic collision with canonical delegation AD-06 posture meaning. |
| `skg-gravity/adapters/impacket_post.py` | emitted `AD-06` for Administrator hash capture | now emits `AD-06-IMPACKET-LEGACY` with explicit quarantine note | deferred redteam-lateral/attack-result residue | Prevents post-exploitation signal from redefining delegation posture semantics. |

## Scope Compliance

- AD-07 not migrated.
- AD-09 not migrated.
- No attacker-usefulness, sensitive-target, recency, or path-chaining logic migrated into canonical AD/domain semantics.
