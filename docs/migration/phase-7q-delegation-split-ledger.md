# Phase 7Q Delegation Split Ledger

Date: 2026-04-03

## Scope

- AD-07 seam (`freshness/reachability`) from legacy delegation branch
- AD-09 seam (`sensitive-target/value`) from legacy delegation branch
- Quarantined legacy AD-06 collisions
- Retirement-readiness classification for remaining legacy delegation branches

## Seam Classification Ledger

| Legacy path | Seam identified | Ownership classification | Recommended action | Rationale | Risk if migrated prematurely |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-07 | `lastlogontimestamp` recency heuristic (`90d`) + unknown-as-active assumption | service/runtime context policy | split now (helper extraction) | AD-07 is contextual runtime freshness logic, not stable AD configuration/posture semantics. | Putting this in AD domain would hardcode runtime recency assumptions as canonical domain truth. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-09 | `SENSITIVE_DELEGATION_SVCS` service-value classification on `allowedtodelegate` SPNs | deferred redteam-lateral/path/value reasoning | defer | AD-09 expresses target sensitivity/value and attacker usefulness coupling. | Domain contamination: AD posture slice would inherit path/value authority. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_unconstrained_delegation_v1` | AD-06 coupled with AD-07 and AD-22 | deferred redteam-lateral/path/value reasoning | defer | Legacy path binds posture, freshness context, and tiering coupling. | Reintroduces legacy mixed authority as canonical path logic. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_constrained_delegation_s4u_v1` | AD-08 coupled with AD-09 sensitivity/value branch | deferred redteam-lateral/path/value reasoning | defer | Path is centered on offensive target-value semantics, not baseline posture. | Drags attacker-usefulness framing into AD baseline model. |
| `skg/sensors/adapter_runner.py::run_bloodhound` | legacy `check_delegation` still executes for non-canonical path ids | service/runtime migration residue | split later | Canonical path already filters AD-06..AD-09 legacy emissions for `ad_delegation_posture_baseline_v1`; remaining legacy execution is compatibility residue. | Hidden dual-path behavior may persist if legacy ids are still invoked externally. |
| `skg-gravity/gravity_field.py` instrument wavelength inventory | still advertises AD-07/AD-09 in broad BloodHound wavelength list | service/runtime compatibility residue | split later | Inventory remains broad and legacy-inclusive; canonical AD posture slice does not consume AD-07/AD-09. | Operators may assume AD-07/AD-09 are canonicalized when they are not. |
| `skg-gravity/adapters/ldap_enum.py` (`AD-06-LDAP-LEGACY`) | quarantined non-delegation AD-06 semantic collision | legacy compatibility residue | retire later (planned) | Collision is already quarantined but still present for compatibility. | If re-aliasing occurs, AD-06 canonical meaning could drift again. |
| `skg-gravity/adapters/impacket_post.py` (`AD-06-IMPACKET-LEGACY`) | quarantined post-exploitation AD-06 semantic collision | deferred redteam-lateral/attack-result residue | retire later (planned) | Collision is already quarantined but still emitted for compatibility. | Attack-result branch could be misinterpreted as delegation posture if remapped carelessly. |

## Safe Helper Extraction In This Phase

| Legacy origin | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `check_delegation` AD-07 recency branch | `packages/skg-services/src/skg_services/gravity/delegation_context.py` | service helper | extracted now | Isolates runtime freshness policy (`lastlogontimestamp`) in services, outside AD domain semantics. | Helper is not yet wired as canonical runtime output; integration policy remains deferred by design. |
| `N/A` | `packages/skg-services/tests/test_delegation_context_helpers.py` | service tests | added | Locks legacy-equivalent AD-07 context behavior in service-owned tests. | Tests only helper semantics; no new AD slice migrated in this phase. |
