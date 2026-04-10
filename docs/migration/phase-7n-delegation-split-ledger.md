# Phase 7N Delegation Split Ledger

Date: 2026-04-03

## Scope

- `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`
- `skg/sensors/bloodhound_sensor.py`
- `skg/sensors/adapter_runner.py`
- `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json`
- `skg-ad-lateral-toolchain/projections/lateral/run.py`
- `skg-gravity/adapters/ldap_enum.py`
- `skg-gravity/adapters/impacket_post.py`

## Delegation Seam Classification Ledger

| Legacy path | Delegation seam/branch | Classification | Ownership classification | Recommended action | Rationale | Risk if migrated prematurely |
|---|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | AD-06 (`unconstraineddelegation=true` on enabled non-DC hosts) | AD semantic fact -> candidate for extraction | AD domain semantics | extract now (helper-level only) | This is a static posture fact from AD object state, independent of attacker-path scoring. | If migrated as full legacy function, AD-07/AD-09 coupling and legacy event emission come with it. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | AD-07 ("reachable/active" via `lastlogontimestamp` age heuristics) | context-dependent logic -> defer | service/runtime dependency + deferred path/value reasoning | defer | Freshness windows and reachability are context/runtime policy, not stable domain posture semantics. | Embeds runtime recency assumptions in canonical AD semantics and causes drift across environments. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | AD-08 (`trustedtoauthfordelegation` + `allowedtodelegate`) | AD semantic fact -> candidate for extraction | AD domain semantics | extract now (helper-level only) | Protocol-transition delegation configuration is a structural AD posture signal. | Full-function migration would couple AD-08 with AD-09 sensitive-target reasoning. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | AD-09 (sensitive target service classification) | path/value reasoning -> defer | deferred redteam-lateral/path/value reasoning | defer | "Sensitive" service classification implies target importance and attack utility context. | Trojan-horse path/value semantics would contaminate AD baseline domain ownership. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | `SENSITIVE_DELEGATION_SVCS` use in AD-09 branch | context-dependent logic -> defer | deferred redteam-lateral/path/value reasoning | defer | Constant encodes offensive utility priorities, not pure AD posture. | Domain layer gains attacker-priority semantics as baseline truth. |
| `skg/sensors/bloodhound_sensor.py` | collection/normalization of delegation fields (`unconstraineddelegation`, `allowedtodelegate`, `trustedtoauthfordelegation`) | runtime dependency -> service | service/runtime | keep in services | Collection and transport normalization are runtime responsibilities. | Moving this into domain would mix transport/runtime with semantic adapters. |
| `skg/sensors/adapter_runner.py::run_bloodhound` | monolithic call to `check_delegation` legacy emitter | runtime dependency -> service | service/runtime | split later | Runtime currently executes mixed semantic branches via legacy module. | Preserves dual-authority semantics and bypasses canonical domain adapters. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_unconstrained_delegation_v1` | path requires `AD-06`,`AD-07`,`AD-22` | path/value reasoning -> defer | deferred redteam-lateral/path/value reasoning | defer | Path binds structural delegation facts to context/tiering coupling. | Reasserts ad-lateral path authority over canonical AD slices. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_constrained_delegation_s4u_v1` | path requires `AD-08`,`AD-09` | path/value reasoning -> defer | deferred redteam-lateral/path/value reasoning | defer | AD-09 remains context-sensitive target-value branch. | Canonical AD posture slice would inherit context-value coupling by default. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | legacy path-scoring projector consumes delegation wickets | path/value reasoning -> defer | deferred broad projector semantics | defer | Projector is legacy ad-lateral authority with fallback import behavior. | Canonical domain/projector boundaries get bypassed. |
| `skg-gravity/adapters/ldap_enum.py` | conflicting AD-06 meaning (privileged account exposure) | context-dependent logic -> defer | deferred legacy compatibility residue | defer/quarantine | Symbol reuse collides with delegation AD-06 meaning. | Wicket id collision corrupts delegation semantic authority. |
| `skg-gravity/adapters/impacket_post.py` | conflicting AD-06 meaning from post-exploitation evidence | path/value reasoning -> defer | deferred redteam-lateral/path/value reasoning | defer/quarantine | AD-06 is reused for attack-result semantics outside delegation posture. | Cross-source semantic collision will break canonical delegation interpretation. |

## Safe Helper Extraction Performed In Phase 7N

| Legacy semantic origin | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` structural branches (AD-06/AD-08 inputs + SPN edge parsing) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/delegation_semantics.py` | helper | extract now | Keeps only structural normalization: delegation principals, unconstrained non-DC hosts, protocol-transition principals, and raw SPN edges. | Does not yet enforce a protocol contract for runtime delegation input because no canonical delegation runtime path exists yet. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/__init__.py` | helper export | rewritten | Exposes canonical delegation helper APIs to future AD slice adapters. | Export surface can sprawl if future helpers are added without slice gating. |
| `N/A` | `packages/skg-domains/ad/tests/test_ad_delegation_semantics_helpers.py` | tests | added | Locks pure structural behavior and prevents accidental insertion of context/path reasoning. | Tests do not yet cover end-to-end delegation slice because slice migration is intentionally deferred. |
