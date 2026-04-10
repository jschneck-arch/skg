# Phase 7Q Delegation Boundaries

Date: 2026-04-03

## Boundary Decision

Delegation remains split into:
- canonical AD posture semantics (`AD-06`, `AD-08`) already migrated in AD domain
- service/runtime context semantics (`AD-07`) kept outside AD domain
- sensitive-target/value semantics (`AD-09`) deferred outside AD domain

No new delegation slice is migrated in Phase 7Q.

## AD-07 Boundary (Freshness/Reachability)

| Item | Current source | Ownership | Phase 7Q decision | Rationale |
|---|---|---|---|---|
| Recency threshold (`90d`) + unknown-as-active handling | `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | service/runtime context policy | keep out of AD domain; isolate in service helper | This is runtime evidence interpretation, not stable delegation configuration semantics. |
| Canonicalized helper | `packages/skg-services/src/skg_services/gravity/delegation_context.py::classify_ad07_unconstrained_activity` | service/runtime | extracted | Preserves behavior without giving AD domain authority over freshness assumptions. |
| Helper tests | `packages/skg-services/tests/test_delegation_context_helpers.py` | service tests | added | Locks context logic under service ownership only. |

## AD-09 Boundary (Sensitive-Target/Value)

| Item | Current source | Ownership | Phase 7Q decision | Rationale |
|---|---|---|---|---|
| `SENSITIVE_DELEGATION_SVCS` and constrained sensitive-target scoring | `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | deferred redteam-lateral/path/value reasoning | remain deferred | Encodes attacker usefulness/target value, not stable AD posture fact semantics. |
| Coupled legacy path requirement (`AD-08` + `AD-09`) | `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_constrained_delegation_s4u_v1` | deferred ad-lateral authority | remain deferred | Legacy path coupling would reintroduce non-canonical value/path authority. |

## Runtime and Legacy Compatibility Boundary

| Path | Boundary status | Decision |
|---|---|---|
| `skg/sensors/adapter_runner.py` (`check_delegation` call still present) | mixed runtime compatibility residue | retain temporarily; retire in controlled wave after legacy path consumers are removed |
| `skg/sensors/adapter_runner.py` canonical path filter | canonical guardrail active | keep: drops legacy `AD-06..AD-09` for `ad_delegation_posture_baseline_v1` |
| `skg-gravity/gravity_field.py` bloodhound wavelength advertises `AD-07`/`AD-09` | legacy inventory residue | update later during retirement wave to prevent false canonical interpretation |

## AD-06 Collision Quarantine Boundary

| Path | Symbol | Classification | Decision |
|---|---|---|---|
| `skg-gravity/adapters/ldap_enum.py` | `AD-06-LDAP-LEGACY` | legacy compatibility collision | keep quarantined until legacy consumers are removed |
| `skg-gravity/adapters/impacket_post.py` | `AD-06-IMPACKET-LEGACY` | deferred attack-result collision | keep quarantined until legacy consumers are removed |

Canonical AD-06 meaning remains exclusively domain-owned via:
- `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py`
