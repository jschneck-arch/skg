# Phase 7P AD Slice Deferred Residue

Date: 2026-04-03

## Deferred Residue After AD-06/AD-08 Posture-Core Migration

| Legacy path | Deferred seam/component | Classification | Why deferred | Exact next step |
|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-07 branch | unconstrained delegation host reachability/recency logic | context-dependent logic | Depends on runtime freshness policy and environment context; not domain posture-core semantics. | Introduce explicit service/runtime policy contract for reachability context before any AD-07 migration. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-09 branch | sensitive-target service/value interpretation | path/value reasoning | Encodes target value/usefulness semantics outside AD baseline posture ownership. | Keep in deferred lateral/reasoning layer; do not migrate into AD domain slice. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_unconstrained_delegation_v1` | AD-06 coupled with AD-07 and AD-22 path prerequisites | deferred redteam-lateral/path/value reasoning | Legacy path authority mixes baseline posture with context/path coupling. | Keep non-canonical; derive future canonical high-coupling path only after dedicated split/governance pass. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_constrained_delegation_s4u_v1` | AD-08 coupled with AD-09 sensitivity branch | deferred redteam-lateral/path/value reasoning | Coupled to sensitive-target interpretation and attack usefulness. | Keep deferred until AD-09 ownership is explicitly resolved outside baseline posture-core migration. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | broad delegation/lateral path projection authority | deferred broad projector semantics | Projector still computes coupled ad-lateral attack reasoning. | Keep deferred as design evidence only; avoid canonical AD projector coupling. |
| `skg/sensors/adapter_runner.py` (legacy check execution for non-canonical delegation paths) | legacy mixed delegation semantics still execute for non-canonical path IDs | service/runtime migration residue | Required for controlled compatibility while legacy paths remain live. | In a later phase, retire legacy `check_delegation` runtime branch after full canonical path migration/deletion wave. |
| `skg-gravity/adapters/ldap_enum.py` (`AD-06-LDAP-LEGACY`) | legacy privileged-account exposure branch | legacy compatibility residue | Kept only as quarantined compatibility output to avoid semantic collision. | Remove or remap after downstream legacy consumers are migrated off this branch. |
| `skg-gravity/adapters/impacket_post.py` (`AD-06-IMPACKET-LEGACY`) | legacy post-exploitation hash-capture branch | deferred redteam-lateral/attack-result residue | Kept as quarantined compatibility output to avoid semantic collision. | Remove or remap once legacy consumers are updated to non-canonical IDs/contracts. |

## Explicit Non-Migration Confirmation

Not migrated in Phase 7P:
- AD-07
- AD-09
- path chaining / attacker usefulness / target value semantics
- ad-lateral projector breadth
