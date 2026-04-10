# Phase 7N Delegation Deferred Residue

Date: 2026-04-03

## Deferred Residue After Delegation Seam Isolation

| Legacy path | Deferred component | Classification | Why deferred | Exact future step |
|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-07 branch | unconstrained host reachability via `lastlogontimestamp` thresholding | context-dependent logic | Recency thresholds and activity interpretation are runtime context policy, not static AD posture semantics. | Define canonical delegation runtime input contract and move recency policy to service-owned evidence shaping. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` AD-09 branch | sensitive-target classification (`SENSITIVE_DELEGATION_SVCS`) | path/value reasoning | Classifies offensive utility and target value; exceeds domain-owned baseline posture. | Split raw SPN edge extraction (already helperized) from sensitivity/value policy into deferred redteam layer. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_unconstrained_delegation_v1` | path coupling to AD-07 and AD-22 | deferred redteam-lateral/path/value reasoning | Attack-path authority is legacy and still couples delegation with tiering/path assumptions. | Introduce canonical AD delegation path catalog entry only after AD-06/AD-08 slice migration and AD-07/AD-09 split policy decisions. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_constrained_delegation_s4u_v1` | AD-08 coupled with AD-09 | deferred redteam-lateral/path/value reasoning | AD-09 remains non-domain sensitivity/value branch. | Keep deferred until AD-09 ownership is explicitly decided outside AD baseline slice. |
| `skg/sensors/adapter_runner.py::run_bloodhound` | direct execution of legacy `check_delegation` monolith | runtime dependency | Runtime still invokes mixed legacy branch set; canonical delegation adapter path does not exist yet. | Replace with service wrapper that loads protocol-governed delegation input and invokes canonical AD delegation adapter when that adapter is migrated. |
| `skg-gravity/adapters/ldap_enum.py` | AD-06 symbol collision (privileged-account exposure, not delegation posture) | deferred legacy compatibility residue | Same wicket id currently represents different semantic meaning. | Quarantine/rename this branch before enabling canonical delegation wickets in active runtime routing. |
| `skg-gravity/adapters/impacket_post.py` | AD-06 symbol collision from post-exploitation branch | deferred redteam-lateral/path/value reasoning | Attack-result semantics conflict with delegation posture semantics. | Recode to non-AD-06 identifier or isolate into legacy-only compatibility mapping. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | delegation path projection authority | deferred broad projector semantics | Legacy projector still computes coupled ad-lateral outcomes outside canonical domain/projector boundaries. | Keep dormant for canonical AD slices; revisit only after delegation slice contract and canonical projector routing exist. |

## Extracted In This Phase

- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/delegation_semantics.py`
- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/__init__.py`
- `packages/skg-domains/ad/tests/test_ad_delegation_semantics_helpers.py`

No delegation adapter/projector slice was migrated in Phase 7N.
