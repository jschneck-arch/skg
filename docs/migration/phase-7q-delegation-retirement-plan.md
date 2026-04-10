# Phase 7Q Delegation Retirement Plan

Date: 2026-04-03

## Objective

Plan controlled retirement of remaining legacy delegation branches (`AD-07`, `AD-09` residue) and quarantined AD-06 collisions without breaking canonical delegation posture-core ownership.

## Retirement Inventory

| Legacy source | Branch/symbol | Status | Canonical replacement |
|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | AD-07 recency/reachability | active legacy compatibility branch | service-owned context helper path (`skg_services.gravity.delegation_context`) + future context contract/handoff |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` | AD-09 sensitive-target/value | active legacy compatibility branch | none in AD domain; remains deferred outside AD |
| `skg/sensors/adapter_runner.py` | executes `check_delegation` monolith | active compatibility callsite | canonical sidecar routes + canonical AD-06/08 mapping |
| `skg-gravity/adapters/ldap_enum.py` | `AD-06-LDAP-LEGACY` | quarantined compatibility output | none; remove after downstream dependency removal |
| `skg-gravity/adapters/impacket_post.py` | `AD-06-IMPACKET-LEGACY` | quarantined compatibility output | none; remove after downstream dependency removal |
| `skg-gravity/gravity_field.py` | BloodHound wavelength includes AD-07/AD-09 | compatibility inventory residue | canonical inventory should reflect only canonicalized delegation semantics |

## Wave Plan

### Wave 1: Gate legacy delegation emission to explicit legacy-only path ids

Scope:
- `skg/sensors/adapter_runner.py`
- `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`

Actions:
- keep canonical `ad_delegation_posture_baseline_v1` path on canonical AD-06/AD-08 sidecar flow only
- add explicit attack-path gating so `check_delegation` cannot emit `AD-07/AD-09` for canonical path ids
- enforce fail-fast log warning when legacy delegation ids are requested through canonical path

Prerequisites:
- no canonical tests depend on legacy AD-07/AD-09 emission
- service/runtime wrappers remain green for canonical AD-06/AD-08

Blockers:
- unknown external consumers still invoking old ad-lateral delegation path ids

Exit criteria:
- runtime tests show canonical path emits AD-06/AD-08 only
- no AD-07/AD-09 emissions under canonical path IDs

### Wave 2: Retire AD-06 legacy collision outputs

Scope:
- `skg-gravity/adapters/ldap_enum.py`
- `skg-gravity/adapters/impacket_post.py`

Actions:
- remove `AD-06-LDAP-LEGACY` and `AD-06-IMPACKET-LEGACY` emissions after consumer migration
- keep compatibility notes until removal lands

Prerequisites:
- zero live references to these wicket ids in active runtime/reporting/compat tests
- replacement identifiers decided for any still-needed legacy reporting

Blockers:
- any downstream policy/report/CLI consumer expecting these ids

Exit criteria:
- `rg "AD-06-LDAP-LEGACY|AD-06-IMPACKET-LEGACY"` returns docs/history only
- canonical AD-06 delegation posture remains singular and collision-free

### Wave 3: De-authorize AD-07/AD-09 as canonical delegation semantics

Scope:
- `skg-gravity/gravity_field.py`
- legacy ad-lateral catalog references where used as runtime authority

Actions:
- update instrument wavelength/advertised delegation coverage to avoid implying canonical AD-07/AD-09 ownership
- keep AD-07 as service-context candidate only if protocol/service contract is added
- keep AD-09 deferred outside AD domain unless ownership model changes

Prerequisites:
- decision recorded for AD-07 future ownership (service-context slice vs permanent defer)
- decision recorded for AD-09 (defer outside AD)

Exit criteria:
- runtime inventory and docs align with canonical ownership
- no dual-authority interpretation remains for delegation slices

## Quarantine Retention Rules (Until Retirement)

1. Quarantined legacy IDs must never be remapped to canonical `AD-06`.
2. Legacy delegation branches must not be enabled for canonical `ad_delegation_posture_baseline_v1` flow.
3. Any new delegation logic must declare ownership class first: AD semantic fact, service context, or deferred value/path reasoning.
