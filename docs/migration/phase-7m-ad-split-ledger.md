# Phase 7M AD Corrective Split Ledger

Date: 2026-04-03

## Scope

- `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`
- `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json`
- `skg-ad-lateral-toolchain/projections/lateral/run.py`
- AD-22 sidecar governance seam:
  - `packages/skg-services/src/skg_services/gravity/ad_runtime.py`
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/run.py`
  - `skg/sensors/adapter_runner.py`

## Seam Split Ledger

| Legacy path | Seam identified | Ownership classification | Recommended action | Rationale | Risk if migrated prematurely |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` (`AD-03`) | static "no detection" heuristic emitted as realized | shared helper/governance concern | split later | This is confidence/policy governance, not stable AD semantic normalization. It needs explicit confidence contract and evidence source policy first. | Canonical AD semantics would embed unverifiable detection-absence assertions as truth. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` (`AD-23`) | DA-impact/value branch coupled to Kerberoast baseline branch | deferred redteam-lateral/path/value reasoning | split later | Branch combines baseline exposure with impact-tiering/value semantics. | Pulls attack-impact reasoning into AD baseline semantic authority. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (`ad_kerberoast_v1`, `ad_kerberoast_da_v1`) | AD-03/AD-23 coupling at path layer | deferred redteam-lateral/path/value reasoning | defer | Catalog still binds heuristic/value branches to path outcomes. | Canonical AD path layer becomes coupled to redteam framing before seam decomposition. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_delegation` (`AD-06..AD-09`) | delegation posture + freshness/reachability + sensitive-target coupling in one function | mixed: AD domain semantic normalization + deferred redteam-lateral/path/value reasoning | split later | AD-06/AD-08 baseline posture can be semantic; AD-07/AD-09 are context/path-coupled. | Premature migration drags runtime/context assumptions into AD domain semantics. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_unconstrained_delegation_v1` | AD-22 posture coupled into delegation chain | deferred redteam-lateral/path/value reasoning | defer | Delegation path currently requires coupled AD-22 posture from lateral path authority. | Reasserts legacy path coupling over canonical AD-22 slice. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_acls` (`AD-10..AD-15`) | ACL edge classes fused with high-value target classification and path framing | mixed: AD domain semantic normalization + deferred redteam-lateral/path/value reasoning | split later | Edge normalization is extractable; high-value/path semantics remain coupled to attack framing. | Canonical AD adapter would inherit path-priority assumptions and mixed authority. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_dcsync_accounts_enabled` (`AD-16`) | enabled-state gate tied to ACL-derived candidate set from same monolith | mixed: AD domain semantic normalization + service/runtime orchestration seam | split later | AD-16 depends on a prior path-coupled ACL extraction in same legacy flow. | Migrating directly would preserve monolithic dependency ordering and hidden coupling. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_adminsdholder` (`AD-19`, `AD-20`) | AdminSDHolder ACL semantics mixed with static SDProp assumption | mixed: AD domain semantic normalization + shared helper/governance concern | split later | AD-19 edge semantics are extractable; AD-20 is policy assumption and needs governance contract. | Canonical AD slice could hardcode static operational assumptions as evidence. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json::ad_acl_abuse_v1`, `ad_dcsync_v1`, `ad_adminsdholder_v1` | ACL/DCSync/AdminSDHolder paths are tightly coupled attack narratives | deferred redteam-lateral/path/value reasoning | defer | Path logic remains legacy lateral authority and not canonical AD baseline contracts. | Canonical AD projector/path authority would be contaminated by broad lateral coupling. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | broad path projector with fallback substrate imports and sheaf augmentation | deferred redteam-lateral/path/value reasoning | defer | Ownership remains legacy lateral projector; not canonical AD domain projector scope. | Mixed fallback projector behavior can bypass canonical AD projector governance. |

## Governance Artifact Extraction In This Pass

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg/sensors/adapter_runner.py` + `packages/skg-services/src/skg_services/gravity/ad_runtime.py` + `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/run.py` sidecar seam | `packages/skg-protocol/src/skg_protocol/contracts/ad_tiering_input.py` | shared helper/governance concern | extract now | Centralized schema id, filename, wicket id, and validation contract for `skg.ad.tiering_input.v1`. | Future schema version transitions still need explicit compatibility policy (`v1` -> `v2`). |
| `N/A (protocol export surface)` | `packages/skg-protocol/src/skg_protocol/contracts/__init__.py` | shared helper/governance concern | rewritten | Exposed sidecar governance contract through protocol public surface. | Export surface discipline required as more sidecar contracts are added. |
| `N/A (service runtime sidecar governance)` | `packages/skg-services/src/skg_services/gravity/ad_runtime.py` | service/runtime routing or orchestration | rewritten | Service now validates sidecar payload before write/use and fails closed on invalid contract. | Runtime drop behavior may hide AD-22 events when malformed sidecars appear; alerting policy should be formalized. |
| `N/A (runtime callsite governance)` | `skg/sensors/adapter_runner.py` | service/runtime routing or orchestration | rewritten | Uses protocol-governed sidecar filename constant to prevent drift. | Legacy callers outside this route can still reference hardcoded filenames. |
| `N/A (domain adapter governance)` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/run.py` | AD domain semantic normalization | rewritten | Domain adapter now validates sidecar contract and surfaces validation errors in `AD-TI-01` attributes. | Validation error policy is informational in domain events; runtime policy still decides fail-open/fail-closed behaviors. |
