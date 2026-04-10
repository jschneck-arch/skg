# Phase 7J AD Seam Split Ledger

Date: 2026-04-02

## Scope

- `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`
- `skg/sensors/bloodhound_sensor.py`
- `skg/sensors/adapter_runner.py`
- `skg-gravity/adapters/ldap_enum.py`
- `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json`
- `skg-ad-lateral-toolchain/projections/lateral/run.py` (classification only)
- AD-03 / AD-23 reassessment in `bloodhound/parse.py` and ad-lateral catalog

## Seam Analysis Ledger

| Legacy path | Seam/slice identified | Ownership classification | Recommended action | Rationale | Risk if migrated prematurely |
|---|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_stale_privileged` | AD-22 branch emits unconditional `unknown` with static note only | mixed: AD domain semantic normalization + service/runtime dependency gap | split later | AD-22 semantic intent exists, but branch has no session evidence path and no tiering evaluation logic. | Migrating this branch directly would codify a permanent `unknown` semantic and block meaningful canonical AD-22 behavior. |
| `skg/sensors/bloodhound_sensor.py` (`da_sessions` query + `sessions.json` write) | privileged-session collection and serialization for AD-22 evidence | service/runtime parser or orchestration behavior | split later | Runtime collector obtains session evidence but does not define canonical AD semantics. | Pulling this code into AD domain would violate runtime/domain boundaries and reintroduce collector coupling. |
| `skg/sensors/adapter_runner.py::run_bloodhound` | runtime call graph ignores `sessions` payload for AD-22 | service/runtime parser or orchestration behavior | split later | Runtime bridge invokes legacy checks that cannot consume the session dataset. | Canonical AD-22 migration would appear complete while active runtime path remains disconnected from required evidence. |
| `skg-gravity/adapters/ldap_enum.py` (`wicket_id=AD-22` on user enumeration) | conflicting AD-22 implementation (`domain user accounts enumerable`) | deferred redteam-lateral/path/value reasoning + service/runtime contamination | defer | Implementation semantics conflict with catalog AD-22 definition and are embedded in runtime adapter with path hacks. | Adopting this branch would corrupt canonical AD-22 meaning and import non-canonical runtime behavior. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (`AD-22`, `ad_unconstrained_delegation_v1`, `ad_laps_absent_v1`) | AD-22 is coupled into path/value attack narratives and cross-slice requirements | deferred redteam-lateral/path/value reasoning | split later | Catalog combines tiering posture with delegation and LAPS path goals rather than isolating AD-22 baseline semantics. | Migrating coupled paths would leak redteam path authority into AD domain slice boundaries. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | broad path projector with fallback substrate imports | deferred broad projector semantics | defer | Projector remains legacy path-centric and not canonical AD projector authority. | Canonical AD projector boundaries would be polluted by ad-lateral fallback and path-coupled semantics. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` (reassessed after AD-22) | AD-03 detection-absence heuristic + AD-23 DA-impact branch remain fused with AD-01/02 baseline | deferred redteam-lateral/path/value reasoning | defer | Seam still mixes baseline exposure with heuristic and value-impact semantics. | Premature migration would reintroduce mixed authority and path/value coupling into canonical AD. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (`ad_kerberoast_v1`, `ad_kerberoast_da_v1`) | AD-03/AD-23 remain coupled at path layer | deferred redteam-lateral/path/value reasoning | defer | Path definitions still bind heuristic/value branches to baseline flow. | Canonical AD slice isolation for Kerberoast derivatives would regress. |

## Safe Helper Extraction Performed

| Legacy semantic origin | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `bloodhound_sensor.py` DA session row shape + `bloodhound/parse.py` AD-22 intent (`sessions`-driven tiering posture) | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/tiering_semantics.py` | shared/cross-domain helper | extracted now | Isolated source-agnostic session normalization and tier classification summary primitives without migrating runtime collectors or full AD-22 slice logic. | Tier model is currently DC-vs-non-DC only; richer tier policy (tier-0 asset classes) remains future work. |
| `N/A` | `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/__init__.py` | helper export | rewritten | Added tiering helper exports for controlled future AD-22 slice migration. | Export surface must remain synchronized with helper evolution. |
| `N/A` | `packages/skg-domains/ad/tests/test_ad_tiering_semantics_helpers.py` | tests | added | Added helper-level tests for session normalization, computer tier index, and baseline tiering summary status behavior. | Tests validate semantic primitives only; no runtime/session ingestion integration yet. |

## AD-22 Split Outcome

- AD-22 semantic core can be expressed as:
  - privileged-session evidence observed
  - privileged sessions present on non-tier0 hosts (`realized`) vs absent (`blocked`) vs unresolved (`unknown`)
- Runtime evidence plumbing (collector -> runner -> canonical adapter input) is still unresolved.
- Full AD-22 slice migration is not safe yet without one focused runtime seam split.
