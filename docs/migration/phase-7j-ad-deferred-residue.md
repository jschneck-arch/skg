# Phase 7J AD Deferred Residue

Date: 2026-04-02

## Deferred Residue After AD-22 Seam Pass

| Legacy path | Deferred seam | Classification | Why deferred | Exact future step |
|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_stale_privileged` AD-22 branch | static `unknown` emission for tiering | service/runtime dependency gap + mixed semantics | Branch does not consume session evidence and cannot produce canonical AD-22 posture states. | Replace with canonical adapter path once runtime session routing seam is corrected. |
| `skg/sensors/adapter_runner.py::run_bloodhound` | sessions are not passed into AD-22 semantic evaluation | service/runtime parser or orchestration | Runtime path still executes legacy checks without AD-22 evidence input. | Add canonical runtime wrapper path that supplies sessions + computer inventory to canonical AD adapter. |
| `skg/sensors/bloodhound_sensor.py` (`sessions.json` write) | collector output remains disconnected from canonical AD-22 semantics | service/runtime parser or orchestration | Session evidence exists but is not wired into canonical semantics. | Keep collector in services; route outputs through canonical contracts/registry boundaries. |
| `skg-gravity/adapters/ldap_enum.py` (`wicket_id=AD-22`) | conflicting AD-22 semantic meaning | deferred redteam-lateral/path/value reasoning + runtime contamination | Uses AD-22 for broad account enumeration and host-domain payload mismatch. | Retire or quarantine this AD-22 branch behind legacy shim; do not treat as canonical source. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` (`AD-22` in `ad_unconstrained_delegation_v1`, `ad_laps_absent_v1`) | path/value coupling | deferred redteam-lateral/path/value reasoning | AD-22 is embedded as attack-path prerequisite, not isolated baseline slice. | Define canonical AD attack path for AD-22 core independently from delegation/LAPS path coupling. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | broad ad-lateral projector ownership | deferred broad projector semantics | Projector remains path-centric and fallback-driven. | Revisit only after AD-22 canonical slice and runtime seam convergence are complete. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py::check_kerberoastable` AD-03/AD-23 branches | mixed heuristic/value coupling | deferred redteam-lateral/path/value reasoning | Reassessment confirms unresolved mixed semantics after AD-22 analysis. | Keep deferred until dedicated AD-03 and AD-23 corrective split/migration decision. |

## Newly Extracted Helper In This Phase

- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/tiering_semantics.py`
- `packages/skg-domains/ad/tests/test_ad_tiering_semantics_helpers.py`

No full new AD semantic slice was migrated in Phase 7J.
