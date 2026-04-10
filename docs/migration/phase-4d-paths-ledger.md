# Phase 4D Paths Ledger

Date: 2026-04-01  
Scope: normalize path/config ownership across `skg-core`, `skg-services`, and the legacy compatibility shim.

## Ownership Classification

| Legacy symbol (`skg.core.paths`) | Ownership class | Canonical replacement | Migrated callers (active tree) | Retained callers (non-canonical trees) | Removal readiness | Rationale |
|---|---|---|---|---|---|---|
| `SKG_HOME` | core primitive | `skg_core.config.paths.SKG_HOME` | `19` active callers now on core primitives (see callsite map) | `skg-gravity/cred_reuse.py`, `skg-gravity/gravity_field.py`, `skg_deploy/...` | `MEDIUM` | Root path primitive is package-neutral; no runtime policy ownership. |
| `SKG_STATE_DIR` | core primitive | `skg_core.config.paths.SKG_STATE_DIR` | `34` active callers migrated | `skg-data-toolchain/adapters/db_profiler/profile.py`, `skg-gravity/...`, `skg_deploy/...` | `MEDIUM` | Canonical state root belongs to core substrate/config primitives. |
| `SKG_CONFIG_DIR` | core primitive | `skg_core.config.paths.SKG_CONFIG_DIR` | `17` active callers migrated | `skg-gravity/...`, `skg_deploy/...` | `MEDIUM` | Config root is package-neutral and used by protocol-neutral consumers. |
| `EVENTS_DIR` | core primitive | `skg_core.config.paths.EVENTS_DIR` | `16` active callers migrated | `skg-gravity/...`, `skg_deploy/...` | `MEDIUM` | Measurement plane event storage path is canonical substrate primitive. |
| `INTERP_DIR` | core primitive | `skg_core.config.paths.INTERP_DIR` | `12` active callers migrated | `skg-gravity/gravity_field.py`, `skg_deploy/...` | `MEDIUM` | Interpretation plane output path is canonical substrate primitive. |
| `DISCOVERY_DIR` | core primitive | `skg_core.config.paths.DISCOVERY_DIR` | `8` active callers migrated | `skg-gravity/...`, `skg_deploy/skg/intel/...` | `MEDIUM` | Observation/discovery persistence path is canonical primitive. |
| `DELTA_DIR` | core primitive | `skg_core.config.paths.DELTA_DIR` | `8` active callers migrated | `skg_deploy/skg/intel/...` | `MEDIUM` | Temporal transition storage belongs in core temporal/config primitive set. |
| `GRAPH_DIR` | core primitive | `skg_core.config.paths.GRAPH_DIR` | Exported canonical primitive; used by shim currently | none outside shim | `HIGH` | Graph substrate state path is kernel/core-owned. |
| `PROPOSALS_DIR` | core primitive | `skg_core.config.paths.PROPOSALS_DIR` | Exported canonical primitive; used by shim currently | none outside shim | `HIGH` | Proposal storage primitive is neutral core state partition. |
| `CVE_DIR` | service policy | `skg_services.gravity.path_policy.CVE_DIR` | `skg/cli/commands/intelligence.py`, `skg/cli/commands/report.py`, `skg/cli/utils.py` | none in active trees; legacy usage only in `skg_deploy/...` | `MEDIUM` | CVE cache/output is runtime policy, not substrate primitive. |
| `FORGE_STAGING` | service policy | `skg_services.gravity.path_policy.FORGE_STAGING` | `skg/forge/generator.py` | none in active trees | `HIGH` | Forge staging is service-owned orchestration state. |
| `RESONANCE_DIR` | service policy | `skg_services.gravity.path_policy.RESONANCE_DIR` | `skg/resonance/cli.py`, `skg/cli/utils.py`, `skg/core/daemon.py` | `skg_deploy/skg/resonance/cli.py`, `skg_deploy/skg/core/daemon.py` | `MEDIUM` | Resonance runtime memory is service layer state, not core substrate. |
| `IDENTITY_FILE` | service policy | `skg_services.gravity.path_policy.IDENTITY_FILE` | `skg/core/daemon.py`, `skg/cli/commands/system.py`, `skg/cli/utils.py` | `skg_deploy/skg/core/daemon.py` | `MEDIUM` | Daemon journal file location is runtime policy. |
| `LOG_FILE` | service policy | `skg_services.gravity.path_policy.LOG_FILE` | `skg/core/daemon.py` | `skg_deploy/skg/core/daemon.py` | `MEDIUM` | Service log path is orchestration/runtime concern. |
| `PID_FILE` | service policy | `skg_services.gravity.path_policy.PID_FILE` | `skg/core/daemon.py` | `skg_deploy/skg/core/daemon.py` | `MEDIUM` | Daemon process file is service runtime concern. |
| `ensure_runtime_dirs` | service policy (with core delegation) | `skg_services.gravity.path_policy.ensure_runtime_dirs` | `skg/core/daemon.py` | `skg_deploy/skg/core/daemon.py` | `MEDIUM` | Runtime directory materialization is orchestration-owned; shim now delegates to canonical core+service directory creation. |
| `TOOLCHAIN_DIR` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.TOOLCHAIN_DIR` (transitional) | `skg/core/daemon.py` | `skg_deploy/skg/core/daemon.py` | `LOW` | Layout-specific toolchain mirrors are not canonical architecture; retained only for controlled compatibility. |
| `CE_TOOLCHAIN_DIR` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.CE_TOOLCHAIN_DIR` (transitional) | `skg/core/daemon.py` | `skg_deploy/skg/core/daemon.py` | `LOW` | Same as above; install-shape compatibility only. |
| `AD_TOOLCHAIN_DIR` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.AD_TOOLCHAIN_DIR` (transitional) | `skg/core/daemon.py` | `skg_deploy/skg/core/daemon.py` | `LOW` | Same as above; install-shape compatibility only. |
| `HOST_TOOLCHAIN_DIR` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.HOST_TOOLCHAIN_DIR` (transitional) | `skg/core/daemon.py` | `skg_deploy/skg/core/daemon.py` | `LOW` | Same as above; install-shape compatibility only. |
| `WEB_TOOLCHAIN_DIR` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.WEB_TOOLCHAIN_DIR` (transitional) | none in active runtime callsites | none outside shim | `LOW` | Retained only as compatibility export in shim/policy module. |
| `MSF_DIR` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.MSF_DIR` (transitional) | none in active runtime callsites | none outside shim | `LOW` | External tool mount path is service/deployment policy; not core primitive. |
| `BH_DIR` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.BH_DIR` (transitional) | none in active runtime callsites | none outside shim | `LOW` | Same as above; deployment-specific service policy. |
| `RESONANCE_INDEX`, `RESONANCE_RECORDS`, `RESONANCE_DRAFTS` | legacy compatibility only (service shim namespace) | `skg_services.gravity.path_policy.RESONANCE_INDEX|RESONANCE_RECORDS|RESONANCE_DRAFTS` (transitional) | none in active runtime callsites | none outside shim | `LOW` | Internal resonance layout constants are retained only for compatibility exports. |

## Canonicalization Actions Applied

- Expanded core primitive surface in [`packages/skg-core/src/skg_core/config/paths.py`](/opt/skg/packages/skg-core/src/skg_core/config/paths.py).
- Expanded service path policy in [`packages/skg-services/src/skg_services/gravity/path_policy.py`](/opt/skg/packages/skg-services/src/skg_services/gravity/path_policy.py).
- Reduced [`skg/core/paths.py`](/opt/skg/skg/core/paths.py) to explicit compatibility delegation; removed standalone path resolution logic from shim.
- Migrated active runtime callsites off `skg.core.paths` (full path map in `phase-4d-paths-callsite-map.md`).
