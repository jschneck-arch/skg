# Migration Plan

Status: execution-grade phased plan.

## Phase 1: Freeze and Classify
- Objective: lock canonical baseline and prevent authority drift.
- Affected: `/opt/skg/skg`, `/opt/skg/skg-gravity`, `/opt/skg/skg-*-toolchain`, `/opt/skg/skg_deploy`, `/opt/skg/forge_staging`, `/opt/skg/*backup`.
- Expected output:
  - `docs/migration/repo-classification.md`
  - `archive/migration_snapshots/phase1/*`
- Risks: mirror tree accidentally edited as canonical.
- Validation:
  - `git status --porcelain`
  - `rg -n --hidden -S "sys.path.insert|/opt/skg|PYTHONPATH" /opt/skg/skg /opt/skg/skg-gravity /opt/skg/bin /opt/skg/scripts`
- Rollback/archive: restore from phase tag and archive snapshot bundle.

## Phase 2: Extract Core/Protocol/Registry Skeleton
- Objective: create clean package boundaries before code movement.
- Affected: `packages/skg-core`, `packages/skg-protocol`, `packages/skg-registry`, plus service/domain/legacy roots.
- Expected output: package skeletons with `src/` and readme/metadata placeholders.
- Risks: import path instability while dual trees coexist.
- Validation: `python -m compileall /opt/skg/packages/skg-core /opt/skg/packages/skg-protocol /opt/skg/packages/skg-registry`
- Rollback/archive: drop skeleton commit and restore tag.

## Phase 3: Migrate Canonical Substrate Pieces
- Objective: move minimal viable substrate to core; contracts to protocol; discovery to registry.
- Affected:
  - Core candidates: `skg/substrate/*`, `skg/kernel/{state,support,observations,projections,contexts,reason,identities,pearls}.py`, `skg/identity/__init__.py`, `skg/temporal/{__init__,interp}.py`, `skg/graph/__init__.py`.
  - Split-required: `skg/core/paths.py`, `skg/temporal/feedback.py`, `skg/sensors/projector.py`.
  - Registry: `skg/core/domain_registry.py`.
  - Protocol: event/contract primitives from `skg/sensors/__init__.py` + assistant contract from `skg/core/assistant_contract.py`.
- Expected output:
  - `packages/skg-core/src/skg_core/...`
  - `packages/skg-protocol/src/skg_protocol/...`
  - `packages/skg-registry/src/skg_registry/...`
- Risks: latent daemon/gravity dependencies in migrated files.
- Validation:
  - `pytest -q /opt/skg/tests/test_runtime_regressions.py`
  - `rg -n "from .*domains|import .*domains" /opt/skg/packages/skg-core /opt/skg/packages/skg-protocol`
- Rollback/archive: keep legacy source live until phase 9 cutover.

## Phase 4: Create Domain Skeletons
- Objective: establish first-class domain package layout.
- Affected: `packages/skg-domains/*`.
- Expected output: one directory per target domain with `domain.yaml`, `contracts`, `adapters`, `projectors`, `policies`, `fixtures`, `examples`, `tests`.
- Risks: naming mismatch with current toolchain roots.
- Validation: `find /opt/skg/packages/skg-domains -maxdepth 3 -name domain.yaml | sort`
- Rollback/archive: remove scaffold dirs and restore from tag.

## Phase 5: Migrate First Domain Cleanly
- Objective: prove clean extraction pipeline on one domain (start with host).
- Affected: `/opt/skg/skg-host-toolchain/**` -> `packages/skg-domains/host/**`; registry domain registration.
- Expected output: host domain bundle with compatibility shim at old CLI entrypoint.
- Risks: adapter runtime regressions, projector output drift.
- Validation:
  - `pytest -q /opt/skg/skg-host-toolchain/tests/test_golden.py`
  - `pytest -q /opt/skg/tests/test_sensor_projection_loop.py -k host`
- Rollback/archive: retain archived original host toolchain and shim rollback path.

## Phase 6: Rebuild Gravity on Registry/Contracts
- Objective: replace gravity monolith with service runtime that consumes public contracts through registry.
- Affected:
  - `skg-gravity/gravity_field.py`
  - `skg/gravity/*`
  - `skg/core/daemon.py` gravity API hooks
  - `skg/cli/commands/gravity.py`
- Expected output:
  - `packages/skg-services/gravity/{planning,runtime,instruments,state}`
- Risks: scheduling/selection behavior drift; hidden projector bypass remains.
- Validation:
  - `pytest -q /opt/skg/tests/test_gravity_runtime.py /opt/skg/tests/test_gravity_routing.py`
  - `rg -n "sys.path.insert|spec_from_file_location|project_event_file" /opt/skg/packages/skg-services/gravity`
- Rollback/archive: maintain fallback toggle to legacy gravity until parity complete.

## Phase 7: Integrate Claw as Service Harness
- Objective: extract exploit/runtime execution into harness service (Claw).
- Affected:
  - `skg/cli/commands/{proposals,exploit}.py`
  - `skg/cli/msf.py`
  - `skg-gravity/exploit_dispatch.py`
  - `skg-gravity/adapters/impacket_post.py`
- Expected output:
  - `packages/skg-services/harness/claw-runtime`
  - `packages/skg-services/harness/claw-bridge`
  - `packages/skg-services/harness/claw-cli`
- Risks: approval-gate regressions; action lifecycle corruption.
- Validation:
  - `pytest -q /opt/skg/tests/test_cli_commands.py -k "proposals or exploit"`
- Rollback/archive: keep compatibility wrappers until harness path is stable.

## Phase 8: Move Leftovers to Legacy or Archive
- Objective: quarantine deprecated/ambiguous runtime paths.
- Affected:
  - Legacy candidates: `skg-gravity/{gravity.py,gravity_web.py,exploit_proposals.py}`
  - Archive candidates: `skg_deploy/**`, `forge_staging/**`, `*.backup/**`, generated mirrors.
- Expected output:
  - `packages/skg-legacy/**`
  - `archive/**`
- Risks: hidden references to quarantined paths.
- Validation: `rg -n "skg_deploy|forge_staging|gravity_web|exploit_proposals|\.backup" /opt/skg/packages /opt/skg/skg /opt/skg/skg-gravity`
- Rollback/archive: move paths back from archive/legacy if blocked.

## Phase 9: Final Validation and Cutover
- Objective: verify boundary compliance and runtime parity, then cut over.
- Affected: all package layers, docs, wrappers.
- Expected output:
  - final architecture docs
  - cutover wrappers from old paths to new packages
- Risks: residual path hacks/import bypasses.
- Validation:
  - `python -m compileall /opt/skg/packages`
  - `pytest -q /opt/skg/tests`
  - `rg -n "sys.path.insert|spec_from_file_location|/opt/skg|PYTHONPATH" /opt/skg/packages`
  - `rg -n "from .*domains|import .*domains" /opt/skg/packages/skg-core /opt/skg/packages/skg-protocol`
- Rollback/archive: cutover only after passing gate; rollback to pre-cutover tag.
