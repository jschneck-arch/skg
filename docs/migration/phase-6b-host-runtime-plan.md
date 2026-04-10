# Phase 6B Host Runtime Plan

Date: 2026-04-02

## Runtime Convergence Achieved In Phase 6B

### Active canonical runtime path for migrated SSH flow
- `skg/sensors/adapter_runner.py::run_ssh_host`
  - now calls `skg_services.gravity.host_runtime.collect_ssh_session_assessment_to_file`
  - which invokes canonical domain adapter mapping:
    - `skg_domain_host.adapters.host_ssh_assessment.run.map_ssh_assessments_to_events`

### Active canonical runtime path for migrated WinRM connectivity/auth slice
- `skg/sensors/ssh_sensor.py::_collect_winrm`
  - now calls `skg_services.gravity.host_runtime.collect_winrm_session_assessment`
  - which invokes canonical domain adapter mapping:
    - `skg_domain_host.adapters.host_winrm_assessment.run.map_winrm_assessments_to_events`

## Legacy Dependence Reduced

- Removed live dependency on:
  - `skg-host-toolchain/adapters/ssh_collect/parse.py` for active `run_ssh_host` path
  - `eval_ho04_winrm_exposed` / `eval_ho05_winrm_credential` symbols from legacy host adapter internals

## Remaining Runtime Work (Next Host Cleanup Pass)

1. Split remaining deep host runtime facts from legacy SSH adapter.
- Candidate: map additional HO wickets through domain adapters from service-collected snapshots.

2. Separate WinRM host flow from APRS mixed collection path in `ssh_sensor`.
- Keep host-runtime wrapper host-owned; route APRS collection via explicit APRS service path.

3. Decide wrapper retirement wave.
- Option A: keep `adapter_runner.run_ssh_host` as compatibility shim (current state).
- Option B: migrate direct callers to `skg_services.gravity.host_runtime` and retire shim.

## Deletion Readiness (Current)

- Not ready to delete legacy adapter files wholesale.
- Ready to enforce canonical service/domain path for migrated SSH+WinRM slices (now active).
