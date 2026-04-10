# Phase 6C Host Template Readiness

Date: 2026-04-02

## Readiness Criteria

| Criterion | Status | Evidence |
|---|---|---|
| Active host runtime callsites use canonical service wrappers | PASS | `ssh_sensor` and `gravity_field` now call `skg_services.gravity.host_runtime` directly for migrated SSH/WinRM flows. |
| Host WinRM path no longer mixes APRS in active host flow | PASS | `ssh_sensor._collect_winrm` no longer appends `run_net_sandbox(...)` events. |
| Domain pack remains semantic source of truth | PASS | Service wrappers still map through `skg_domain_host` adapters + explicit host policies. |
| Legacy host entrypoints are reduced to compatibility-only wrappers | PASS | `ssh_collect/parse.py` and `winrm_collect/parse.py` now delegate to canonical service wrappers. |
| No active in-repo production callsite requires legacy host parse modules for migrated flows | PASS | Static callsite assertions in `packages/skg-services/tests/test_host_runtime_wrappers.py`. |
| Required service-level convergence coverage added | PASS | Added test covering WinRM runtime convergence + APRS separation guard. |

## Residual Non-Blocking Risks

- Compatibility wrappers can still be called externally and should be retired on a controlled schedule.
- Cross-domain mixed modules (`smb_collect`, `msf_session`) are still deferred and must stay out of host canonical semantics.
- `adapter_runner.run_ssh_host` remains as a dormant compatibility shim until fallback deletion wave.

## Recommendation

Host is template-ready. AD migration can begin, with `smb_collect`/`msf_session` explicitly scoped as corrective split prerequisites if those flows are selected.
