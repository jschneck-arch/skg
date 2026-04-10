# Phase 6C Host Wrapper Retirement

Date: 2026-04-02

## Wrapper Retirement/Reduction Decisions

| Legacy file/symbol | Decision | Current state | Rationale | Future removal trigger |
|---|---|---|---|---|
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | REDUCED + RETAINED | Thin compatibility CLI wrapper delegates to `skg_services.gravity.host_runtime.collect_ssh_assessment_to_file`; legacy toolchain launcher `skg-host-toolchain/skg_host.py` still references this entrypoint. | In-repo production runtime callers are migrated; wrapper retained for temporary external + legacy launcher compatibility only. | Remove in next controlled fallback-deletion wave after compatibility window and no external dependency reports. |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | REDUCED + RETAINED | Thin compatibility CLI wrapper delegates to `skg_services.gravity.host_runtime.collect_winrm_assessment_to_file`; legacy toolchain launcher `skg-host-toolchain/skg_host.py` still references this entrypoint. | In-repo production runtime callers are migrated; wrapper retained for temporary external + legacy launcher compatibility only. | Remove in next controlled fallback-deletion wave after compatibility window and no external dependency reports. |
| `skg/sensors/adapter_runner.py::run_ssh_host` | RETAINED (dormant bridge) | Compatibility shim still delegates to canonical host service wrapper. | No active production host runtime callsite uses it after this phase; retained to avoid abrupt break for legacy importers/tests. | Remove when root regression callers are migrated and shim-usage telemetry remains zero. |

## Runtime Callsite Retirements Completed

- Retired active `ssh_sensor` dependency on `adapter_runner.run_ssh_host`.
- Retired active host WinRM APRS append path (`run_net_sandbox`) in `ssh_sensor`.
- Retired active gravity SSH dependency on `adapter_runner.run_ssh_host`.

## Retained Compatibility Surface (Intentional)

- `skg-host-toolchain/adapters/ssh_collect/parse.py` (wrapper only)
- `skg-host-toolchain/adapters/winrm_collect/parse.py` (wrapper only)
- `skg/sensors/adapter_runner.py::run_ssh_host` (compat shim, no active production caller)
