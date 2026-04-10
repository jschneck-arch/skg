# Phase 6C Host Boundary Status

Date: 2026-04-02

## Current Boundary Ownership

### Service-owned runtime execution (active)

- `packages/skg-services/src/skg_services/gravity/host_runtime.py`
- Runtime ownership includes:
  - SSH command execution and session/runtime assessment
  - WinRM transport/auth execution and runtime assessment
  - Runtime-to-domain adapter handoff

### Domain-owned host semantics (active)

- `packages/skg-domains/host/src/skg_domain_host/adapters/host_ssh_assessment/run.py`
- `packages/skg-domains/host/src/skg_domain_host/adapters/host_winrm_assessment/run.py`
- `packages/skg-domains/host/src/skg_domain_host/projectors/host/run.py`
- `packages/skg-domains/host/src/skg_domain_host/policies/*.yaml`

### Legacy compatibility layer (reduced)

- `skg-host-toolchain/adapters/ssh_collect/parse.py` (wrapper)
- `skg-host-toolchain/adapters/winrm_collect/parse.py` (wrapper)
- `skg/sensors/adapter_runner.py::run_ssh_host` (bridge shim)
- `skg-host-toolchain/skg_host.py` still references the two legacy wrapper entrypoints

## Boundary Violations Closed in Phase 6C

1. Host WinRM/APRS runtime mixing removed from active host path.
- `skg/sensors/ssh_sensor.py::_collect_winrm` no longer performs APRS net-sandbox collection.
- Host WinRM flow now emits only canonical host-domain events via service wrapper.

2. Active SSH runtime bypass reduced.
- `skg/sensors/ssh_sensor.py::_collect_ssh` now calls canonical host service wrapper directly.
- `skg-gravity/gravity_field.py::_exec_ssh_sensor` now calls canonical host service wrapper directly.

3. Legacy host entrypoints no longer contain active mixed runtime semantics for migrated flows.
- `ssh_collect/parse.py` and `winrm_collect/parse.py` are reduced to compatibility wrappers.

## Remaining Deferred Residue

| Path | Deferred concern | Status |
|---|---|---|
| `skg-host-toolchain/adapters/smb_collect/enum4linux_adapter.py` | Host + AD-lateral semantic mixing | deferred |
| `skg-host-toolchain/adapters/msf_session/parse.py` | Post-exploitation runtime mixed with host semantics | deferred |
| `skg/sensors/adapter_runner.py::run_ssh_host` | Bridge shim still present for compatibility callers/tests | retained shim |

## Net Boundary Assessment

For migrated host SSH/WinRM flows, runtime ownership is now service-only and semantic ownership is domain-only. No active in-repo production callsite bypasses canonical service/domain boundaries for these flows.
