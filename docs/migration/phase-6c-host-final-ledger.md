# Phase 6C Host Final Ledger

Date: 2026-04-02

## Changed Items

| Legacy path | New or retained canonical path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg/sensors/ssh_sensor.py` (`_collect_ssh`) | `skg_services.gravity.host_runtime.collect_ssh_session_assessment(...)` | service wrapper | rewritten | Removed dependency on `adapter_runner.run_ssh_host`; active SSH sensor path now calls canonical service runtime wrapper directly. | Requires `skg_services` package availability at runtime; sensor logs and returns empty list if unavailable. |
| `skg/sensors/ssh_sensor.py` (`_collect_winrm`) | `skg_services.gravity.host_runtime.collect_winrm_assessment(...)` | service wrapper | rewritten | Removed mixed host+APRS behavior (`run_net_sandbox`) from WinRM host path; host flow now emits only canonical host-domain events. | Legacy behavior that appended APRS events is intentionally removed; APRS must run through APRS-owned paths. |
| `skg-gravity/gravity_field.py` (`_exec_ssh_sensor`) | `skg_services.gravity.host_runtime.collect_ssh_session_assessment_to_file(...)` | service wrapper | rewritten | Gravity SSH runtime callsite now uses canonical services directly instead of `adapter_runner` bridge. | Global gravity module still has broader legacy coupling outside host scope. |
| `skg/sensors/adapter_runner.py` (`run_ssh_host`) | retained bridge to `skg_services.gravity.host_runtime.collect_ssh_session_assessment_to_file(...)` | bridge | reduced | Marked as compatibility bridge only; no active in-repo host runtime callsite requires it after this phase. | Root-level regression tests still exercise this shim; deletion deferred to controlled fallback-removal wave. |
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | compatibility wrapper -> `collect_ssh_assessment_to_file(...)` | bridge | reduced | Replaced mixed legacy adapter implementation with explicit canonical delegation wrapper. | External consumers (and legacy launcher `skg-host-toolchain/skg_host.py`) that imported removed helper symbols must migrate to canonical APIs. |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | compatibility wrapper -> `collect_winrm_assessment_to_file(...)` | bridge | reduced | Replaced mixed legacy adapter implementation with explicit canonical delegation wrapper. | External consumers (and legacy launcher `skg-host-toolchain/skg_host.py`) that imported removed helper symbols must migrate to canonical APIs. |
| `packages/skg-services/tests/test_host_runtime_wrappers.py` | same path | service wrapper | rewritten | Added convergence test proving `_collect_winrm` routes only through canonical host service wrapper and static assertions for no APRS bypass and wrapper reduction. | Static assertions guard callsite drift but do not validate external tooling behavior. |

## Active Host Runtime Callsites After Phase 6C

- `skg/sensors/ssh_sensor.py::_collect_ssh` -> `skg_services.gravity.host_runtime.collect_ssh_session_assessment`
- `skg/sensors/ssh_sensor.py::_collect_winrm` -> `skg_services.gravity.host_runtime.collect_winrm_assessment`
- `skg-gravity/gravity_field.py::_exec_ssh_sensor` -> `skg_services.gravity.host_runtime.collect_ssh_session_assessment_to_file`

## Explicitly Deferred (Out of Scope/Still Ambiguous)

- `skg-host-toolchain/adapters/smb_collect/enum4linux_adapter.py` (host + AD-lateral mixing)
- `skg-host-toolchain/adapters/msf_session/parse.py` (post-exploitation runtime + semantic mixing)
