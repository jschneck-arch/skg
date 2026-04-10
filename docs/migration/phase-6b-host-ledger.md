# Phase 6B Host Ledger

Date: 2026-04-02

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | `packages/skg-domains/host/src/skg_domain_host/adapters/host_ssh_assessment/run.py` | adapter | split | Extracted host-owned SSH semantic mapping (HO-01/02/03/06/10/12) into canonical domain adapter contract. | Legacy adapter still contains broader HO and context nodes not migrated in this pass. |
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | `packages/skg-domains/host/src/skg_domain_host/policies/ssh_adapter_policy.yaml` | policy | split | Pulled confidence/evidence/kernel-pattern policy into explicit artifact. | Policy values are conservative defaults; tuning may be required per environment. |
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | `packages/skg-services/src/skg_services/gravity/host_runtime.py` | service wrapper | split | Moved runtime SSH command execution ownership to services (`collect_ssh_session_assessment*`, `collect_ssh_assessment*`). | Wrapper currently captures a minimal runtime slice, not full legacy parity. |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | `packages/skg-domains/host/src/skg_domain_host/adapters/host_winrm_assessment/run.py` | adapter | split | Extracted host-owned WinRM semantic mapping (HO-04/05/09/10) into canonical domain adapter contract. | Legacy file has additional WinRM checks still deferred. |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | `packages/skg-domains/host/src/skg_domain_host/policies/winrm_adapter_policy.yaml` | policy | split | Externalized WinRM mapping policy and credential-indicator patterns. | Regex-only credential indicator may over/under-match in noisy env dumps. |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | `packages/skg-services/src/skg_services/gravity/host_runtime.py` | service wrapper | split | Moved WinRM runtime session execution ownership to services (`collect_winrm_session_assessment*`, `collect_winrm_assessment*`). | Wrapper currently focuses on auth/admin/env indicators; deeper package/service checks deferred. |
| `skg/sensors/adapter_runner.py` | `skg/sensors/adapter_runner.py` (`run_ssh_host`) | service wrapper | rewritten | Migrated active SSH runtime callsite from legacy adapter eval functions to canonical service wrapper path. | `adapter_runner` is still a legacy shim layer and should be reduced further in a later phase. |
| `skg/sensors/ssh_sensor.py` | `skg/sensors/ssh_sensor.py` (`_collect_winrm`) | service wrapper | rewritten | Replaced WinRM connectivity/auth event emission via legacy adapter symbols with canonical service wrapper mapping. | `_collect_winrm` still mixes host and APRS collection for now. |

## New Canonical Assets Added In Phase 6B

- `packages/skg-domains/host/src/skg_domain_host/adapters/host_ssh_assessment/__init__.py`
- `packages/skg-domains/host/src/skg_domain_host/adapters/host_ssh_assessment/run.py`
- `packages/skg-domains/host/src/skg_domain_host/adapters/host_winrm_assessment/__init__.py`
- `packages/skg-domains/host/src/skg_domain_host/adapters/host_winrm_assessment/run.py`
- `packages/skg-domains/host/src/skg_domain_host/policies/ssh_adapter_policy.yaml`
- `packages/skg-domains/host/src/skg_domain_host/policies/winrm_adapter_policy.yaml`
- `packages/skg-services/src/skg_services/gravity/host_runtime.py`
- `packages/skg-domains/host/tests/test_host_ssh_adapter_mapping.py`
- `packages/skg-domains/host/tests/test_host_winrm_adapter_mapping.py`
- `packages/skg-services/tests/test_host_runtime_wrappers.py`
