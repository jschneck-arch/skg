# Phase 6B Host Boundaries

Date: 2026-04-02

## Boundary Decisions Applied

1. Services own runtime execution for migrated host flows.
- Runtime transport/execution now lives in:
  - `packages/skg-services/src/skg_services/gravity/host_runtime.py`
- Includes:
  - SSH command execution for runtime facts (`id`, `sudo -l`, `uname -r`)
  - WinRM command execution for runtime facts (`whoami /groups`, env snapshot)

2. Host domain owns semantics and policy.
- Semantic mapping is domain-owned:
  - `packages/skg-domains/host/src/skg_domain_host/adapters/host_ssh_assessment/run.py`
  - `packages/skg-domains/host/src/skg_domain_host/adapters/host_winrm_assessment/run.py`
- Explicit policy artifacts:
  - `packages/skg-domains/host/src/skg_domain_host/policies/ssh_adapter_policy.yaml`
  - `packages/skg-domains/host/src/skg_domain_host/policies/winrm_adapter_policy.yaml`

3. Legacy host adapter symbols are no longer active for migrated flows.
- `run_ssh_host` no longer imports `skg-host-toolchain/adapters/ssh_collect/parse.py`.
- WinRM connectivity/auth events in `ssh_sensor` no longer call legacy `eval_ho04_winrm_exposed`/`eval_ho05_winrm_credential`.

4. Cross-domain ambiguity remains deferred.
- Host consolidation did not pull SMB/AD-lateral mixed semantics into host pack.
- APRS-specific WinRM collection (`run_net_sandbox`) remains separate and deferred.

## Closed Boundary Violations

- Runtime/semantic mixing for migrated SSH and WinRM slices is now split along service/domain ownership.
- Host semantic mapping no longer depends on legacy adapter module internals.

## Remaining Boundary Risks

| Path | Risk | Status |
|---|---|---|
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | Large mixed legacy file still exists and can drift from canonical semantic contract. | deferred |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | Large mixed legacy file still exists and can drift from canonical semantic contract. | deferred |
| `skg/sensors/ssh_sensor.py` | WinRM path still appends APRS collection in same sensor flow, preserving mixed runtime concerns. | deferred |
| `skg-host-toolchain/adapters/smb_collect/enum4linux_adapter.py` | Host+AD-lateral mixed semantics unresolved. | deferred |
