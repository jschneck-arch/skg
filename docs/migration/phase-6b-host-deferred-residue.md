# Phase 6B Host Deferred Residue

Date: 2026-04-02

## Retained Deferred Files/Concerns

| Legacy path | Classification | Why retained | Exact next step |
|---|---|---|---|
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | deferred | Contains many additional mixed runtime + semantic checks beyond migrated canonical slice. | Convert to explicit compatibility wrapper or retire after remaining HO semantic slices migrate to domain adapters. |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | deferred | Contains deeper Windows package/process/task checks mixed with runtime execution. | Extract remaining host semantic mappings to domain adapters; keep runtime collection in service wrappers. |
| `skg-host-toolchain/adapters/smb_collect/enum4linux_adapter.py` | deferred | Mixes host and AD-lateral semantics in one runtime adapter. | Perform explicit host/ad-lateral split before any migration of this flow. |
| `skg-host-toolchain/adapters/msf_session/parse.py` | deferred | Post-exploitation runtime and host semantics are still coupled. | Create service-owned MSF session wrapper, then split domain semantic mapping. |
| `skg/sensors/ssh_sensor.py` (`_collect_winrm` APRS branch) | deferred | Host and APRS collection remain co-located for legacy compatibility. | Move APRS branch behind explicit APRS service path and keep host branch canonical. |

## What Is No Longer Deferred For Migrated Slice

- SSH initial-access + selected host runtime semantics (HO-01/02/03/06/10/12) are canonicalized.
- WinRM connectivity/auth/admin/env semantics (HO-04/05/09/10) are canonicalized.

## Current Risk Profile

- Medium risk: semantic drift if legacy adapters continue to be edited while canonical adapters evolve.
- Low risk for migrated runtime callsites validated in Phase 6B tests.
