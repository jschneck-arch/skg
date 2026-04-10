# Phase 6A Deferred Domain Residue (host)

Date: 2026-04-02

## Deferred Legacy Files

| Legacy path | Classification | Why deferred | Exact next split/removal step |
|---|---|---|---|
| `skg-host-toolchain/adapters/ssh_collect/parse.py` | deferred | Mixed SSH runtime execution, command orchestration, host/domain semantics, and event emission in one module. | Split into service-owned SSH runtime collector + domain-owned semantic mapper(s) for resulting findings. |
| `skg-host-toolchain/adapters/winrm_collect/parse.py` | deferred | Runtime transport/auth orchestration mixed with host wicket mapping. | Extract WinRM runtime wrapper into services; move only mapping semantics to domain adapters. |
| `skg-host-toolchain/adapters/smb_collect/enum4linux_adapter.py` | deferred | Mixes runtime subprocess execution with host and `ad_lateral` semantic emission. | Split runtime execution to services and split host/ad semantics into their respective domain packs. |
| `skg-host-toolchain/adapters/msf_session/parse.py` | deferred | Depends on runtime session orchestration and post-exploitation state ownership. | Isolate MSF runtime/session collector in services and migrate only host-domain semantic mapping slice. |
| `skg-host-toolchain/adapters/sysaudit/audit.py` | deferred | Runtime-heavy local audit execution mixed with policy and event shaping. | Extract audit execution runtime wrapper first, then migrate normalized findings->event mapper to domain pack. |
| `skg-host-toolchain/adapters/nmap_scan/parse.py` (subprocess/XML portions) | deferred | Process execution and XML parsing are runtime concerns; only semantic mapping was migrated in Phase 6A. | Keep canonical mapper in domain pack; migrate execution/parsing wrappers to `skg-services` when host runtime convergence phase starts. |
| `skg-host-toolchain/projections/host/run.py` (legacy residue) | deferred | Contains legacy kernel/sheaf coupling and CLI wrapper behavior beyond canonical substrate projector. | Retire when all host runtime callsites use domain-pack projector through service wrappers. |

## Excluded As Canonical Source In This Phase

- `skg_deploy/**`
- `skg-gravity/**`
- `.claude/worktrees/**`
- `archive/**`

## Removal Readiness

- Ready now:
  - Domain semantics for nmap profile mapping and projector scoring run canonically in `skg-domain-host`.
- Not ready now:
  - Deleting deferred host runtime modules would break legacy runtime flows.
- Next controlled step:
  - Introduce service-owned host runtime wrappers (nmap execution + optional SSH/WinRM runners) that call canonical host domain adapters.
