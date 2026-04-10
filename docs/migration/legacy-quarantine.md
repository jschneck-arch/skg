# Legacy Quarantine Plan

Status: temporary quarantine map for non-canonical or compatibility-only material.

## Rules

- Quarantine means "removed from canonical runtime path", not immediate deletion.
- Quarantined code must not be imported by `skg-core`, `skg-protocol`, `skg-registry`, or active services.
- Each quarantined item needs an exit condition: migrate, rewrite, or archive permanently.

## Move to `packages/skg-legacy`

| Source Path | Target Path | Why |
|---|---|---|
| `/opt/skg/skg-gravity/gravity.py` | `packages/skg-legacy/gravity/gravity.py` | Explicit compatibility shim only. |
| `/opt/skg/skg-gravity/gravity_web.py` | `packages/skg-legacy/gravity/gravity_web.py` | Legacy bond sidecar model. |
| `/opt/skg/skg-gravity/exploit_proposals.py` | `packages/skg-legacy/gravity/exploit_proposals.py` | Sidecar proposal queue outside canonical lifecycle. |
| `/opt/skg/skg/core/daemon_registry.py` | `packages/skg-legacy/runtime/daemon_registry.py` | Private cross-layer hook pending API rewrite. |

## Move to `archive`

| Source Path | Target Path | Why |
|---|---|---|
| `/opt/skg/skg_deploy` | `archive/deploy-mirror/skg_deploy` | Deploy mirror; non-canonical runtime authority. |
| `/opt/skg/forge_staging` | `archive/staging/forge_staging` | Generated/staging artifacts. |
| `/opt/skg/skg-web-toolchain.backup` | `archive/backups/toolchains/skg-web-toolchain.backup` | Backup tree only. |
| `/opt/skg/skg-nginx-toolchain.backup` | `archive/backups/toolchains/skg-nginx-toolchain.backup` | Backup tree only. |
| `/opt/skg/skg-gravity/gravity_field.py.pre_fix` | `archive/pre-fix/gravity_field.py.pre_fix` | Historical pre-fix snapshot. |

## Generated/Transient Quarantine

- Python caches: `__pycache__/`
- Virtualenvs embedded in domain trees: `.venv/`
- Local dependency mirrors: `node_modules/`

These move under `archive/generated/` unless required for a reproducible build artifact.

## Exit Criteria

- Legacy file has replacement in target package layer and zero import references from canonical packages.
- Archive file has recorded provenance in `archive/README.md`.
- `rg` check returns no live references:

```bash
rg -n "skg-legacy|skg_deploy|forge_staging|gravity_web|exploit_proposals" /opt/skg/packages
```
