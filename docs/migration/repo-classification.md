# Repository Classification

Date: 2026-04-01
Scope: current `/opt/skg` repository, classified against target architecture.

Legend:
- Classification: `CORE` / `PROTOCOL` / `REGISTRY` / `SERVICE` / `DOMAIN` / `LEGACY` / `ARCHIVE` / `DELETE`
- Action: `KEEP` / `SPLIT` / `MOVE` / `REWRITE` / `ARCHIVE` / `DELETE`

## Top-Level Classification

| Path | Classification | Action | Target Destination | Confidence | Rationale |
|---|---|---|---|---|---|
| `/opt/skg/skg` | MIXED (`CORE` + `SERVICE` + partial `DOMAIN`) | `SPLIT` | `packages/skg-core`, `packages/skg-protocol`, `packages/skg-registry`, `packages/skg-services`, `packages/skg-domains` | HIGH | Contains substrate and runtime monoliths in same tree. |
| `/opt/skg/skg-gravity` | SERVICE | `SPLIT` + `MOVE` + `REWRITE` | `packages/skg-services/gravity` and `packages/skg-services/harness` | HIGH | Runtime orchestration and exploit sidecars are mixed and heavily coupled. |
| `/opt/skg/skg-*-toolchain` | DOMAIN | `MOVE` | `packages/skg-domains/<domain>/...` | HIGH | Domain-specific contracts/adapters/projectors belong in domain bundles. |
| `/opt/skg/skg-discovery` | SERVICE | `MOVE` + `REWRITE` | `packages/skg-services/reporting` or `packages/skg-services/api` intake path | HIGH | Discovery runtime and hardcoded catalog scanning. |
| `/opt/skg/ui` | SERVICE | `MOVE` | `packages/skg-services/reporting/ui` | HIGH | Operator-facing service UI. |
| `/opt/skg/bin` | SERVICE | `MOVE` + `REWRITE` | `packages/skg-services/cli/bin` | HIGH | Launcher uses `sys.path` injection. |
| `/opt/skg/scripts` | SERVICE | `MOVE` + `REWRITE` | `packages/skg-services/*/deploy` | HIGH | systemd units hardcode `/opt/skg` and `PYTHONPATH`. |
| `/opt/skg/tests` | MIXED TESTS | `SPLIT` | package-local tests + integration suite | MEDIUM | Tests currently span core/service/domain in one place. |
| `/opt/skg/docs` | EVIDENCE | `KEEP` | `docs/...` | HIGH | Design evidence, not runtime authority. |
| `/opt/skg/review` | EVIDENCE | `KEEP` | `docs/review` or retain path | HIGH | Design evidence only. |
| `/opt/skg/skg_deploy` | ARCHIVE | `ARCHIVE` | `archive/deploy-mirror` | HIGH | Explicit deploy mirror, non-canonical runtime source. |
| `/opt/skg/forge_staging` | ARCHIVE | `ARCHIVE` | `archive/staging/forge_staging` | HIGH | Generated/staging material only. |
| `/opt/skg/skg-web-toolchain.backup` | ARCHIVE | `ARCHIVE` | `archive/backups/toolchains` | HIGH | Backup tree only. |
| `/opt/skg/skg-nginx-toolchain.backup` | ARCHIVE | `ARCHIVE` | `archive/backups/toolchains` | HIGH | Backup tree only. |
| `/opt/skg/node_modules` | ARCHIVE | `ARCHIVE` | `archive/generated/node_modules` | HIGH | Generated dependencies. |

## High-Impact Subdirectory Classification

| Path | Classification | Action | Target Destination | Confidence | Rationale |
|---|---|---|---|---|---|
| `/opt/skg/skg/core/daemon.py` | SERVICE | `SPLIT` + `MOVE` + `REWRITE` | `packages/skg-services/api` + service clients | HIGH | API + gravity control + assistant + reporting mixed in one module. |
| `/opt/skg/skg/core/domain_registry.py` | REGISTRY | `MOVE` + `REWRITE` | `packages/skg-registry` | HIGH | Right responsibility, wrong placement and path coupling. |
| `/opt/skg/skg/core/paths.py` | CORE (config primitives) | `SPLIT` + `MOVE` + `REWRITE` | `packages/skg-core/config` | HIGH | Useful primitives but includes deployment assumptions. |
| `/opt/skg/skg/core/assistant_contract.py` | PROTOCOL | `MOVE` | `packages/skg-protocol/contracts/assistant` | HIGH | Contract semantics, not core runtime. |
| `/opt/skg/skg/core/state_db.py` | SERVICE | `MOVE` | `packages/skg-services/gravity/state` | HIGH | SQLite runtime mirror for gravity orchestration. |
| `/opt/skg/skg/substrate` | CORE | `MOVE` + selective `KEEP` | `packages/skg-core/substrate` | HIGH | Canonical substrate primitives. |
| `/opt/skg/skg/kernel` | CORE (mixed) | `SPLIT` + `MOVE` | `packages/skg-core/kernel` + service extras | MEDIUM | Mostly substrate logic with some runtime coupling. |
| `/opt/skg/skg/identity` | CORE | `MOVE` | `packages/skg-core/identity` | HIGH | Canonical identity memory/parsing. |
| `/opt/skg/skg/temporal` | CORE (mixed) | `SPLIT` + `MOVE` | `packages/skg-core/temporal` + service ingestion wrappers | MEDIUM | Feedback ingester currently coupled to runtime layout. |
| `/opt/skg/skg/graph` | CORE | `MOVE` + `REWRITE` | `packages/skg-core/graph` | MEDIUM | Canonical graph but weight semantics need cleanup. |
| `/opt/skg/skg/sensors/projector.py` | PROTOCOL+SERVICE MIX | `SPLIT` + `MOVE` + `REWRITE` | protocol contracts + service projector runtime | HIGH | Contract logic and runtime execution are mixed. |
| `/opt/skg/skg/cli` | SERVICE | `SPLIT` + `MOVE` + `REWRITE` | `packages/skg-services/cli` + harness/reporting splits | HIGH | CLI includes runtime execution, path hacks, private imports. |
| `/opt/skg/skg/assistant` | SERVICE | `MOVE` | `packages/skg-services/assistant` | HIGH | Assistant runtime and proposal drafting service. |
| `/opt/skg/skg/forge` | SERVICE | `MOVE` | `packages/skg-services/forge` | HIGH | Proposal/toolchain generation service. |
| `/opt/skg/skg/intel/surface.py` | SERVICE | `MOVE` | `packages/skg-services/reporting/model` | HIGH | Reporting/model synthesis surface. |
| `/opt/skg/skg/topology/energy.py` | CORE+SERVICE MIX | `SPLIT` + `REWRITE` | core topology + service view layer | HIGH | Imports daemon registry private hooks. |
| `/opt/skg/skg-gravity/gravity_field.py` | SERVICE | `SPLIT` + `MOVE` + `REWRITE` | `packages/skg-services/gravity/runtime` | HIGH | Monolithic runtime with boundary bypasses and path hacks. |
| `/opt/skg/skg-gravity/exploit_dispatch.py` | HARNESS SERVICE | `MOVE` + `REWRITE` | `packages/skg-services/harness/claw-bridge` | HIGH | Exploit mapping/dispatch belongs in Claw bridge. |
| `/opt/skg/skg-gravity/exploit_proposals.py` | LEGACY | `MOVE` | `packages/skg-legacy/gravity` | HIGH | Sidecar proposal queue outside canonical lifecycle. |
| `/opt/skg/skg-gravity/gravity_web.py` | LEGACY | `MOVE` | `packages/skg-legacy/gravity` | HIGH | Legacy bond model sidecar. |
| `/opt/skg/skg-gravity/gravity.py` | LEGACY | `MOVE` | `packages/skg-legacy/gravity` | HIGH | Compatibility shim only. |
| `/opt/skg/skg-gravity/gravity_field.py.pre_fix` | ARCHIVE | `ARCHIVE` | `archive/pre-fix` | HIGH | Historical snapshot. |

## Boundary Violations (Priority)

1. Runtime/service code embedded in core: `skg/core/daemon.py`, `skg/core/state_db.py`.
2. Direct bypass of registry/projector contracts: `skg-gravity/gravity_field.py`, `skg/cli/commands/*`.
3. Path and import hacks: widespread `sys.path.insert`, hardcoded `/opt/skg`, `PYTHONPATH` reliance.
4. Mixed authority planes: declared targets/config merged into measured/runtime surfaces.
5. Duplicate runtime implementations: gravity loops and surface hydration logic duplicated across daemon/CLI/gravity.
