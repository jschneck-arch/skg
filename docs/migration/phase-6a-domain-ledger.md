# Phase 6A Domain Ledger (host)

Date: 2026-04-02

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json` | `packages/skg-domains/host/src/skg_domain_host/ontology/catalogs/attack_preconditions_catalog.host.v1.json` | ontology | copied | Preserved canonical host ontology source as in-pack artifact. | Full catalog includes paths whose adapters are not yet migrated. |
| `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json` | `packages/skg-domains/host/src/skg_domain_host/ontology/wickets.yaml` | ontology | split | Extracted domain wickets into pack-native YAML for direct loader use. | Must remain aligned with catalog as domain expands. |
| `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json` | `packages/skg-domains/host/src/skg_domain_host/ontology/attack_paths.yaml` | ontology | split | Extracted attack-path declarations into pack-native YAML for projector use. | Paths referencing deferred adapters remain indeterminate until those adapters migrate. |
| `skg-host-toolchain/adapters/nmap_scan/parse.py` | `packages/skg-domains/host/src/skg_domain_host/mappings/service_wickets.yaml` | mapping | split | Isolated domain-owned service->wicket semantics from mixed runtime adapter file. | Mapping coverage is scoped to currently migrated nmap slice. |
| `skg-host-toolchain/adapters/nmap_scan/parse.py` | `packages/skg-domains/host/src/skg_domain_host/mappings/exploit_signatures.yaml` | mapping | split | Isolated exploit-signature semantics from mixed runtime adapter file. | Signature list is heuristic and may need tuning for false positives. |
| `skg-host-toolchain/adapters/nmap_scan/parse.py` | `packages/skg-domains/host/src/skg_domain_host/adapters/host_nmap_profile/run.py` | adapter | split | Rebuilt as contract-driven semantic mapper (`profile -> canonical events`) with no subprocess execution. | XML parsing + scan execution parity intentionally deferred to services. |
| `skg-host-toolchain/projections/host/run.py` | `packages/skg-domains/host/src/skg_domain_host/projectors/host/run.py` | projector | rewritten | Rewrote projector to canonical `skg_core.substrate.projection.project_path` flow; removed legacy kernel imports and `sys.path` manipulation. | Legacy sheaf-specific enrichment is deferred. |
| `skg-host-toolchain/projections/host/run.py` | `packages/skg-domains/host/src/skg_domain_host/policies/projection_policy.yaml` | policy | split | Externalized status-priority and score-key policy from projector conditionals. | Additional alias/priority policy may be needed as more host flows migrate. |
| `skg-host-toolchain/adapters/nmap_scan/parse.py` | `packages/skg-domains/host/src/skg_domain_host/policies/nmap_adapter_policy.yaml` | policy | split | Externalized evidence rank/confidence/wicket policy from mixed adapter code. | Confidence defaults are conservative, not calibrated. |
| `packages/skg-domains/host/domain.yaml` | deleted (manifest authority moved to `src/skg_domain_host/manifest.yaml`) | manifest | rewritten | Removed dual manifest authority and made in-pack manifest canonical. | Out-of-repo legacy callers expecting root `domain.yaml` will need explicit compatibility handling if they exist. |

## New Canonical Assets (No Direct Legacy Source)

- `packages/skg-domains/host/pyproject.toml`
- `packages/skg-domains/host/src/skg_domain_host/__init__.py`
- `packages/skg-domains/host/src/skg_domain_host/manifest.yaml`
- `packages/skg-domains/host/src/skg_domain_host/ontology/__init__.py`
- `packages/skg-domains/host/src/skg_domain_host/mappings/__init__.py`
- `packages/skg-domains/host/src/skg_domain_host/policies/__init__.py`
- `packages/skg-domains/host/src/skg_domain_host/examples/pilot_usage.md`
- `packages/skg-domains/host/src/skg_domain_host/fixtures/host_nmap_profiles.json`
- `packages/skg-domains/host/tests/test_host_nmap_adapter.py`
- `packages/skg-domains/host/tests/test_host_projector_e2e.py`
