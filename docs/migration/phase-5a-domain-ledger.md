# Phase 5A Domain Ledger (web)

Date: 2026-04-01

## Migrated Items

| Legacy path | New path | Classification | Action | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg-web-toolchain/contracts/catalogs/attack_preconditions_catalog.web.v1.json` | `packages/skg-domains/web/src/skg_domain_web/ontology/catalogs/attack_preconditions_catalog.web.v1.json` | ontology | split | Extracted canonical web ontology subset needed for pilot attack paths and wickets. | Catalog is intentionally partial; broader wicket coverage deferred. |
| `skg-web-toolchain/contracts/catalogs/attack_preconditions_catalog.web.v1.json` | `packages/skg-domains/web/src/skg_domain_web/ontology/wickets.yaml` | ontology | split | Converted web wicket declarations into pack-local ontology artifact. | YAML subset must stay in sync with catalog subset during expansion. |
| `skg-web-toolchain/contracts/catalogs/attack_preconditions_catalog.web.v1.json` | `packages/skg-domains/web/src/skg_domain_web/ontology/attack_paths.yaml` | ontology | split | Isolated attack-path declarations used by projector and tests. | Only pilot paths included; missing paths intentionally deferred. |
| `skg-web-toolchain/adapters/web_active/gobuster_adapter.py` | `packages/skg-domains/web/src/skg_domain_web/mappings/path_signatures.yaml` | mapping | split | Extracted domain-owned path signature semantics out of runtime subprocess adapter. | Regex coverage is pilot-level and not full legacy parity. |
| `skg-web-toolchain/adapters/web_active/gobuster_adapter.py` | `packages/skg-domains/web/src/skg_domain_web/adapters/web_path_inventory/run.py` | adapter | split | Preserved contract-level observation mapping (`path findings -> obs.attack.precondition`) without subprocess/runtime control. | Adapter currently assumes pre-collected findings instead of executing scanners. |
| `skg-web-toolchain/projections/web/run.py` | `packages/skg-domains/web/src/skg_domain_web/policies/projection_policy.yaml` | policy | split | Moved attack-path alias policy out of projector code into explicit artifact. | Alias list is minimal and requires expansion for broader path support. |
| `skg-web-toolchain/projections/web/run.py` | `packages/skg-domains/web/src/skg_domain_web/projectors/web/run.py` | projector | rewritten | Rebuilt projector as domain-owned module using canonical `skg-core` substrate projection primitives and explicit policy/ontology inputs. | Service runtime integration beyond pilot signatures still needs broader compatibility pass. |
| `packages/skg-domains/web/domain.yaml` (scaffold) | `packages/skg-domains/web/domain.yaml` | policy | rewritten | Updated registry manifest to canonical src-owned component paths. | Non-canonical callers expecting old root-level component dirs may break. |
| `packages/skg-domains/web/domain.yaml` (scaffold) | `packages/skg-domains/web/src/skg_domain_web/manifest.yaml` | policy | rewritten | Added in-pack manifest required for domain-pack internal metadata ownership. | Registry currently reads root `domain.yaml`; dual-manifest maintenance required until registry enhancement. |
| n/a (new canonical asset) | `packages/skg-domains/web/src/skg_domain_web/policies/adapter_policy.yaml` | policy | rewritten | Made adapter behavior explicit (status code admissibility/fallback confidence) instead of hidden conditionals. | Policy values are pilot defaults and may need domain tuning. |
| n/a (new canonical asset) | `packages/skg-domains/web/src/skg_domain_web/fixtures/web_path_findings.json` | fixture | rewritten | Added deterministic fixture for adapter/projector test flow. | Fixture scope is small and does not represent all web observation types. |
| n/a (new canonical asset) | `packages/skg-domains/web/src/skg_domain_web/examples/pilot_usage.md` | example | rewritten | Added explicit pilot usage artifact under domain pack. | Example is documentation only; no executable harness yet. |

## New Package Scaffold And Tests

- `packages/skg-domains/web/pyproject.toml`
- `packages/skg-domains/web/src/skg_domain_web/...`
- `packages/skg-domains/web/tests/test_web_adapter_mapping.py`
- `packages/skg-domains/web/tests/test_web_projector_e2e.py`

These are new canonical files (no legacy path equivalent), added to make the pilot domain installable/testable.
