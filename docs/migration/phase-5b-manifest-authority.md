# Phase 5B Manifest Authority (web)

Date: 2026-04-01

## Decision

Canonical manifest authority for the web domain is:

- `packages/skg-domains/web/src/skg_domain_web/manifest.yaml`

This file is now the single source of truth for domain-pack metadata and component paths.

## What Changed

1. Registry discovery was updated to prioritize in-package manifests:
- `packages/skg-registry/src/skg_registry/discovery.py`
- Authority order now:
  1. `src/skg_domain_<name>/manifest.{yaml,yml,json}`
  2. `domain.{yaml,yml,json}` (legacy compatibility fallback only)

2. Registry component path resolution now binds to manifest location:
- `component_root = manifest_path.parent`
- Adapters/projectors/policies/catalog paths are resolved from `component_root`, not from fixed domain root assumptions.

3. Root manifest for web was removed to eliminate dual authority:
- Deleted: `packages/skg-domains/web/domain.yaml`

4. Discovery behavior is covered by tests:
- `packages/skg-registry/tests/test_registry_discovery.py::test_discovery_prefers_in_package_manifest_authority`
- `packages/skg-domains/web/tests/test_web_projector_e2e.py::test_registry_discovers_web_pack_src_layout`

## Compatibility Policy

- Registry still supports root `domain.yaml` for legacy/transition packs.
- For the web pilot, that fallback is explicitly non-authoritative because the root file no longer exists.
- No generated compatibility manifest is required for web in Phase 5B.

## Rationale

- Eliminates split-brain manifest ownership.
- Keeps ownership with the domain package itself.
- Preserves cross-domain migration safety by keeping legacy fallback behavior in registry for packs not yet consolidated.
