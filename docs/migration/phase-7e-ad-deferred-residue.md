# Phase 7E AD Deferred Residue

Date: 2026-04-02

## Deferred Residue After Corrective Split Pass

| Legacy path | Deferred seam | Classification | Why deferred | Exact future step |
|---|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | source parsing + CLI + file emission | service/runtime collection or orchestration | Runtime/parser ownership not resolved into service wrapper boundary yet. | Create service-owned source wrappers and keep AD domain adapters semantic-only. |
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | AD-05, AD-06..AD-16, AD-19..AD-23, AD-25 mixed attack-path semantics | deferred redteam-lateral/path reasoning | Functions remain monolithic and path-coupled. | Split by semantic family before any canonical migration of these branches. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | monolithic `main` with mixed slice emission | service/runtime collection or orchestration + mixed semantics | No clean module seams between parser and semantic mapping branches. | Break into parser module + per-slice semantic mappers with explicit contracts. |
| `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` | multi-slice exploit path catalog | deferred redteam-lateral/path reasoning | Catalog authority remains legacy/path-driven and not canonical AD-owned. | Continue extracting slice-local ontology entries into canonical AD catalog only when slice is migrated. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | broad lateral projector and fallback logic | deferred redteam-lateral/path reasoning | Projector still keyed to legacy catalog breadth and fallback imports. | Revisit only after additional AD slices are canonicalized and runtime convergence is planned. |

## Newly Extracted Safe Helper

- `packages/skg-domains/ad/src/skg_domain_ad/adapters/common/account_semantics.py`
  - extracted UAC/pre-auth/encryption semantics from mixed legacy adapters
  - tested under `packages/skg-domains/ad/tests/test_ad_account_semantics_helpers.py`

## Current Canonical AD Scope

- Phase 7A: privileged-membership slice
- Phase 7C: credential-hint slice
- Phase 7D: weak password policy slice
- Phase 7E: corrective split helper extraction for higher-coupling seams
