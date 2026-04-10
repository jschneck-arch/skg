# Phase 7M AD Boundaries

Date: 2026-04-03

## Boundary Classification (Remaining Higher-Coupling Seams)

### AD-03 / AD-23 seam

- AD domain semantic normalization:
  - AD-01/AD-02 baseline Kerberoast exposure (already canonicalized in prior phases)
- shared helper/governance concern:
  - AD-03 detection-absence confidence semantics (`check_kerberoastable` static branch)
- deferred redteam-lateral/path/value reasoning:
  - AD-23 DA-impact/value coupling
  - `ad_kerberoast_da_v1` path-level coupling in legacy catalog

Decision:
- Keep AD-03/AD-23 deferred from canonical AD migration until confidence and value-impact ownership is split explicitly.

### Delegation family seam (AD-06..AD-09)

- AD domain semantic normalization (candidate):
  - delegation posture facts (`unconstraineddelegation`, `trustedtoauthfordelegation`)
- deferred redteam-lateral/path/value reasoning:
  - freshness/reachability heuristics (`lastlogontimestamp` context assumptions)
  - sensitive target prioritization tied to attack path framing
  - path coupling through `ad_unconstrained_delegation_v1`

Decision:
- Split later, not migrate now. Extract posture-only semantics before any delegation slice migration.

### ACL / DCSync / AdminSDHolder family seam (AD-10..AD-16, AD-19/AD-20)

- AD domain semantic normalization (candidate):
  - ACL edge normalization by right type
  - DCSync candidate extraction
  - AdminSDHolder edge observation
- shared helper/governance concern:
  - AD-20 static SDProp assumption policy
- deferred redteam-lateral/path/value reasoning:
  - high-value target labeling embedded in attack framing
  - coupled path authority in legacy catalog paths (`ad_acl_abuse_v1`, `ad_dcsync_v1`, `ad_adminsdholder_v1`)

Decision:
- Keep deferred and require one dedicated split pass before any coupled slice migration in this family.

### Broad projector seam

- deferred redteam-lateral/path/value reasoning:
  - `skg-ad-lateral-toolchain/projections/lateral/run.py` remains legacy path projector authority with fallback substrate behavior

Decision:
- Remains deferred; no canonical AD projector expansion in this pass.

## Governance Boundary Applied In Phase 7M

- Canonical AD sidecar contract moved to protocol layer:
  - `packages/skg-protocol/src/skg_protocol/contracts/ad_tiering_input.py`
- Services own sidecar production and routing validation:
  - `packages/skg-services/src/skg_services/gravity/ad_runtime.py`
  - `skg/sensors/adapter_runner.py`
- AD domain owns semantic interpretation after contract validation:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_tiering_posture/run.py`

## Explicit Authority Guardrail

Legacy ad-lateral catalog/projector materials remain design evidence and compatibility residue, not canonical AD semantic/path authority for new slices.
