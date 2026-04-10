# Phase 7A Domain Selection

Date: 2026-04-02

## Selected Domain

- Domain: `ad`
- Selected slice: **group membership / privilege assignment mapping**

## Why This Slice

1. Cleanest ownership boundary in current repo.
- Source evidence is inventory semantics from BloodHound-style `users` + `groups` snapshots.
- No transport/session/subprocess logic is required to map this slice.

2. Lowest contamination risk.
- Avoids direct migration of mixed redteam/ad-lateral orchestration semantics.
- Avoids host runtime concerns and AD attack-chain-specific ACL/delegation logic in first pass.

3. Fits web/host template directly.
- Domain-owned adapter + ontology + projector + explicit policy files.
- Service/runtime remains separate and deferred.

## Canonical Manifest Authority Decision

- Canonical manifest: `packages/skg-domains/ad/src/skg_domain_ad/manifest.yaml`
- Legacy scaffold manifest removed: `packages/skg-domains/ad/domain.yaml`

This keeps single-manifest authority for `ad` consistent with web/host domain packs.

## Explicitly Out Of Scope In Phase 7A

- ACL abuse and DCSync semantics
- Delegation abuse semantics
- BloodHound/LDAP runtime collection and transport wrappers
- Redteam/ad-lateral orchestration and exploit-path semantics
