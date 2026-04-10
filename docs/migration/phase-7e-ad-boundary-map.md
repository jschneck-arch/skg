# Phase 7E AD Boundary Map

Date: 2026-04-02

## Ownership Map By Source File

### `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`

- AD domain semantic normalization seams:
  - account enabled/disabled normalization (UAC and explicit flags)
  - pre-auth disabled normalization (`dontreqpreauth`)
  - encryption-type interpretation (`supportedencryptiontypes`)
- service/runtime collection or orchestration seams:
  - source file discovery and schema normalization
  - event emission writer and CLI orchestration
- deferred redteam-lateral/path reasoning seams:
  - delegation reachability/sensitivity path assumptions
  - ACL/DCSync/AdminSDHolder attack-chain checks
  - detection/tiering heuristics tied to exploitation narratives

### `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py`

- AD domain semantic normalization seams:
  - UAC bit interpretation (`ACCOUNTDISABLE`, `DONT_REQUIRE_PREAUTH`)
  - encryption-type interpretation for Kerberos cracking feasibility
- service/runtime collection or orchestration seams:
  - JSON input loading and key-coercion
  - single `main()` flow combining parsing, evaluation, and emission
- deferred redteam-lateral/path reasoning seams:
  - AD-05 value coupling and path-priority semantics when merged with AD-04 branch

### `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json`

- deferred redteam-lateral/path reasoning:
  - path definitions couple multiple semantics into exploit narratives (`ad_*_v1`).
- retained role in this phase:
  - design evidence only for seam identification, not canonical authority source.

### `skg-ad-lateral-toolchain/projections/lateral/run.py`

- deferred redteam-lateral/path reasoning:
  - broad lateral projection classification and sheaf fallback tied to legacy catalog IDs.
- retained role in this phase:
  - boundary evidence; no migration into canonical AD projector path.

## Boundary Decisions Applied

1. Runtime parser/orchestration seams remain out of canonical AD domain.
2. Only one narrow semantic helper extraction was performed.
3. Path-coupled attack-chain logic was explicitly deferred.
4. Existing canonical slices (privileged-membership, credential-hint, weak-policy) remain authoritative for their semantics.

## Boundary Violations Prevented

- No migration of legacy `emit`/CLI execution into AD domain adapters.
- No migration of ad-lateral projector breadth into canonical AD projectors.
- No import of runtime collectors (BloodHound/ldap transport) into domain modules.
