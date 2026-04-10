# Phase 7B AD Boundary Map

Date: 2026-04-02

## Boundary Classification By File

### `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py`

- AD domain semantics:
  - privileged group identity heuristics
  - password-description lexical hints
  - account typing (human vs machine)
- service/runtime concerns:
  - file discovery and BloodHound schema parsing
  - local event file writing (`emit`)
  - CLI entrypoint and execution orchestration (`main`)
- deferred/redteam-lateral semantics:
  - Kerberoast/AS-REP attack-path coupling
  - delegation abuse path gating
  - ACL/DCSync/AdminSDHolder attack-chain semantics
- ownership decision:
  - extract only source-agnostic semantic primitives now
  - keep remaining file deferred until per-slice decomposition

### `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py`

- AD domain semantics:
  - lexical credential-hint detection
  - high-level account/policy semantic checks (candidates)
- service/runtime concerns:
  - ldapdomaindump file loading and key coercion
  - adapter CLI orchestration + file emission
- deferred/redteam-lateral semantics:
  - wicket assignment tied to legacy ad-lateral IDs and paths
- ownership decision:
  - extract helper-level semantic primitives only
  - defer full check migration until source parser is split from semantic mapper

### `skg/sensors/bloodhound_sensor.py`

- service/runtime concerns:
  - API auth/session lifecycle
  - Neo4j transport fallback
  - pagination/query orchestration
  - state management and scheduler cadence
  - cache directory materialization + adapter invocation
- shared/cross-domain coupling:
  - normalization shaped to legacy ad-lateral adapter contracts
- ownership decision:
  - retain in service/runtime layer
  - future split should introduce service wrapper that calls canonical AD adapters

### `skg-gravity/adapters/ldap_enum.py`

- service/runtime concerns:
  - LDAP bind/query execution
  - credentials and host-target runtime integration
  - kernel ingest side-effect and output file handling
  - legacy `sys.path` mutation
- AD domain semantic fragments:
  - privileged group-name matching
  - machine-account and attribute interpretation hints
- ownership decision:
  - keep runtime module deferred
  - extract only semantic primitives into canonical AD helper modules

## Cross-Domain Contamination Risks

- Host contamination:
  - `ldap_enum.py` emits host-scoped workload semantics (`host::<node>`), while evaluating AD wickets.
- Redteam-lateral contamination:
  - BloodHound parser couples AD evidence checks directly to exploit-oriented attack paths (`ad_*_v1`).
- Runtime contamination:
  - Domain-relevant semantics are embedded inside modules that also own network auth, transport, and runtime fallback behavior.

## Boundary-Enforcement Decisions

1. No runtime/service modules were migrated into `packages/skg-domains/ad`.
2. No second AD slice was migrated in Phase 7B.
3. Only semantic helpers proven source-agnostic were extracted.
4. Legacy modules remain the execution path for deferred AD-lateral runtime flows until a dedicated service-wrapper migration phase.
