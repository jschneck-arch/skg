# Phase 7B AD Deferred Residue

Date: 2026-04-02

## Deferred Residue

| Legacy path | Deferred slice(s) | Why deferred | Exact removal/split prerequisite |
|---|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | Kerberoast, AS-REP privilege coupling, delegation, ACL abuse, DCSync, AdminSDHolder, stale-account path semantics | File is a monolith mixing parser IO, semantic checks, event emission, and ad-lateral attack-path IDs. | Split into: source reader, semantic evaluators per slice, and canonical AD mapping layer with no direct runtime/file emission. |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | Mixed multi-slice checks emitted in one `main()` flow | Conflates source parsing, normalization, and legacy wicket assignment with no boundary between runtime parser and domain semantic logic. | Extract parser module first; move semantic mappers into canonical AD modules slice-by-slice. |
| `skg/sensors/bloodhound_sensor.py` | BH/Neo4j collection and normalization path still targets legacy bloodhound adapter contract | Runtime transport and orchestration remain coupled to legacy normalization shape. | Introduce service-owned wrapper that maps collection outputs directly into canonical AD adapter inputs. |
| `skg-gravity/adapters/ldap_enum.py` | LDAP runtime execution + event emission + kernel ingest in one module | Runtime transport and side-effects are mixed with AD semantic predicates; contains legacy path hack. | Remove `sys.path` hack, isolate transport/orchestration in service module, and route semantic evidence through canonical AD adapter contracts. |
| `skg-ad-lateral-toolchain/projections/lateral/run.py` | Full ad-lateral projection breadth | Path-level projection still tied to ad-lateral catalog breadth and legacy fallback imports. | Migrate only after additional AD slices are canonicalized and mapped to canonical projector contracts. |

## Retained Compatibility Boundary

- Legacy AD-lateral runtime files remain active only for deferred slices.
- Canonical AD package remains authoritative only for the migrated privileged-membership slice and extracted semantic helpers.

## Residual Risk

- Dual ontology pressure remains between ad-lateral catalog IDs (`AD-*`) and canonical AD domain wickets (`AD-PR-*`) until next slice migration defines explicit crosswalks.
- Runtime callers still transitively depend on legacy adapters for non-migrated AD flows.
