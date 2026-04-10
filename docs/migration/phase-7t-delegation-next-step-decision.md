# Phase 7T Delegation Next Step Decision

Date: 2026-04-03

## Decision

Continue delegation retirement.

Wave-2 goals were met for AD-06 collision outputs:
- in-repo consumers identified,
- legacy collision outputs retired where safe,
- coverage advertisement aligned with actual runtime behavior.

## What Was Proven Safe

1. No active in-repo runtime consumer required `AD-06-LDAP-LEGACY` or `AD-06-IMPACKET-LEGACY`.
2. Retiring both collision outputs did not break canonical/domain test suite.
3. Canonical ownership model remained unchanged.

## Retained Blockers

| Blocker | Why retained | Next step |
|---|---|---|
| Legacy delegation branch (`check_delegation`) still exists for explicit legacy path IDs | Compatibility containment still active | Decide hard-disable/removal timeline for legacy path IDs |
| Out-of-repo consumers may still parse retired collision IDs | Not discoverable in repo-only analysis | Announce deprecation/removal in operator release notes and monitor runtime logs |
| AD-09 path/value semantics remain deferred | Ownership model intentionally excludes this from canonical AD domain | Either keep deferred or move to explicit reasoning-layer design track |

## Recommendation

Continue retirement if the goal is to fully remove legacy delegation branches.

If AD-09 and broader ad-lateral semantics need future evolution, pause AD migration work and move to a dedicated reasoning-layer design pass before reintroducing any coupled semantics.

