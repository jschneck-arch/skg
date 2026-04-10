# Phase 7S Delegation Next Step Decision

Date: 2026-04-03

## Decision

Proceed to retirement wave 2.

Phase 7S completed wave-1 de-authorization intent:
- runtime gating is explicit for legacy delegation branches,
- AD-07/AD-09 are no longer implied as canonical via BloodHound coverage advertisement,
- AD-06 collision advertisement moved to quarantined IDs.

## What Wave 2 Should Do

1. Remove or hard-disable remaining legacy delegation branch execution paths where no external compatibility contract is required.
2. Begin controlled removal of collision outputs:
   - `AD-06-LDAP-LEGACY`
   - `AD-06-IMPACKET-LEGACY`
3. Keep AD-09 deferred outside AD domain unless ownership model changes.

## Retained Blockers

| Blocker | Why retained | Required next step |
|---|---|---|
| Legacy `check_delegation` implementation still exists | Compatibility for explicit legacy path IDs | Wave 2 deprecation/removal with callsite inventory confirmation |
| Quarantined AD-06 collision outputs still emitted by legacy adapters | Downstream compatibility may still exist | Identify consumers, migrate, then remove emissions |
| ad-lateral catalog still contains delegation path/value coupling | Remains non-canonical by design | Keep deferred; do not re-authorize as canonical authority |

## Recommendation

Ready to continue retirement wave 2.

If wave-2 consumer impact is unknown, execute a short compatibility inventory pass first, then delete collision outputs in a controlled wave.

