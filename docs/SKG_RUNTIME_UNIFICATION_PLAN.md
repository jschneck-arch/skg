# SKG Runtime Unification Plan

Purpose: make the "two SKGs" situation explicit and operationally safe.

This is not a deletion plan.
It is a plan to keep one canonical runtime while preserving mirrors, backups, and staging trees.

## The Actual Split

There are currently two materially different SKG code surfaces in the repo:

- canonical live runtime
  - `/opt/skg/bin/skg`
  - `/opt/skg/skg`
  - `/opt/skg/skg-gravity`
  - `/opt/skg/skg-*-toolchain`
  - `/var/lib/skg/*`

- preserved deploy mirror
  - `/opt/skg/skg_deploy`

There are also adjacent preserved trees:

- `/opt/skg/skg-web-toolchain.backup`
- `/opt/skg/forge_staging`

The problem is not that these paths exist.
The problem is when they are treated as equally authoritative during active work.

## Rule

There is one live SKG.

That live SKG is the canonical runtime under:

- `/opt/skg/bin/skg`
- `/opt/skg/skg`
- `/opt/skg/skg-gravity`
- `/opt/skg/skg-*-toolchain`
- `/var/lib/skg/*`

`/opt/skg/skg_deploy` is part of SKG, but it is not the live runtime unless a task is explicitly deploy-oriented.

## Why This Matters

If both trees are edited casually:

- semantics drift
- runtime fixes land in one tree but not the other
- operator behavior becomes hard to reason about
- docs stop matching the actual running system

This is exactly the kind of substrate ambiguity SKG should not tolerate.

## Interpretation

When asking "what is SKG doing right now?", start with:

1. `/opt/skg/bin/skg`
2. `/opt/skg/skg`
3. `/opt/skg/skg-gravity`
4. `/opt/skg/skg-*-toolchain`
5. `/var/lib/skg/*`

When asking "what else is part of SKG?", include:

1. `/opt/skg/skg_deploy`
2. `/opt/skg/skg-web-toolchain.backup`
3. `/opt/skg/forge_staging`
4. `/opt/skg/docs`

## Working Discipline

1. fix canonical runtime first
2. validate canonical runtime
3. only then decide whether deploy mirror synchronization is needed
4. never assume deploy mirror parity without checking it

## Near-Term Cleanup

The next safe cleanup is classification and synchronization, not deletion.

That means:

- keep `skg_deploy`
- label it clearly as a deploy mirror
- stop treating it as a parallel primary source
- only sync it deliberately after canonical runtime changes settle

## Desired End State

SKG should present as:

- one canonical observational runtime
- one preserved deploy mirror
- one staging area for generated growth
- one docs tree describing the actual system

Not:

- multiple half-canonical runtime surfaces competing for authority

