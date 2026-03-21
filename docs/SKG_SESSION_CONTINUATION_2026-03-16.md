# SKG Session Continuation — 2026-03-16

## Context
This note captures the current SKG substrate state at the end of the 2026-03-16 session so work can resume without reconstructing the entire thread.

The guiding constraint remains unchanged:
- preserve SKG as SKG
- do not collapse into telemetry, policy tables, or tool orchestration
- maintain the math and physics:
  - energy = unresolved state pressure
  - gravity = routing toward expected collapse
  - folds = model mismatch / unresolved structure
  - pearls = preserved meaningful collapse and remembered state
  - resonance = reusable memory / recall, not narration
  - forge = structural growth from folds

## What Was Completed

### History / Pearls
- Pearl schema was enriched in [`/opt/skg/skg/kernel/pearls.py`](/opt/skg/skg/kernel/pearls.py):
  - `target_snapshot`
  - `fold_context`
- Gravity now writes richer pearls in [`/opt/skg/skg-gravity/gravity_field.py`](/opt/skg/skg-gravity/gravity_field.py):
  - target kind
  - domains
  - services
  - inferred identity properties
  - top fold context
- Historical report queries are real in [`/opt/skg/bin/skg`](/opt/skg/bin/skg):
  - `skg report --target <target> --at <iso-ts>`
  - `skg report --target <target> --diff-against <iso-ts>`
- Validated live:
  - `www.google.com` pearl at `2026-03-17T03:35:01.743320+00:00` contains `target_snapshot`
  - `skg report --target www.google.com --at 2026-03-17T03:35:01.743320+00:00` reconstructs from pearl-backed history

### Fold Semantics
- Folds now carry richer semantics in [`/opt/skg/skg/kernel/folds.py`](/opt/skg/skg/kernel/folds.py):
  - `why`
  - `hypotheses`
  - `discriminators`
  - `evidence_refs`
- Projection fold detection was broadened beyond narrow web-only heuristics.

### Recall / Resonance
- `skg resonance drafts` now uses a real draft store instead of a fake memory fallback.
- Recall is visible in `skg report` and `skg proposals show`.
- A bounded recall modifier is wired into proposal confidence, but live recall remains sparse in practice.

### Operator Surface
- `skg report` now includes:
  - identity
  - evidence
  - top mismatch
  - hypotheses
  - recent memory
  - next collapse/action
- `skg web` now starts from field context instead of acting like a disconnected bond renderer.
- `skg proposals` is clearer:
  - active queue vs historical records
  - toolchain maturity surfaced

### Pearl Structure / Compression
- The append-only pearl ledger remains the substrate truth.
- A derived pearl clustering layer now exists in [`/opt/skg/bin/skg`](/opt/skg/bin/skg):
  - repeated pearl patterns are compressed into clustered remembered structure for reporting
- Example live output for `172.17.0.3`:
  - `domains +sysaudit -none x24`

### Identity-Driven Routing
- Focused gravity on URL targets now canonicalizes and registers external web targets.
- Instrument routing in [`/opt/skg/skg-gravity/gravity_field.py`](/opt/skg/skg-gravity/gravity_field.py) now uses observed target identity coherence rather than crude target-kind assumptions.
- Validated live on `https://www.google.com`:
  - gravity no longer failed with `not present in surface`
  - focused routing selected only coherent instruments (`nvd_feed`, `metasploit`) instead of trying host/data/container paths

## Current State

### Good
- SKG is no longer “just telemetry”.
- Historical pearl-backed state is real.
- The operator surface is substantially more coherent.
- Fold semantics are richer and closer to Paper 3 intent.
- Identity-informed routing is beginning to behave like SKG rather than rule tables.

### Still Partial
- Recall is still too sparse to strongly steer routing in practice.
- Pearl clustering is useful but still shallow; near-identical clusters can still appear separately.
- Proposal history still leaks into the operator picture more than ideal.
- `web` is better, but `report` remains the strongest canonical surface.
- The system still understands known structure better than genuinely novel structure.

## Most Recent Verified Live Outputs

### `skg report --target 172.17.0.3`
Now shows:
- target identity and evidence
- top mismatch:
  - `CVE-2008-2050 is observed on PHP/5.2.4-2ubuntu5.10, but SKG has no wicket mapping`
- remembered structure:
  - `domains +sysaudit -none x24`
- next action:
  - pending SSH follow-on proposal

### `skg gravity --target https://www.google.com --cycles 1`
Now:
- registers `www.google.com` into surface
- treats it as `external-web`
- routes coherently by observed identity instead of trying host/data/container instruments

## Next Best Steps
1. Review all of `/opt/skg` at a whole-system level, as requested by the user.
2. Deepen pearl clustering into a more manifold/graph-like derived structure:
   - treat repeated/nearby pearls as reinforced memory, not repeated rows
   - use overlap rather than flat dedupe
3. Let pearl structure feed recall and interpretation more strongly.
4. Keep the operator surface subordinate to substrate truth:
   - evidence
   - meaning
   - uncertainty
   - next collapse
5. Continue checking all changes against SKG’s math/physics so the system does not regress into scanner behavior.

## Important Design Constraint
Do not introduce policy tables or static exclusions as a substitute for understanding.

The user explicitly rejected that direction. Instrument routing should derive from observed identity/properties and field state, not hardcoded guardrails.

## Note For Resume
If resuming from here, the first step should likely be:
- inspect `/opt/skg` broadly
- then revisit the pearl manifold / graph idea as a derived layer on top of the existing pearl ledger

Timestamp: 2026-03-16T23:11:38-05:00
