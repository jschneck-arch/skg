# SKG Operator Checklist

Purpose: provide a practical checklist for running an SKG engagement without losing the substrate-centered model.

This is not a rigid script.
It is a control checklist for the operator.

## Before Starting

Confirm:

- scope is defined
- approval boundaries are defined
- destructive actions are clearly separated from observation
- `/var/lib/skg` is the active state root
- the current surface, folds, proposals, and pearls are readable

Check:

```bash
skg status --self-audit
skg surface
skg folds list
skg proposals list --status all
```

Operator question:

- is SKG in a coherent starting state, or are there unresolved runtime/self folds first?

## Intake

Add or confirm targets:

```bash
skg target list
skg target add-subnet <cidr>
```

Confirm the intended proving focus:

- surface formation
- foothold collapse
- post-foothold consequence
- fold discovery
- model growth

Operator question:

- what are we trying to measure in this run?

## Surface Formation

Run a surface-forming cycle:

```bash
skg gravity --cycles 1
skg surface
skg report
```

Look for:

- identities and manifestations
- domains inferred
- services discovered
- early folds
- obviously broken or missing runtime paths

Operator question:

- does the measured surface make sense, and what remains unresolved?

## Foothold Collapse

Use either gravity or a target-focused run:

```bash
skg gravity --cycles 1 --target <ip>
skg report --target <ip>
```

If needed, inspect attack-path state:

```bash
skg surface
skg report --target <ip> --json
```

Look for:

- realized footholds
- blocked footholds
- indeterminate footholds
- the evidence pointers behind those states

Operator question:

- is this foothold measured, blocked, or merely suggested?

## Post-Foothold Measurement

After a realized foothold:

```bash
skg gravity --cycles 1 --target <ip>
skg report --target <ip>
```

Look for:

- host consequence
- post-exp consequence
- data access
- container context
- binary constraints
- new folds caused by deeper access

Operator question:

- what changed because access became real?

## Fold Review

Review folds directly:

```bash
skg folds list
skg report --target <ip>
```

Look for:

- structural folds
- contextual folds
- projection folds
- temporal folds
- recurring fold families on one identity/domain/service family

Operator question:

- is this a target-side gap, an SKG-side gap, or both?

## Proposal Review

Review proposals:

```bash
skg proposals list --status all
skg proposals show <id>
```

Look for:

- `field_action`
- `toolchain_generation`
- `catalog_growth`
- growth-memory reinforcement
- clustered fold pressure

Operator question:

- does this proposal reflect one real structural pressure or many fragmented ones?

## Recall And Comparison

Use report and pearls to compare state over time:

```bash
skg report --target <ip>
skg report --target <ip> --json
```

Look for:

- recent pearl clusters
- changes in collapse
- temporal folds
- repeated growth pressure

Operator question:

- what is newly measured, what persisted, and what is now stale?

## AI Use

Use AI only to:

- explain current substrate state
- summarize folds and growth pressure
- draft actions or reports
- prepare human-readable views

Do not use AI to:

- assign substrate state
- erase uncertainty
- invent causal links

Operator question:

- is the AI describing SKG state, or trying to replace it?

## Closeout

Before ending, confirm:

- measured paths are separated from unresolved paths
- folds are included, not hidden
- proposal state is preserved
- pearls reflect the run

Check:

```bash
skg report --target <ip>
skg proposals list --status all
skg status --self-audit
```

Final operator question:

- did this run improve the measured model of the system, or only re-state what we already expected?
