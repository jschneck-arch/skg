# SKG Red-Team Engagement Model

Purpose: define how SKG is used in a real engagement without collapsing back into scanner workflow or narrative reporting.

This is a proving-ground document.

Cyber and red teaming are not the final scope of SKG, but they are the correct first domain because they force:

- bounded observation
- hostile conditions
- incomplete information
- measurable cause and effect
- changing state over time
- costly decisions under uncertainty

## What SKG Is During An Engagement

SKG is the observational substrate of the engagement.

It does not replace the operator.
It does not replace instruments.
It does not declare final truth.

It does:

- preserve measured state over time
- represent unsupported state as unresolved
- retain cause/effect traces as pearls, folds, and projection changes
- route attention toward high-value measurement
- preserve model-growth pressure when the current structure is insufficient

## Engagement Phases

### 1. Surface Formation

Goal:
- establish the initial field of identities, manifestations, domains, services, and unknown regions

Typical SKG work:
- target intake
- discovery
- nmap and passive network observation
- initial domain inference
- first fold generation

Operator output:
- a measured surface, not a claims list

### 2. Foothold Observation

Goal:
- determine whether initial-access paths are realized, blocked, or indeterminate

Typical SKG work:
- host/web/AI/data/domain-specific attack-path projection
- credential validation
- authenticated versus unauthenticated differentiation
- recording why a path collapsed as it did

Operator output:
- a constrained set of viable footholds, not generic “findings”

### 3. Post-Foothold Expansion

Goal:
- measure consequences of realized access

Typical SKG work:
- post-exploitation observation
- privilege and persistence checks
- local service and data exposure checks
- container and binary follow-on paths

Operator output:
- measured consequences of access, not assumed blast radius

### 4. Structural Growth

Goal:
- handle repeated missing structure without pretending the current model already covers it

Typical SKG work:
- folds
- catalog growth proposals
- toolchain generation proposals
- clustered model pressure by host/domain/service family

Operator output:
- explicit model deficit and candidate growth, not silent omission

### 5. Recall And Re-Observation

Goal:
- use remembered observation and prior collapses without treating them as permanent

Typical SKG work:
- pearl manifold
- temporal folds
- observation confirmation history
- identity-aware recall across manifestations

Operator output:
- state with remembered context and explicit decay, not stale certainty

### 6. Reporting

Goal:
- present the measured state of the engagement in human-usable form

Typical SKG work:
- surface
- report
- proposal queue
- pearl clusters
- fold summary

Operator output:
- a human-readable version of substrate state

## What The Operator Sees

The operator should see a human-usable rendering of:

- identities
- manifestations
- domains
- projections
- folds
- recent pearls
- growth pressure
- next observation pressure

The operator should not be forced to parse raw events unless needed.

The operator should also not be shown invented certainty.

## What Makes An Engagement “With SKG”

An engagement counts as an SKG engagement if:

1. the system preserves observations and changes over time
2. attack reasoning is expressed through projections, not ad hoc assertions
3. unresolved structure is surfaced as folds
4. model insufficiency becomes explicit growth pressure
5. operator actions and substrate changes can be traced back to measurements

If those conditions are missing, SKG is only being used as a wrapper around tools.

## Core Engagement Artifacts

An SKG red-team engagement should preserve at least:

- target surface snapshots
- raw events
- interpreted projections
- folds
- proposals
- pearl records
- operator-triggered actions
- final operator report

## Success Criteria

The proving-ground question is not:
- “did SKG find more CVEs?”

The proving-ground question is:
- “did SKG help the operator maintain better measured state and make better decisions under uncertainty?”

Useful evidence includes:

- fewer repeated dead-end actions
- clearer collapse of paths to realized/blocked/indeterminate
- better preservation of cause/effect through foothold and post-foothold phases
- explicit model-growth pressure when the system is underspecified
- stronger operator recall across time and manifestations

## Immediate Next Step

The next operational step after this document is to define:

- the SKG operator assistant contract
- the red-team playbook of instruments and decision points
- the artifact checklist for a full SKG engagement
