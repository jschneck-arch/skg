# SKG Facet Readiness Matrix

Purpose: assess whether SKG is materially ready for a proving-ground engagement.

This is a readiness matrix, not a claim of completion.

Statuses used here:

- `ready`
  - usable in a proving-ground engagement now
- `partial`
  - functional, but with known gaps or weaker validation
- `blocked`
  - cannot be meaningfully validated yet because a dependency or environment piece is missing

## Runtime Facets

### Host

- status: `ready`
- reason:
  - active adapters, contracts, projections, tests
  - live SSH and host projection loop validated
  - support-aware host projection in place

### Web

- status: `ready`
- reason:
  - live projection path and surface integration fixed
  - active adapters and projections present
  - no dedicated toolchain-local tests, but live runtime path is working

### Data

- status: `ready`
- reason:
  - active adapters, projections, tests
  - live profiler/projection loop validated

### Container Escape

- status: `ready`
- reason:
  - active adapters, projections, tests
  - collapse semantics and live path validated

### Binary

- status: `partial`
- reason:
  - live path works
  - exploitability constraints are being measured
  - depth still depends on local analysis tooling and richer reachability analysis

### AI Target

- status: `ready`
- reason:
  - live TinyLlama/Ollama target path validated
  - active adapters and projections present
  - proving usage as observed target is working

### AD / BloodHound

- status: `blocked`
- reason:
  - collector/projection path is repaired
  - meaningful validation still depends on a populated AD graph

### Supply Chain

- status: `partial`
- reason:
  - active adapters and projections present
  - live canonical state exists
  - weaker direct test coverage than host/data/container

### IoT Firmware

- status: `partial`
- reason:
  - active adapters and projections present
  - canonical state exists
  - weaker direct validation coverage than core domains

### Post-Exploitation / Session Crossing

- status: `ready`
- reason:
  - real foothold-to-post-exp path validated on Metasploitable
  - SSH fallback closed a real runtime gap

## Substrate Facets

### Support-Aware Collapse

- status: `ready`
- reason:
  - main projection boundary now uses aggregated support
  - priority path also support-aware

### Identity / Manifestation

- status: `partial`
- reason:
  - bridge exists across surface, daemon, graph, folds, pearls, memory
  - runtime contract still primarily uses `workload_id`

### Projections

- status: `ready`
- reason:
  - live projection refresh loop is functioning across major domains

### Folds

- status: `ready`
- reason:
  - structural, contextual, projection, temporal model exists
  - fold handling now better connected to growth

### Pearls

- status: `ready`
- reason:
  - append-only memory is active
  - observation confirmations now preserved

### Pearl Manifold

- status: `partial`
- reason:
  - live and feeding gravity/proposals
  - still depends on richer pearl structure to become stronger across all domains

### Growth Memory

- status: `ready`
- reason:
  - proposal lifecycle is pearled
  - growth memory now feeds proposal recall and ordering

## Operator Facets

### Surface / Report / Status

- status: `ready`
- reason:
  - materially improved coherence
  - now includes growth backlog and proposal memory cues

### Proposal Review

- status: `ready`
- reason:
  - `field_action`, `toolchain_generation`, and `catalog_growth` are now distinct and operator-reviewable

### Self-Audit

- status: `partial`
- reason:
  - useful
  - still primarily counts structures rather than explaining reflexive insufficiency in depth

## AI Assistant Facets

### Contract / Role

- status: `ready`
- reason:
  - explicit docs now define AI as assistant/instrument, not substrate

### Runtime Integration

- status: `partial`
- reason:
  - AI target observation is working
  - AI-on-SKG operator-assistant behavior is documented but not yet fully built as a dedicated assistant layer

## Repository Shape Facets

### Canonical Runtime Map

- status: `ready`
- reason:
  - canonical runtime map now exists

### Duplicate / Mirror Trees

- status: `partial`
- reason:
  - preserved intentionally
  - still a source of semantic drift if treated casually

## Current Blocking Item

The main environment-level block for full proving coverage is:

- meaningful AD/BloodHound validation with real graph data

## Overall Readiness

Overall state:

- SKG is ready for proving-ground engagements in the core cyber/red-team path
- some peripheral domains remain partial
- AD/BloodHound remains the main blocked facet

This is sufficient to begin real proving runs, provided the engagement is explicit about which facets are in-scope and which remain partial or blocked.
