# SKG UI Minimum Viable Surface

Purpose: define the smallest useful UI for SKG without flattening the substrate into a generic dashboard.

The UI should be:

- a field/intelligence plane
- read-mostly at first
- centered on SKG objects

The CLI remains:

- the control plane
- the debugging plane
- the precise operator interface

## UI Goals

The minimum viable UI should let an operator see:

- what exists
- what is measured
- what is unresolved
- what changed
- where pressure is accumulating
- what action is being proposed

## Required Views

### 1. Field View

Shows:

- identities
- manifestations
- domains
- services
- current energy/priority cues
- fold pressure

Purpose:

- orient the operator in the field quickly

### 2. Target View

Shows for one identity:

- current attack-path projections
- realized / blocked / indeterminate paths
- service/domain context
- recent pearls
- recent fold pressure
- proposal pressure

Purpose:

- make one target legible as measured structure over time

### 3. Fold View

Shows:

- fold type
- target identity
- weight
- why it exists
- whether it is target-side or SKG-side insufficiency
- clustered related folds

Purpose:

- make structural insufficiency a first-class operator object

### 4. Proposal View

Shows:

- active proposals
- type (`field_action`, `toolchain_generation`, `catalog_growth`)
- growth-memory reinforcement
- linked fold ids
- dry-run command or next action

Purpose:

- make operator review actionable and grounded

### 5. Memory View

Shows:

- recent pearls
- pearl clusters
- manifold neighborhoods
- repeated reinforced wickets
- repeated proposal/fold pressure

Purpose:

- let the operator understand persistence and recurrence

## First Interaction Model

The first UI does not need full control capability.

It can start with:

- read-only substrate views
- proposal detail panes
- operator copyable commands
- assistant explanations tied to visible substrate objects

That is enough to make SKG legible without prematurely overbuilding control widgets.

## Things The UI Must Avoid

The UI should not default to:

- severity dashboards
- vulnerability ticket grids
- scanner-style finding tables as the main frame
- flattened “risk scores” with no substrate trace

Those destroy the ontology SKG is trying to preserve.

## Assistant In The UI

The assistant should appear as:

- a contextual explainer
- a summarizer
- a drafter of next action

It should speak from currently visible substrate state.

## Minimum Build Sequence

1. Field view
2. Target view
3. Fold/proposal view
4. Assistant explanation panel
5. Memory view

## Immediate Next Step

After this document, the next practical step is to define the first implementation slice:

- routes/pages
- data sources
- operator interactions
- which assistant prompts are tied to which view
