# SKG AI Assistant Contract

Purpose: define the role of AI in SKG without allowing it to become the substrate.

AI is an instrument and operator assistant.
AI is not the source of measured state.
AI is a cross-cutting SKG layer, not a gravity-only feature.
SKG directs AI work and provides the context AI is allowed to see.

## AI Is Allowed To

- summarize substrate state for humans
- explain folds, projections, and proposal pressure
- draft operator actions
- help select and invoke tools under operator control
- parse and translate instrument output into human-readable form
- compare current state to remembered state
- assist with reporting
- help identify candidate next measurements
- synthesize mutation artifacts such as `.rc` scripts, UI patches, code changes, and toolchain scaffolds
- return reconciliation claims when remembered structure and fresh observation appear to diverge
- relay raw evidence only when the artifact remains unaltered and chain of custody is preserved

## AI Is Not Allowed To

- assign realized/blocked/unknown state by itself
- invent observations
- override substrate uncertainty
- silently transform unsupported inference into measured state
- replace instrument evidence
- rewrite the append-only observational record
- decide final action for SKG
- narrow the admissible instrument set to a single forced choice
- write live state without observation passing through the normal support and collapse path

## AI Inputs

AI should work from SKG objects, not free-floating narrative whenever possible:

- surface
- projections
- folds
- pearls
- proposal queue
- recall summaries
- operator constraints

SKG may query AI from any layer:

- substrate interpretation
- gravity and field selection
- forge and proposal drafting
- state reconciliation
- mutation and toolchain synthesis
- operator UI and reporting

## AI Outputs

AI outputs should be treated as one of:

- `derived_advice`
- `mutation_artifact`
- `reconciliation_claim`
- `observed_evidence` only when custody is complete

They are not canonical state.

## Observation Boundary

Only `observed_evidence` may enter the observation plane.

If AI relays evidence into SKG, the record must carry a complete custody chain:

- artifact path or artifact reference
- artifact hash
- source command, pointer, or URI
- collection timestamp

If that custody chain is incomplete, the output remains advisory and must not be admitted as observation.

AI summaries, hypotheses, explanations, or reconciliation claims are never observational truth by themselves.

## Authority Rule

The authority chain is:

- SKG asks the question
- AI returns structured help
- SKG decides what to do
- observation updates state

Pearls and AI memory work the same way: they shape attention and priority, but they do not dictate present-tense state.

## Operator Relationship

AI is an extra hand for the operator.

It can:

- move instruments
- help parse outputs
- draft actions and reports
- describe the picture SKG is drawing

It cannot replace:

- the operator’s judgment
- the substrate’s measurement boundary
- the instrument layer
- SKG’s decision authority

## Red-Team Use

In a red-team context, AI is most useful for:

- engagement narration from substrate state
- action sequencing suggestions
- comparison between current and prior target states
- summarizing why gravity is pulling toward a target or instrument
- drafting engagement notes and closeout material

## Constraint

If an AI claim cannot be traced back to:

- an observation
- a support contribution
- a projection
- a fold
- a pearl
- or an operator instruction

then it does not belong in SKG state.
