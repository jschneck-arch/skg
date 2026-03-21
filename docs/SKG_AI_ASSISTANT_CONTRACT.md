# SKG AI Assistant Contract

Purpose: define the role of AI in SKG without allowing it to become the substrate.

AI is an instrument and operator assistant.
AI is not the source of measured state.

## AI Is Allowed To

- summarize substrate state for humans
- explain folds, projections, and proposal pressure
- draft operator actions
- help select and invoke tools under operator control
- parse and translate instrument output into human-readable form
- compare current state to remembered state
- assist with reporting
- help identify candidate next measurements

## AI Is Not Allowed To

- assign realized/blocked/unknown state by itself
- invent observations
- override substrate uncertainty
- silently transform unsupported inference into measured state
- replace instrument evidence
- rewrite the append-only observational record

## AI Inputs

AI should work from SKG objects, not free-floating narrative whenever possible:

- surface
- projections
- folds
- pearls
- proposal queue
- recall summaries
- operator constraints

## AI Outputs

AI outputs should be treated as one of:

- explanation
- draft
- suggestion
- orchestration hint
- human-readable rendering

They are not canonical state.

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

## Immediate Next Step

The next step after this contract is to define:

- which operator actions the AI may trigger directly
- which require explicit operator approval
- how AI should read and present pearl/fold/proposal memory during an engagement
