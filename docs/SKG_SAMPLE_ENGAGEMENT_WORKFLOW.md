# SKG Sample Engagement Workflow

Purpose: define one complete SKG proving-ground run from intake to closeout, including what should be preserved and what constitutes a successful engagement.

This is a workflow template, not a rigid script.

## Engagement Goal

Demonstrate that SKG can:

- form a measured surface
- collapse attack paths honestly
- preserve cause/effect over time
- expose unresolved structure as folds
- cluster growth pressure
- support operator action without replacing operator judgment

## Phase 0: Intake

Operator tasks:

- define target scope
- define constraints
- define which actions require explicit approval
- define whether the run is exploratory, validation-focused, or growth-focused

SKG artifacts to preserve:

- initial scope note
- target list
- constraints
- operator intent

Minimum output:

- a known initial scope boundary

## Phase 1: Surface Formation

Operator tasks:

- add targets
- trigger initial discovery
- confirm the resulting surface is plausible

Likely instruments:

- `nmap`
- `pcap`
- `http_collector`
- `nvd_feed`

SKG artifacts to preserve:

- surface snapshot
- raw discovery events
- initial interpreted projections
- initial folds

Success condition:

- SKG produces a measured field of identities, domains, and services
- unknowns remain explicit

## Phase 2: Initial Access Collapse

Operator tasks:

- allow gravity and/or directed actions to test initial footholds
- compare multiple routes where appropriate
- verify why a path is realized, blocked, or indeterminate

Likely instruments:

- `http_collector`
- `auth_scanner`
- `ssh_sensor`
- `metasploit`
- `ai_probe`

SKG artifacts to preserve:

- foothold-related events
- fresh `interp`
- proposal changes
- pearls from the cycle

Success condition:

- SKG expresses footholds as constrained paths, not generic findings

## Phase 3: Post-Foothold Measurement

Operator tasks:

- observe consequences of realized access
- avoid assuming blast radius
- confirm which follow-on conditions are real, blocked, or unresolved

Likely instruments:

- `ssh_sensor`
- `sysaudit`
- `container_inspect`
- `data_profiler`
- `binary_analysis`
- `bloodhound`

SKG artifacts to preserve:

- post-exp events
- updated projections
- new folds
- pearls showing state change and confirmations

Success condition:

- access consequences are measured and preserved over time

## Phase 4: Fold Handling

Operator tasks:

- review high-weight folds
- distinguish target-side insufficiency from SKG-side insufficiency
- decide whether a fold calls for:
  - re-observation
  - catalog growth
  - toolchain growth
  - deferred investigation

AI-assist opportunities:

- cluster related folds
- explain fold type and origin
- draft dry-run growth actions

SKG artifacts to preserve:

- fold summaries
- growth proposals
- superseded proposals
- pearl-backed proposal lifecycle memory

Success condition:

- unresolved structure becomes explicit pressure, not silent omission

## Phase 5: Recall And Comparison

Operator tasks:

- compare current state to prior pearls and folds
- identify what changed, what persisted, and what decayed
- avoid treating remembered state as permanent fact

AI-assist opportunities:

- render differences in human terms
- connect current pressure to prior engagement structure

SKG artifacts to preserve:

- report snapshots
- recall summary
- pearl clusters
- temporal folds

Success condition:

- the engagement shows measured cause/effect over time, not just a single scan moment

## Phase 6: Closeout

Operator tasks:

- review what was actually measured
- separate measured conditions from suggestions or interpretation
- review folds and growth pressure as part of the outcome, not just realized paths

AI-assist opportunities:

- draft closeout summary
- explain structural pressure
- summarize why certain paths remained indeterminate

Final artifacts to preserve:

- target-scoped report
- active folds
- proposal state
- pearl summary
- operator notes
- final action/decision trace

Success condition:

- the closeout reflects measured state, unresolved state, and model pressure

## Artifact Checklist

For a complete SKG engagement, preserve:

- target scope input
- surface snapshot(s)
- raw events
- interpreted projections
- folds
- proposals
- pearls
- operator-triggered actions
- final report

## AI Checklist

AI may help with:

- explanation
- clustering
- drafting
- summarization
- command preparation

AI may not:

- invent measurements
- erase indeterminacy
- replace the substrate record

## What Counts As Success

An SKG proving-ground run is successful if it demonstrates:

1. honest path collapse
2. preserved cause/effect over time
3. meaningful folds
4. remembered structural pressure
5. improved operator orientation under uncertainty

It is not enough to show:

- many events
- many CVEs
- many exploits
- visually impressive output

The key question is:

- did SKG help maintain a better measured model of the engagement over time?

## Next Step

After this workflow, the next useful artifact is a concrete red-team operator checklist tied to actual commands and outputs.
