# SKG Red-Team Playbook

Purpose: define how an operator runs an engagement with SKG and how the available instruments fit into that workflow.

This is a proving-ground playbook, not a fixed doctrine.

## Core Rule

The operator does not ask:
- "what should I exploit next?"

The operator asks:
- "what is measured?"
- "what remains unresolved?"
- "what effect did that action produce?"
- "where is the cheapest next observation?"

SKG preserves those answers.

## Engagement Flow

### 1. Form The Surface

Primary aim:
- discover identities, manifestations, domains, services, and initial unknown regions

Primary instruments:
- `nmap`
- `pcap`
- `http_collector`
- `nvd_feed`

Primary artifacts:
- surface snapshots
- raw events
- early projections
- first folds

### 2. Collapse Initial Access

Primary aim:
- determine whether initial footholds are realized, blocked, or indeterminate

Primary instruments:
- `http_collector`
- `auth_scanner`
- `ssh_sensor`
- `metasploit`
- `ai_probe`

Primary artifacts:
- realized/blocked/indeterminate foothold paths
- observation confirmations
- fold pressure where the current model is thin

### 3. Expand From Foothold

Primary aim:
- measure what access actually allows

Primary instruments:
- `ssh_sensor`
- `sysaudit`
- `container_inspect`
- `data_profiler`
- `binary_analysis`
- `bloodhound`

Primary artifacts:
- post-foothold consequences
- persistence/integrity observations
- local service and data exposure
- follow-on path collapse

### 4. Grow The Model

Primary aim:
- convert repeated missing structure into explicit operator-reviewable growth

Primary sources:
- structural folds
- contextual folds
- projection folds
- repeated pearl/manifold pressure

Primary outputs:
- `toolchain_generation` proposals
- `catalog_growth` proposals

### 5. Re-Observe And Compare

Primary aim:
- distinguish current measured state from stale remembered state

Primary structures:
- pearls
- pearl manifold
- temporal folds
- recall summaries

Primary operator question:
- "what changed, what persisted, and what is decayed?"

## Instrument Map

### Surface / Network

- `nmap`
  - service detection
  - version fingerprinting
  - network-level surface formation
- `pcap`
  - interaction seen on the wire
  - useful when app-layer output is misleading or partial

### Web

- `http_collector`
  - unauthenticated HTTP recon
  - headers, paths, forms, baseline injection surface
- `auth_scanner`
  - authenticated scanning
  - CSRF-aware login, post-auth paths and injection checks

### Host / Access

- `ssh_sensor`
  - SSH auth, shell, sudo, SUID, kernel, host context
- `metasploit`
  - auxiliary and exploit modules
  - crossing mechanism, not the source of state truth

### Integrity / Post-Exploitation

- `sysaudit`
  - filesystem, processes, logs, integrity and persistence conditions
- `binary_analysis`
  - mitigations, dangerous functions, gadget density, exploitability constraints
- `container_inspect`
  - Docker/container conditions for escape and privilege implications

### Data / AD / IoT / Supply Chain / AI

- `data_profiler`
  - schema, integrity, completeness, drift, freshness
- `bloodhound`
  - AD object graph and lateral conditions
- `iot_firmware`
  - firmware and embedded exposure
- `supply_chain`
  - SBOM and package vulnerability pressure
- `ai_probe`
  - AI/ML target observation as a measured domain

## What The Operator Should Preserve

Every serious engagement should preserve:

- surface snapshots
- raw event files
- interpreted projections
- folds
- proposals
- pearl memory
- operator-triggered actions
- final engagement summary

## AI Assistant In The Playbook

AI may help:

- explain current state
- summarize folds and points of interest
- draft tool invocations and operator notes
- compare current state to prior pearls
- render the picture SKG is drawing in human terms

AI may not:

- declare substrate state on its own
- erase indeterminacy
- fabricate causal links not supported by observations

## Operator-Only Decisions

These should stay explicitly operator-controlled:

- accepting model growth
- destructive exploitation steps
- irreversible changes to targets
- claims in final reporting that exceed measured state

## AI-Assisted But Substrate-Bound Actions

These are good AI-assist targets:

- parsing large outputs
- preparing commands
- clustering related folds
- drafting growth proposals
- summarizing why gravity is favoring a target or instrument

## What Counts As A Good Engagement

A good SKG engagement is not one with the most events.

It is one where:

- the operator can see what is measured
- unresolved regions stay explicit
- cause and effect are preserved over time
- folds meaningfully drive growth
- memory improves later decisions

## Next Step

The next document should define the artifact checklist and operator workflow for one full sample engagement:

- target intake
- surface formation
- foothold collapse
- post-foothold measurement
- fold handling
- proposal review
- closeout
