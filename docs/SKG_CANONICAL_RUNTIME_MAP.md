# SKG Canonical Runtime Map

Purpose: preserve the full SKG workspace while making the active runtime shape explicit.

This is a classification document, not a deletion plan.

Operationally: there is one live SKG runtime and one preserved deploy mirror.

## Canonical Live Runtime

These paths are the current primary implementation surface and should be treated as authoritative unless a specific experiment says otherwise.

- `/opt/skg/bin/skg`
  - primary operator CLI
- `/opt/skg/skg`
  - primary Python package for kernel, substrate, sensors, forge, resonance, identity, graph, intel
- `/opt/skg/skg-gravity`
  - active gravity loop and orchestration
- `/opt/skg/skg-*-toolchain`
  - active domain toolchains
  - examples:
    - `/opt/skg/skg-host-toolchain`
    - `/opt/skg/skg-web-toolchain`
    - `/opt/skg/skg-data-toolchain`
    - `/opt/skg/skg-container-escape-toolchain`
    - `/opt/skg/skg-ad-lateral-toolchain`
    - `/opt/skg/skg-ai-toolchain`
    - `/opt/skg/skg-binary-toolchain`
    - `/opt/skg/skg-iot_firmware-toolchain`
    - `/opt/skg/skg-supply-chain-toolchain`
- `/opt/skg/tests`
  - top-level focused regression tests for live runtime integration

## Canonical Stateful Runtime Data

These are the primary runtime/state locations that current code should read and write.

- `/var/lib/skg/events`
- `/var/lib/skg/discovery`
- `/var/lib/skg/interp`
- `/var/lib/skg/cve`
- `/var/lib/skg/proposals`
- `/var/lib/skg/proposals_accepted`
- `/var/lib/skg/proposals_rejected`
- `/var/lib/skg/proposals_superseded`
- `/var/lib/skg/pearls.jsonl`
- `/var/lib/skg/resonance`

Rule:
- prefer `/var/lib/skg/pearls.jsonl` over `/opt/skg/pearls.jsonl`
- prefer `/var/lib/skg/*` state over ad hoc local mirrors unless explicitly running offline fixtures

## Staging And Generated Artifacts

These are useful and part of SKG, but they are not primary runtime source.

- `/opt/skg/forge_staging`
  - generated or staged toolchains under review
- `/opt/skg/resonance`
  - local resonance workspace and records under repo root
- `/opt/skg/feeds`
  - feed/cache inputs and utilities

## Legacy / Mirror Trees

These should be preserved, but treated as mirrors, deployment copies, or historical branches unless explicitly selected.

- `/opt/skg/skg_deploy`
  - deployment mirror with older copies of:
    - `bin`
    - `skg`
    - `skg-gravity`
    - domain toolchains
  - do not assume semantic parity with live runtime
  - changes here should be deliberate, not incidental

- `/opt/skg/skg-web-toolchain.backup`
  - backup copy, not canonical live web path

## Research / Reference Material

- `/opt/skg/docs`
  - theory, runtime direction, canonical model notes, session continuation
- `/opt/skg/skg_paper_evidence.py`
  - research/evidence support, not primary runtime control

## Working Rules

When changing SKG:

1. Change canonical live runtime first.
2. Treat deploy/backup trees as mirrors unless the task is explicitly deployment-oriented.
3. Do not delete legacy trees just to simplify navigation.
4. If a new path becomes canonical, update this map.
5. If a state path differs between components, normalize toward `/var/lib/skg`.

## Current Drift To Watch

- `skg_deploy` still contains older semantics and duplicate codepaths.
- some proposal/status/report surfaces were historically written before `catalog_growth` existed
- some topology/research modules may still reflect older state-loading logic than the live kernel/substrate path

## Practical Interpretation

If a question is "what is SKG doing right now?", start here:

1. `/opt/skg/bin/skg`
2. `/opt/skg/skg`
3. `/opt/skg/skg-gravity`
4. `/opt/skg/skg-*-toolchain`
5. `/var/lib/skg/*`

If a question is "what else exists in the repo?", then include:

1. `/opt/skg/skg_deploy`
2. `/opt/skg/skg-web-toolchain.backup`
3. `/opt/skg/forge_staging`
4. `/opt/skg/docs`
