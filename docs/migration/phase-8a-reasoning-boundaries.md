# Phase 8A Reasoning Boundaries

Date: 2026-04-04

## Objective

Introduce `packages/skg-reasoning` as a new canonical layer (`SKG-R`) that:
- consumes canonical domain events and protocol context contracts,
- derives higher-order reasoning outputs,
- stays strictly downstream of domain and service semantics.

## Ownership Boundaries

| Concern | Owner | Canonical path |
|---|---|---|
| AD-06 / AD-08 posture semantics | AD domain | `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_delegation_posture/run.py` |
| AD-07 freshness/context semantics and routing | protocol + services | `packages/skg-protocol/src/skg_protocol/contracts/ad_delegation_context.py`, `packages/skg-services/src/skg_services/gravity/ad_runtime.py` |
| Path/value/attacker-usefulness derivation | reasoning layer | `packages/skg-reasoning/src/skg_reasoning/delegation_engine.py` |

## Explicit Boundary Rules Enforced

1. Reasoning does not redefine AD wicket semantics.
2. Reasoning consumes canonical contracts:
   - `skg.ad.delegation_context.v1`
   - canonical `obs.attack.precondition` event payload statuses for `AD-06` / `AD-08`
3. Reasoning output is derived-only and versioned:
   - `schema = skg.reasoning.delegation_evaluation.v1`
4. Reasoning does not emit raw observations or event envelopes.
5. Reasoning package has no imports from:
   - `skg_domain_*`
   - `skg_services.*`
   - legacy `skg/*` runtime modules

## Pilot Scope (Delegation)

- Inputs:
  - canonical AD posture events (`AD-06`, `AD-08`)
  - AD-07 context contract (`skg.ad.delegation_context.v1`)
- Outputs:
  - `path_pressure`
  - `value_pressure`
  - `attacker_usefulness`
  - confidence + explanation
- Deferred by design:
  - AD-09 sensitive-target semantics
  - attack-path chaining
  - runtime transport coupling
