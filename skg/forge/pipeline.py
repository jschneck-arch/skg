"""
skg.forge.pipeline
===================
Auto-trigger pipeline — runs after every sweep in UNIFIED mode.

Called by SensorLoop after _auto_project_all completes.
Full flow:
  1. detect_new_gaps()        — scan event files for uncovered services
  2. filter cooldowns         — skip domains in rejection cooldown
  3. generate_toolchain()     — catalog + adapter + projector
  4. validate()               — structural + import + synthetic
  5. create proposal()        — queue for operator review
  6. log summary              — what was found, what was proposed
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("skg.forge.pipeline")


def run_forge_pipeline(
    events_dir: Path | None = None,
    resonance_engine=None,
    staging_dir: Path | None = None,
) -> dict:
    """
    Full forge pipeline: gap detection → generation → validation → proposal.

    Returns summary dict of what happened.
    """
    from skg.intel.gap_detector import detect_new_gaps
    from skg.forge.generator import generate_toolchain
    from skg.forge.validator import validate
    from skg.forge import proposals

    summary = {
        "gaps_detected":   0,
        "gaps_skipped":    0,
        "generated":       0,
        "validated":       0,
        "proposed":        0,
        "errors":          [],
        "proposal_ids":    [],
    }

    # Step 1: detect new gaps
    try:
        new_gaps = detect_new_gaps(events_dir)
    except Exception as exc:
        summary["errors"].append(f"Gap detection failed: {exc}")
        log.error(f"[forge] gap detection error: {exc}", exc_info=True)
        return summary

    summary["gaps_detected"] = len(new_gaps)
    if not new_gaps:
        return summary

    log.info(f"[forge] {len(new_gaps)} new gap(s) detected: "
             f"{[g['service'] for g in new_gaps]}")

    # Step 2-5: for each gap
    for gap in new_gaps:
        domain = gap["service"]

        # Skip if in rejection cooldown
        if proposals.is_in_cooldown(domain):
            log.debug(f"[forge] {domain}: in cooldown, skipping")
            summary["gaps_skipped"] += 1
            continue

        # Skip if not forge-ready
        if not gap.get("forge_ready", True):
            log.debug(f"[forge] {domain}: not forge-ready, skipping")
            summary["gaps_skipped"] += 1
            continue

        description = gap.get("attack_surface", f"{domain} attack surface")

        # Step 3: generate
        try:
            gen_result = generate_toolchain(
                domain=domain,
                description=description,
                gap=gap,
                resonance_engine=resonance_engine,
                staging_dir=staging_dir,
            )
            summary["generated"] += 1
        except Exception as exc:
            msg = f"{domain}: generation failed: {exc}"
            summary["errors"].append(msg)
            log.error(f"[forge] {msg}", exc_info=True)
            continue

        if not gen_result.get("success"):
            summary["errors"].extend(gen_result.get("errors", []))
            continue

        staged_path = Path(gen_result["staging_path"])

        # Step 4: validate
        try:
            val_result = validate(staged_path)
            summary["validated"] += 1
            if not val_result["passed"]:
                log.warning(f"[forge] {domain}: validation failed — "
                            f"proposing anyway with warning")
        except Exception as exc:
            val_result = {"passed": False, "checks": {}, "tc_name": domain}
            log.warning(f"[forge] {domain}: validator error: {exc}")

        # Step 5: create proposal
        try:
            proposal = proposals.create(
                domain=domain,
                description=description,
                gap=gap,
                generation_result=gen_result,
                validation_result=val_result,
            )
            summary["proposed"] += 1
            summary["proposal_ids"].append(proposal["id"])
            log.info(f"[forge] proposal created: {proposal['id'][:8]} "
                     f"({domain}, {gen_result.get('wicket_count',0)} wickets, "
                     f"validation={'PASS' if val_result.get('passed') else 'FAIL'})")
        except Exception as exc:
            summary["errors"].append(f"{domain}: proposal creation failed: {exc}")
            log.error(f"[forge] proposal error: {exc}", exc_info=True)

    if summary["proposed"] > 0:
        log.info(
            f"[forge] pipeline complete: {summary['proposed']} proposal(s) ready — "
            f"run 'skg proposals list' to review"
        )

    return summary
