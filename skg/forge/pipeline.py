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

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg_core.config.paths import SKG_STATE_DIR

log = logging.getLogger("skg.forge.pipeline")

METACOGNITION_SIGNAL_DIR = SKG_STATE_DIR / "metacognition" / "signals"
COGNITIVE_SIGNAL_DIR = SKG_STATE_DIR / "cognitive" / "signals"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mc03_signal_from_gap(gap: dict[str, Any]) -> dict[str, Any]:
    hosts = [str(host) for host in gap.get("hosts", []) if host]
    service = str(gap.get("service", "") or "unknown")
    detail = str(gap.get("detail", "") or f"Coverage gap detected for {service}")
    return {
        "id": str(uuid.uuid4()),
        "ts": _iso_now(),
        "schema_version": "1.0.0",
        "kind": "substrate.metacognition.signal",
        "expression": "metacognition",
        "signal_id": "MC-03",
        "label": "coverage_gap_detected",
        "status": "realized",
        "trigger_reason": "service_class_with_no_catalog_wickets",
        "service": service,
        "category": str(gap.get("category", "unknown")),
        "hosts": hosts,
        "hosts_count": len(hosts),
        "evidence": str(gap.get("evidence", "") or ""),
        "detail": detail,
        "attack_surface": str(gap.get("attack_surface", "") or ""),
        "collection_hints": [str(hint) for hint in gap.get("collection_hints", [])[:8]],
        "forge_ready": bool(gap.get("forge_ready", True)),
    }


def _proposal_trigger_from_signal(signal: dict[str, Any]) -> dict[str, Any]:
    return {
        "expression": signal.get("expression", "metacognition"),
        "signal_id": signal.get("signal_id", "MC-03"),
        "label": signal.get("label", "coverage_gap_detected"),
        "status": signal.get("status", "realized"),
        "service": signal.get("service", ""),
        "detail": signal.get("detail", ""),
        "trigger_reason": signal.get("trigger_reason", ""),
        "signal_ref": signal.get("id", ""),
    }


def _write_metacognition_signals(signals: list[dict[str, Any]]) -> Path | None:
    if not signals:
        return None

    METACOGNITION_SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = METACOGNITION_SIGNAL_DIR / f"coverage_gap_{stamp}_{uuid.uuid4().hex[:8]}.ndjson"
    with out.open("w", encoding="utf-8") as fh:
        for signal in signals:
            fh.write(json.dumps(signal) + "\n")
    return out


def _write_cognitive_signals(signals: list[dict[str, Any]]) -> Path | None:
    if not signals:
        return None

    COGNITIVE_SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = COGNITIVE_SIGNAL_DIR / f"candidate_generation_{stamp}_{uuid.uuid4().hex[:8]}.ndjson"
    with out.open("w", encoding="utf-8") as fh:
        for signal in signals:
            fh.write(json.dumps(signal) + "\n")
    return out


def _cp01_signal_from_proposal(gap: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
    hosts = [str(host) for host in gap.get("hosts", []) if host]
    service = str(gap.get("service", "") or proposal.get("domain", "") or "unknown")
    return {
        "id": str(uuid.uuid4()),
        "ts": _iso_now(),
        "schema_version": "1.0.0",
        "kind": "cognitive.proposal.signal",
        "namespace": "cognitive_probe",
        "signal_id": "CP-01",
        "label": "toolchain_candidate_generated",
        "status": "realized",
        "service": service,
        "hosts": hosts,
        "hosts_count": len(hosts),
        "proposal_id": str(proposal.get("id", "")),
        "proposal_kind": str(proposal.get("proposal_kind", "")),
        "detail": f"Candidate toolchain for {service} generated and staged for operator review.",
        "trigger_reason": "forge_candidate_ready",
        "source_trigger": ((proposal.get("metacognition_trigger") or {}).get("signal_id") or ""),
    }


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
        "mc03_realized":   0,
        "mc03_signal_file": None,
        "cp01_generated":  0,
        "cp01_signal_files": [],
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

    triggered_gaps: list[dict[str, Any]] = []
    mc03_signals = [_mc03_signal_from_gap(gap) for gap in new_gaps]
    summary["mc03_realized"] = len(mc03_signals)
    if mc03_signals:
        try:
            signal_file = _write_metacognition_signals(mc03_signals)
            summary["mc03_signal_file"] = str(signal_file) if signal_file else None
            log.info(
                f"[forge] metacognition: {len(mc03_signals)} MC-03 coverage-gap signal(s) realized"
            )
        except Exception as exc:
            summary["errors"].append(f"Metacognition signal write failed: {exc}")
            log.warning(f"[forge] metacognition signal write error: {exc}")
        for gap, signal in zip(new_gaps, mc03_signals):
            triggered_gap = dict(gap)
            triggered_gap["metacognition_trigger"] = _proposal_trigger_from_signal(signal)
            triggered_gaps.append(triggered_gap)
    else:
        triggered_gaps = [dict(gap) for gap in new_gaps]

    log.info(f"[forge] {len(new_gaps)} new gap(s) detected: "
             f"{[g['service'] for g in new_gaps]}")

    # Step 2-5: for each gap
    cp01_signals: list[dict[str, Any]] = []
    for gap in triggered_gaps:
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
            cp01_signal = _cp01_signal_from_proposal(gap, proposal)
            cp01_signals.append(cp01_signal)
            proposal["cognitive_signal"] = cp01_signal
            proposals._proposal_path(proposal["id"]).write_text(json.dumps(proposal, indent=2))
            log.info(f"[forge] proposal created: {proposal['id'][:8]} "
                     f"({domain}, {gen_result.get('wicket_count',0)} wickets, "
                     f"validation={'PASS' if val_result.get('passed') else 'FAIL'})")
        except Exception as exc:
            summary["errors"].append(f"{domain}: proposal creation failed: {exc}")
            log.error(f"[forge] proposal error: {exc}", exc_info=True)

    if cp01_signals:
        try:
            signal_file = _write_cognitive_signals(cp01_signals)
            summary["cp01_generated"] = len(cp01_signals)
            if signal_file:
                summary["cp01_signal_files"].append(str(signal_file))
        except Exception as exc:
            summary["errors"].append(f"Cognitive signal write failed: {exc}")
            log.warning(f"[forge] cognitive signal write error: {exc}")

    if summary["proposed"] > 0:
        log.info(
            f"[forge] pipeline complete: {summary['proposed']} proposal(s) ready — "
            f"run 'skg proposals list' to review"
        )

    return summary
