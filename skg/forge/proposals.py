"""
skg.forge.proposals
====================
Proposal queue — the operator's interface to generated toolchains.

A proposal is created when:
  1. Gap detector finds an uncovered service
  2. Generator produces a valid staged toolchain
  3. Validator passes structural + import + synthetic checks

Each proposal is a JSON file in PROPOSALS_DIR with:
  {
    id, domain, description, attack_surface, hosts,
    staged_path, validation, generated_at, status,
    wicket_count, path_count, generation_backend,
  }

Status lifecycle:
  pending   → operator hasn't reviewed
  accepted  → operator accepted, toolchain installed
  rejected  → operator rejected, cooldown applied
  deferred  → operator deferred, will re-surface after defer_days

The operator surface (surface.py full_report) includes pending proposals
so they appear naturally in the sweep summary.

CLI:
  skg proposals list              — show all pending proposals
  skg proposals show <id>         — full detail including catalog
  skg proposals accept <id>       — install and activate
  skg proposals reject <id>       — archive, apply 30-day cooldown
  skg proposals defer  <id> [N]   — re-surface in N days (default 7)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from skg.core.paths import SKG_STATE_DIR, SKG_HOME
from skg.kernel.pearls import Pearl, PearlLedger

log = logging.getLogger("skg.forge.proposals")

PROPOSALS_DIR = SKG_STATE_DIR / "proposals"
REJECTED_DIR  = SKG_STATE_DIR / "proposals_rejected"
ACCEPTED_DIR  = SKG_STATE_DIR / "proposals_accepted"
SUPERSEDED_DIR = SKG_STATE_DIR / "proposals_superseded"

DEFAULT_COOLDOWN_DAYS = 30
DEFAULT_DEFER_DAYS    = 7


def _proposal_path(proposal_id: str) -> Path:
    return PROPOSALS_DIR / f"{proposal_id}.json"


def _iter_proposal_records(include_archived: bool = False,
                           include_hidden_deferred: bool = False) -> list[dict]:
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    roots = [PROPOSALS_DIR]
    if include_archived:
        roots.extend([ACCEPTED_DIR, REJECTED_DIR, SUPERSEDED_DIR])

    records: list[dict] = []
    for root in roots:
        if not root.exists():
            continue
        for f in root.glob("*.json"):
            try:
                proposal = json.loads(f.read_text())
            except Exception:
                continue
            if not include_hidden_deferred and proposal.get("status") == "deferred" and proposal.get("defer_until"):
                try:
                    defer_until = datetime.fromisoformat(proposal["defer_until"])
                    if now < defer_until:
                        continue
                except Exception:
                    pass
            records.append(proposal)
    return records


def proposals_for_dedupe(include_archived: bool = True) -> list[dict]:
    """Raw proposal records for internal dedupe decisions."""
    return _iter_proposal_records(
        include_archived=include_archived,
        include_hidden_deferred=True,
    )


def _proposal_pearl_ledger() -> PearlLedger:
    return PearlLedger(SKG_STATE_DIR / "pearls.jsonl")


def _record_proposal_memory(
    proposal: dict,
    reason: str,
    related: list[str] | None = None,
    replacement_id: str | None = None,
) -> None:
    hosts = list(proposal.get("hosts", []) or [])
    host = hosts[0] if hosts else ""
    workload_id = f"growth::{host}" if host else f"growth::{proposal.get('domain', 'unknown')}"
    ledger = _proposal_pearl_ledger()
    ledger.record(Pearl(
        reason_changes=[{
            "kind": "proposal_lifecycle",
            "proposal_kind": proposal.get("proposal_kind"),
            "proposal_id": proposal.get("id"),
            "status": proposal.get("status"),
            "reason": reason,
            "replacement_id": replacement_id,
            "related_ids": list(related or []),
            "category": proposal.get("category"),
            "domain": proposal.get("domain"),
        }],
        energy_snapshot={
            "target_ip": host,
            "workload_id": workload_id,
            "domain": proposal.get("domain"),
            "proposal_kind": proposal.get("proposal_kind"),
            "proposal_status": proposal.get("status"),
        },
        target_snapshot={
            "workload_id": workload_id,
            "hosts": hosts,
            "domain": proposal.get("domain"),
            "proposal_id": proposal.get("id"),
        },
        fold_context=[{
            "proposal_kind": proposal.get("proposal_kind"),
            "proposal_id": proposal.get("id"),
            "fold_ids": list(proposal.get("fold_ids", []) or []),
            "compiler_hints": dict(proposal.get("compiler_hints", {}) or {}),
            "command": proposal.get("action", {}).get("command", ""),
        }],
    ))


def _load_recall_adjustment(domain: str, hosts: list[str] | None = None) -> dict:
    """
    Small bounded confidence modifier from confirmed observation history.

    This does not replace current evidence. It only nudges confidence when
    the substrate has enough closed-loop history to justify it.
    """
    records_path = SKG_STATE_DIR / "resonance" / "records" / "observations.jsonl"
    pearls_path = SKG_STATE_DIR / "pearls.jsonl"
    hosts = hosts or []
    recall = {
        "delta": 0.0,
        "confirmation_rate": None,
        "confirmed": 0,
    }
    if not records_path.exists() and not pearls_path.exists():
        return recall

    confirmed = []
    if records_path.exists():
        for line in records_path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("projection_confirmed") is None:
                continue
            if domain and rec.get("domain") != domain:
                continue
            if hosts:
                wid = str(rec.get("workload_id", ""))
                cond = str(rec.get("wicket_id", ""))
                if not any(h in wid or h in cond for h in hosts):
                    continue
            confirmed.append(rec)

    if len(confirmed) < 3:
        recall["confirmed"] = len(confirmed)
    else:
        realized = sum(1 for rec in confirmed if rec.get("projection_confirmed") == "realized")
        rate = realized / len(confirmed)
        # bounded nudge in [-0.05, +0.05], centered at 0.5
        recall["delta"] = round(max(-0.05, min(0.05, (rate - 0.5) * 0.2)), 4)
        recall["confirmation_rate"] = round(rate, 3)
        recall["confirmed"] = len(confirmed)

    if pearls_path.exists():
        try:
            from skg.kernel.pearl_manifold import load_pearl_manifold
            manifold = load_pearl_manifold(pearls_path)
            pearl_recall = manifold.recall_adjustment(domain=domain, hosts=hosts)
            recall["delta"] = round(
                max(-0.05, min(0.05, float(recall["delta"]) + float(pearl_recall.get("delta", 0.0)))),
                4,
            )
            recall["pearl_manifold"] = pearl_recall
            growth_recall = manifold.growth_adjustment(domain=domain, hosts=hosts)
            recall["delta"] = round(
                max(-0.05, min(0.05, float(recall["delta"]) + float(growth_recall.get("delta", 0.0)))),
                4,
            )
            recall["growth_memory"] = growth_recall
        except Exception:
            pass
    return recall


def _proposal_order_key(proposal: dict) -> tuple:
    active_statuses = {"pending", "triggered", "accepted_preserved_existing"}
    status = str(proposal.get("status", ""))
    status_rank = 0 if status in active_statuses else 1
    recall = proposal.get("recall", {}) or {}
    growth = recall.get("growth_memory", {}) or {}
    growth_delta = 0.0
    try:
        growth_delta = float(growth.get("delta", 0.0) or 0.0)
    except Exception:
        growth_delta = 0.0
    confidence = 0.0
    try:
        confidence = float(proposal.get("confidence", 0.0) or 0.0)
    except Exception:
        confidence = 0.0
    generated_ts = 0.0
    generated = str(proposal.get("generated_at", ""))
    try:
        generated_ts = datetime.fromisoformat(generated).timestamp()
    except Exception:
        generated_ts = 0.0
    return (
        status_rank,
        -growth_delta,
        -confidence,
        -generated_ts,
    )


def _toolchain_maturity(validation_result: dict, generation_result: dict) -> dict:
    checks = validation_result.get("checks", {}) or {}
    stub = checks.get("stub_quality", {}) or {}
    synth = checks.get("synthetic", {}) or {}
    coverage = checks.get("coverage", {}) or {}

    if not validation_result.get("passed", False):
        return {
            "level": "scaffold",
            "reason": "validation_failed",
        }

    missing_checks = len(coverage.get("missing_checks", []) or [])
    warnings = len(coverage.get("warnings", []) or [])
    backend = generation_result.get("generation_backend", "template")

    if not stub.get("passed", True):
        return {
            "level": "scaffold",
            "reason": "stub_quality_failed",
        }
    if missing_checks or warnings:
        return {
            "level": "candidate",
            "reason": f"coverage_gap:{missing_checks or warnings}",
        }
    if backend in {"compiler", "template"} and synth.get("passed", False):
        return {
            "level": "substrate_grade",
            "reason": "validated_deterministic",
        }
    return {
        "level": "candidate",
        "reason": f"backend:{backend}",
    }


def create(
    domain: str,
    description: str,
    gap: dict,
    generation_result: dict,
    validation_result: dict,
) -> dict:
    """Create a new proposal and write to queue."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)

    proposal_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()

    proposal = {
        "id":                proposal_id,
        "proposal_kind":     "toolchain_generation",
        "domain":            domain,
        "description":       description,
        "attack_surface":    gap.get("attack_surface", ""),
        "hosts":             gap.get("hosts", []),
        "hosts_count":       len(gap.get("hosts", [])),
        "category":          gap.get("category", "unknown"),
        "evidence":          gap.get("evidence", ""),
        "staged_path":       generation_result.get("staging_path", ""),
        "wicket_count":      generation_result.get("wicket_count", 0),
        "path_count":        generation_result.get("path_count", 0),
        "generation_backend": generation_result.get("generation_backend", "template"),
        "generation_errors": generation_result.get("errors", []),
        "validation":        {
            "passed":   validation_result.get("passed", False),
            "checks":   {k: {"passed": v.get("passed"), "error_count": len(v.get("errors", []))}
                         for k, v in validation_result.get("checks", {}).items()},
        },
        "maturity":          _toolchain_maturity(validation_result, generation_result),
        "generated_at":      now,
        "status":            "pending",
        "cooldown_until":    None,
        "defer_until":       None,
        "reviewed_at":       None,
    }

    _proposal_path(proposal_id).write_text(json.dumps(proposal, indent=2))
    log.info(f"[proposals] created: {proposal_id} ({domain}, {len(gap.get('hosts',[]))} hosts)")
    return proposal


def create_catalog_growth(
    domain: str,
    description: str,
    hosts: list[str],
    attack_surface: str = "",
    evidence: str = "",
    category: str = "contextual_fold_cluster",
    compiler_hints: dict | None = None,
    fold_ids: list[str] | None = None,
    command: str = "",
) -> dict:
    """Create a non-destructive operator review item for catalog growth."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)

    proposal_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()
    hosts = hosts or []
    compiler_hints = dict(compiler_hints or {})
    compiler_hints["packages"] = sorted(set(compiler_hints.get("packages", [])))
    compiler_hints["keywords"] = sorted(set(compiler_hints.get("keywords", [])))
    fold_ids = [fid for fid in (fold_ids or []) if fid]
    command = command.strip()
    recall = _load_recall_adjustment(domain=domain, hosts=hosts)

    proposal = {
        "id":             proposal_id,
        "proposal_kind":  "catalog_growth",
        "domain":         domain,
        "description":    description,
        "attack_surface": attack_surface,
        "hosts":          hosts,
        "hosts_count":    len(hosts),
        "category":       category,
        "evidence":       evidence,
        "compiler_hints": compiler_hints,
        "fold_ids":       fold_ids,
        "action":         {
            "instrument": "catalog_compiler",
            "command": command,
            "command_hint": command,
            "mode": "dry_run_review",
        },
        "recall":         recall,
        "confidence":     round(max(0.0, min(1.0, 0.5 + float(recall.get("delta", 0.0)))), 4),
        "generated_at":   now,
        "status":         "pending",
        "cooldown_until": None,
        "defer_until":    None,
        "reviewed_at":    None,
    }

    _proposal_path(proposal_id).write_text(json.dumps(proposal, indent=2))
    log.info(f"[proposals] created catalog_growth: {proposal_id} ({domain}, {hosts})")
    try:
        _record_proposal_memory(
            proposal,
            reason="proposal_created",
            related=list(fold_ids),
        )
    except Exception as exc:
        log.debug(f"[proposals] create catalog_growth memory hook error: {exc}")
    return proposal


def list_proposals(status: str = "pending") -> list[dict]:
    """Return proposals filtered by status, sorted by generated_at desc."""
    proposals = []
    now = datetime.now(timezone.utc)

    for p in _iter_proposal_records(include_archived=False, include_hidden_deferred=False):

        # Skip if deferred and defer_until hasn't passed
        if p.get("status") == "deferred" and p.get("defer_until"):
            try:
                defer_until = datetime.fromisoformat(p["defer_until"])
                if now < defer_until:
                    continue
                else:
                    # Defer expired — reset to pending
                    p["status"] = "pending"
                    p["defer_until"] = None
                    _proposal_path(p["id"]).write_text(json.dumps(p, indent=2))
            except Exception:
                pass

        if status == "all" or p.get("status") == status:
            proposals.append(p)

    return sorted(proposals, key=_proposal_order_key)


def get(proposal_id: str) -> dict | None:
    """Get a single proposal by ID (prefix match allowed)."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    # Exact match
    p = _proposal_path(proposal_id)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    # Prefix match
    for f in PROPOSALS_DIR.glob(f"{proposal_id}*.json"):
        try:
            return json.loads(f.read_text())
        except Exception:
            pass
    return None


def accept(proposal_id: str) -> dict:
    """
    Accept a proposal — install the toolchain and mark accepted.
    Returns installation result.
    """
    proposal = get(proposal_id)
    if not proposal:
        raise ValueError(f"Proposal not found: {proposal_id}")
    if proposal["status"] != "pending":
        raise ValueError(f"Proposal {proposal_id} is {proposal['status']}, not pending")

    if proposal.get("proposal_kind") == "catalog_growth":
        proposal_key = proposal["id"]
        proposal["status"] = "accepted"
        proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()
        ACCEPTED_DIR.mkdir(parents=True, exist_ok=True)
        archive = ACCEPTED_DIR / f"{proposal_key}.json"
        archive.write_text(json.dumps(proposal, indent=2))
        _proposal_path(proposal_key).unlink(missing_ok=True)
        try:
            _record_proposal_memory(
                proposal,
                reason="proposal_accepted",
                related=list(proposal.get("fold_ids", []) or []),
            )
        except Exception as exc:
            log.debug(f"[proposals] accept memory hook error: {exc}")
        log.info(f"[proposals] accepted catalog_growth: {proposal_key}")
        return {
            "accepted": True,
            "domain": proposal["domain"],
            "proposal_kind": "catalog_growth",
            "command": proposal.get("action", {}).get("command", ""),
            "next": proposal.get("action", {}).get("command_hint", ""),
        }

    if proposal.get("proposal_kind") == "field_action":
        proposal_key = proposal["id"]
        proposal["status"] = "accepted"
        proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()
        ACCEPTED_DIR.mkdir(parents=True, exist_ok=True)
        archive = ACCEPTED_DIR / f"{proposal_key}.json"
        archive.write_text(json.dumps(proposal, indent=2))
        _proposal_path(proposal_key).unlink(missing_ok=True)
        try:
            _record_proposal_memory(
                proposal,
                reason="proposal_accepted",
                related=list(proposal.get("fold_ids", []) or []),
            )
        except Exception as exc:
            log.debug(f"[proposals] accept memory hook error: {exc}")
        dispatch = (proposal.get("action") or {}).get("dispatch") or {}
        log.info(f"[proposals] accepted field_action: {proposal_key}")
        return {
            "accepted": True,
            "domain": proposal["domain"],
            "proposal_kind": "field_action",
            "command_hint": dispatch.get("command_hint", ""),
            "rc_file": (proposal.get("action") or {}).get("rc_file", ""),
        }

    staged_path_val = proposal.get("staged_path", "")
    if not staged_path_val:
        raise ValueError(f"Proposal {proposal_id} has no staged_path (kind: {proposal.get('proposal_kind')})")
    staged = Path(staged_path_val)
    if not staged.exists():
        raise ValueError(f"Staged toolchain not found: {staged}")

    # Install
    from skg.forge.generator import install_toolchain
    install_result = install_toolchain(staged)
    installed_path = install_result.get("installed_path", "")

    # Update proposal
    proposal["status"]      = "accepted_preserved_existing" if install_result.get("preserved_existing") else "accepted"
    proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    proposal["installed_path"] = str(installed_path)
    proposal["installed"] = bool(install_result.get("installed"))
    proposal["preserved_existing"] = bool(install_result.get("preserved_existing"))

    # Training corpus — positive example
    try:
        from skg.training.corpus import on_proposal_accept
        on_proposal_accept(proposal, {"generation_backend": proposal.get("generation_backend",""),
                                       "staging_path": proposal.get("staged_path","")})
    except Exception as _ce:
        log.debug(f"[proposals] corpus hook error: {_ce}")

    # Move to accepted archive
    proposal_key = proposal["id"]
    ACCEPTED_DIR.mkdir(parents=True, exist_ok=True)
    archive = ACCEPTED_DIR / f"{proposal_key}.json"
    archive.write_text(json.dumps(proposal, indent=2))
    _proposal_path(proposal_key).unlink(missing_ok=True)
    try:
        _record_proposal_memory(
            proposal,
            reason="proposal_accepted",
            related=list(proposal.get("fold_ids", []) or []),
        )
    except Exception as exc:
        log.debug(f"[proposals] accept memory hook error: {exc}")

    if install_result.get("preserved_existing"):
        log.info(f"[proposals] accepted-noop: {proposal_key} preserved existing toolchain @ {installed_path}")
    else:
        log.info(f"[proposals] accepted: {proposal_key} → {installed_path}")

    # Training corpus — positive example from operator acceptance
    try:
        from skg.training.corpus import on_proposal_accept
        # Reconstruct generation_result from proposal data
        gen_result = {
            "generation_backend": proposal.get("generation_backend", "unknown"),
            "staging_path": proposal.get("staged_path", ""),
            "wicket_count": proposal.get("wicket_count", 0),
        }
        on_proposal_accept(proposal, gen_result)
    except Exception as _te:
        log.debug(f"[proposals] corpus hook error: {_te}")

    return {
        "accepted": True,
        "domain":   proposal["domain"],
        "installed_path": str(installed_path),
        "installed": proposal["installed"],
        "preserved_existing": proposal["preserved_existing"],
        "wicket_count": proposal["wicket_count"],
        "path_count": proposal["path_count"],
        "next": f"skg mode unified  # next sweep will evaluate {proposal['domain']} toolchain",
    }


def reject(proposal_id: str,
           reason: str = "",
           cooldown_days: int = DEFAULT_COOLDOWN_DAYS) -> dict:
    """Reject a proposal with cooldown."""
    proposal = get(proposal_id)
    if not proposal:
        raise ValueError(f"Proposal not found: {proposal_id}")

    now = datetime.now(timezone.utc)
    cooldown_until = (now + timedelta(days=cooldown_days)).isoformat()
    proposal_key = proposal["id"]

    proposal["status"]        = "rejected"
    proposal["reviewed_at"]   = now.isoformat()
    proposal["cooldown_until"] = cooldown_until
    proposal["reject_reason"] = reason

    # Move to rejected archive
    REJECTED_DIR.mkdir(parents=True, exist_ok=True)
    archive = REJECTED_DIR / f"{proposal_key}.json"
    archive.write_text(json.dumps(proposal, indent=2))
    _proposal_path(proposal_key).unlink(missing_ok=True)
    try:
        _record_proposal_memory(
            proposal,
            reason="proposal_rejected",
            related=list(proposal.get("fold_ids", []) or []),
        )
    except Exception as exc:
        log.debug(f"[proposals] reject memory hook error: {exc}")

    # Training corpus — negative example
    try:
        from skg.training.corpus import on_proposal_reject
        on_proposal_reject(proposal, reason)
    except Exception as _ce:
        log.debug(f"[proposals] corpus hook error: {_ce}")

    # Record cooldown in gap state so gap detector won't re-propose
    _record_cooldown(proposal["domain"], cooldown_until)

    log.info(f"[proposals] rejected: {proposal_key} ({proposal['domain']}, "
             f"cooldown until {cooldown_until[:10]})")

    # Training corpus — negative example from operator rejection
    try:
        from skg.training.corpus import on_proposal_reject
        on_proposal_reject(proposal, reason=reason)
    except Exception as _te:
        log.debug(f"[proposals] corpus hook error: {_te}")

    return {
        "rejected": True,
        "domain": proposal["domain"],
        "cooldown_until": cooldown_until[:10],
    }


def defer(proposal_id: str, days: int = DEFAULT_DEFER_DAYS) -> dict:
    """Defer a proposal — re-surface after N days."""
    proposal = get(proposal_id)
    if not proposal:
        raise ValueError(f"Proposal not found: {proposal_id}")

    defer_until = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    proposal["status"]      = "deferred"
    proposal["defer_until"] = defer_until
    proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    _proposal_path(proposal_id).write_text(json.dumps(proposal, indent=2))
    try:
        _record_proposal_memory(
            proposal,
            reason="proposal_deferred",
            related=list(proposal.get("fold_ids", []) or []),
        )
    except Exception as exc:
        log.debug(f"[proposals] defer memory hook error: {exc}")

    log.info(f"[proposals] deferred: {proposal_id} until {defer_until[:10]}")
    return {"deferred": True, "domain": proposal["domain"], "until": defer_until[:10]}


def supersede(
    proposal_ids: list[str],
    replacement_id: str = "",
    reason: str = "clustered_catalog_growth",
) -> dict:
    """Archive proposals as superseded by a newer aggregate proposal."""
    SUPERSEDED_DIR.mkdir(parents=True, exist_ok=True)

    superseded_ids: list[str] = []
    for proposal_id in proposal_ids:
        proposal = get(proposal_id)
        if not proposal:
            continue
        if proposal.get("status") != "pending":
            continue

        proposal["status"] = "superseded"
        proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()
        proposal["superseded_by"] = replacement_id or None
        proposal["supersede_reason"] = reason

        archive = SUPERSEDED_DIR / f"{proposal['id']}.json"
        archive.write_text(json.dumps(proposal, indent=2))
        _proposal_path(proposal["id"]).unlink(missing_ok=True)
        superseded_ids.append(proposal["id"])
        try:
            _record_proposal_memory(
                proposal,
                reason=reason,
                related=superseded_ids,
                replacement_id=replacement_id or None,
            )
        except Exception as exc:
            log.debug(f"[proposals] supersede memory hook error: {exc}")

    return {
        "superseded": len(superseded_ids),
        "ids": superseded_ids,
        "replacement_id": replacement_id or None,
    }


def _record_cooldown(domain: str, until: str):
    """Record rejection cooldown in gap detector state."""
    try:
        from skg.intel.gap_detector import GAP_STATE_FILE, load_known_gaps, save_known_gaps
        known = load_known_gaps()
        if domain in known:
            known[domain]["cooldown_until"] = until
        else:
            known[domain] = {"cooldown_until": until, "hosts": []}
        save_known_gaps(known)
    except Exception as exc:
        log.debug(f"[proposals] cooldown record failed: {exc}")


def is_in_cooldown(domain: str) -> bool:
    """Check if a domain is in rejection cooldown."""
    try:
        from skg.intel.gap_detector import load_known_gaps
        known = load_known_gaps()
        entry = known.get(domain, {})
        until = entry.get("cooldown_until")
        if not until:
            return False
        return datetime.now(timezone.utc) < datetime.fromisoformat(until)
    except Exception:
        return False


def format_proposal_list(proposals: list[dict], verbose: bool = False) -> str:
    """Format proposal list for CLI display."""
    if not proposals:
        return "No pending proposals."

    lines = [f"{len(proposals)} pending proposal(s):\n"]
    for p in proposals:
        kind = p.get("proposal_kind", "toolchain_generation")
        if kind == "catalog_growth":
            val_icon = "+"
            metric = "catalog"
        else:
            val_passed = p.get("validation", {}).get("passed", False)
            val_icon = "✓" if val_passed else "⚠"
            metric = f"{p.get('wicket_count',0)}w/{p.get('path_count',0)}p"
        hosts_str  = f"{p.get('hosts_count', len(p.get('hosts', [])))} host(s)"
        lines.append(
            f"  [{p['id'][:8]}] {p['domain']:20s} "
            f"{val_icon} {metric} "
            f"| {hosts_str} | {p.get('category','')}"
        )
        lines.append(f"           {p.get('attack_surface','')[:72]}")
        if verbose:
            lines.append(f"           hosts: {', '.join(p.get('hosts', [])[:5])}")
            if kind == "catalog_growth":
                hint = p.get("action", {}).get("command_hint", "")
                if hint:
                    lines.append(f"           command: {hint}")
                recall = p.get("recall", {}) or {}
                growth = recall.get("growth_memory", {}) or {}
                if growth.get("proposal_reasons"):
                    lines.append(
                        "           growth-memory: "
                        + ", ".join(growth.get("proposal_reasons", [])[:4])
                    )
            else:
                lines.append(f"           backend: {p.get('generation_backend','')}")
                errs = p.get("generation_errors", [])
                if errs:
                    lines.append(f"           warnings: {'; '.join(errs[:2])}")
        lines.append("")

    lines.append("Commands:")
    lines.append("  skg proposals show   <id>   — view catalog and adapter")
    lines.append("  skg proposals accept <id>   — accept proposal")
    lines.append("  skg proposals reject <id>   — archive with 30-day cooldown")
    lines.append("  skg proposals defer  <id>   — re-surface in 7 days")
    return "\n".join(lines)


def format_proposal_detail(proposal: dict) -> str:
    """Format full proposal detail for CLI display."""
    lines = []
    lines.append(f"Proposal: {proposal['id']}")
    lines.append(f"Domain:   {proposal['domain']}")
    lines.append(f"Desc:     {proposal['description']}")
    lines.append(f"Surface:  {proposal['attack_surface']}")
    lines.append(f"Hosts:    {', '.join(proposal.get('hosts', []))}")
    lines.append(f"Evidence: {proposal.get('evidence','')}")
    lines.append(f"Kind:     {proposal.get('proposal_kind','toolchain_generation')}")
    lines.append(f"Backend:  {proposal.get('generation_backend','')}")
    lines.append(f"Generated:{proposal.get('generated_at','')[:19]}")
    lines.append("")

    if proposal.get("proposal_kind") == "catalog_growth":
        hints = proposal.get("compiler_hints", {})
        lines.append("Catalog Growth:")
        lines.append(f"  packages: {', '.join(hints.get('packages', []))}")
        lines.append(f"  keywords: {', '.join(hints.get('keywords', []))}")
        recall = proposal.get("recall", {}) or {}
        growth = recall.get("growth_memory", {}) or {}
        if growth:
            lines.append(f"  growth memory delta: {growth.get('delta', 0.0)}")
            if growth.get("proposal_reasons"):
                lines.append(f"  growth memory: {', '.join(growth.get('proposal_reasons', [])[:6])}")
        command = proposal.get("action", {}).get("command_hint", "")
        if command:
            lines.append(f"  dry-run: {command}")
        lines.append("")
        lines.append(f"skg proposals accept {proposal['id'][:8]}")
        lines.append(f"skg proposals reject {proposal['id'][:8]}")
        return "\n".join(lines)

    val = proposal.get("validation", {})
    lines.append(f"Validation: {'PASS' if val.get('passed') else 'FAIL'}")
    for check, result in val.get("checks", {}).items():
        icon = "✓" if result.get("passed") else "✗"
        errs = result.get("error_count", 0)
        lines.append(f"  {icon} {check}" + (f" ({errs} errors)" if errs else ""))
    lines.append("")

    # Show catalog summary
    staged = Path(proposal.get("staged_path", ""))
    catalogs = list(staged.glob("contracts/catalogs/*.json")) if staged.exists() else []
    if catalogs:
        try:
            catalog = json.loads(catalogs[0].read_text())
            lines.append(f"Catalog: {len(catalog.get('wickets',{}))} wickets, "
                         f"{len(catalog.get('attack_paths',{}))} attack paths")
            lines.append("Wickets:")
            for wid, w in list(catalog.get("wickets", {}).items()):
                lines.append(f"  {wid}: {w.get('label','')} — {w.get('description','')[:60]}")
            lines.append("Attack Paths:")
            for pid, ap in catalog.get("attack_paths", {}).items():
                lines.append(f"  {pid}: requires {ap.get('required_wickets', [])}")
        except Exception as exc:
            lines.append(f"Catalog read error: {exc}")
    else:
        lines.append("(staged toolchain not found)")

    lines.append("")
    lines.append(f"skg proposals accept {proposal['id'][:8]}")
    lines.append(f"skg proposals reject {proposal['id'][:8]}")
    return "\n".join(lines)


def create_action(
    domain: str,
    description: str,
    action: dict,
    attack_surface: str = "",
    hosts: list[str] | None = None,
    category: str = "runtime_observation",
    evidence: str = "",
) -> dict:
    """
    Create a runtime field-action proposal.
    This is operator-reviewable work, not a staged toolchain install.
    """
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)

    proposal_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()
    hosts = hosts or []
    recall = _load_recall_adjustment(domain=domain, hosts=hosts)

    action = dict(action or {})
    base_confidence = action.get("confidence")
    if base_confidence is not None:
        try:
            adjusted = max(0.0, min(1.0, float(base_confidence) + float(recall.get("delta", 0.0))))
            action["base_confidence"] = round(float(base_confidence), 4)
            action["confidence"] = round(adjusted, 4)
        except Exception:
            pass

    proposal = {
        "id":             proposal_id,
        "proposal_kind":  "field_action",
        "domain":         domain,
        "description":    description,
        "attack_surface": attack_surface,
        "hosts":          hosts,
        "hosts_count":    len(hosts),
        "category":       category,
        "evidence":       evidence,
        "action":         action,
        "confidence":     action.get("confidence"),
        "recall":         recall,
        "generated_at":   now,
        "status":         "pending",
        "cooldown_until": None,
        "defer_until":    None,
        "reviewed_at":    None,
    }

    _proposal_path(proposal_id).write_text(json.dumps(proposal, indent=2))
    log.info(f"[proposals] created field_action: {proposal_id} ({domain}, {hosts})")
    return proposal


def trigger_action(proposal_id: str) -> dict:
    """
    Mark a field-action proposal as operator-triggered.
    Returns the proposal payload for the caller to dispatch.
    Does NOT execute anything itself.
    """
    proposal = get(proposal_id)
    if not proposal:
        raise ValueError(f"Proposal not found: {proposal_id}")

    if proposal.get("proposal_kind") != "field_action":
        raise ValueError(f"Proposal {proposal_id} is not a field_action proposal")

    if proposal.get("status") != "pending":
        raise ValueError(f"Proposal {proposal_id} is {proposal.get('status')}, not pending")

    proposal["status"] = "triggered"
    proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    _proposal_path(proposal["id"]).write_text(json.dumps(proposal, indent=2))

    log.info(f"[proposals] triggered field_action: {proposal_id}")
    return proposal


def interactive_review(proposal_id: str,
                       defer_days: int = DEFAULT_DEFER_DAYS) -> dict:
    """
    Prompt the operator in real time when running on an interactive TTY.
    Field-action proposals map "approve" -> trigger.
    Toolchain-generation proposals map "approve" -> accept.
    """
    if os.environ.get("SKG_INTERACTIVE_PROPOSALS", "1").lower() in {"0", "false", "no"}:
        return {"interactive": False, "decision": "disabled"}
    if not sys.stdin.isatty():
        return {"interactive": False, "decision": "non_interactive"}

    proposal = get(proposal_id)
    if not proposal:
        return {"interactive": True, "decision": "missing", "error": f"Proposal not found: {proposal_id}"}

    kind = proposal.get("proposal_kind", "field_action")
    approve_action = "trigger" if kind == "field_action" else "accept"
    print(f"    [REVIEW] {proposal['id']} [{kind}] {proposal.get('description', '')[:80]}")
    print(f"    [REVIEW] [a]pprove/{approve_action}  [r]eject  [d]efer  [s]kip")

    while True:
        try:
            choice = input("    [REVIEW] Decision: ").strip().lower()
        except EOFError:
            return {"interactive": True, "decision": "skipped"}
        if choice in {"", "s", "skip"}:
            return {"interactive": True, "decision": "skipped"}
        if choice in {"a", "approve", "accept", "trigger"}:
            if kind == "field_action":
                triggered = trigger_action(proposal["id"])
                return {"interactive": True, "decision": "approved", "proposal": triggered}
            accepted = accept(proposal["id"])
            return {"interactive": True, "decision": "approved", "result": accepted}
        if choice in {"r", "reject"}:
            rejected = reject(proposal["id"], reason="interactive_review")
            return {"interactive": True, "decision": "rejected", "result": rejected}
        if choice in {"d", "defer"}:
            deferred = defer(proposal["id"], days=defer_days)
            return {"interactive": True, "decision": "deferred", "result": deferred}
        print("    [REVIEW] Enter a, r, d, or s.")
