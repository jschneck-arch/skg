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
import shutil
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from skg.core.paths import SKG_STATE_DIR, SKG_HOME

log = logging.getLogger("skg.forge.proposals")

PROPOSALS_DIR = SKG_STATE_DIR / "proposals"
REJECTED_DIR  = SKG_STATE_DIR / "proposals_rejected"
ACCEPTED_DIR  = SKG_STATE_DIR / "proposals_accepted"

DEFAULT_COOLDOWN_DAYS = 30
DEFAULT_DEFER_DAYS    = 7


def _proposal_path(proposal_id: str) -> Path:
    return PROPOSALS_DIR / f"{proposal_id}.json"


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
        "generated_at":      now,
        "status":            "pending",
        "cooldown_until":    None,
        "defer_until":       None,
        "reviewed_at":       None,
    }

    _proposal_path(proposal_id).write_text(json.dumps(proposal, indent=2))
    log.info(f"[proposals] created: {proposal_id} ({domain}, {len(gap.get('hosts',[]))} hosts)")
    return proposal


def list_proposals(status: str = "pending") -> list[dict]:
    """Return proposals filtered by status, sorted by generated_at desc."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    proposals = []
    now = datetime.now(timezone.utc)

    for f in PROPOSALS_DIR.glob("*.json"):
        try:
            p = json.loads(f.read_text())
        except Exception:
            continue

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
                    f.write_text(json.dumps(p, indent=2))
            except Exception:
                pass

        if status == "all" or p.get("status") == status:
            proposals.append(p)

    return sorted(proposals, key=lambda p: p.get("generated_at", ""), reverse=True)


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

    staged = Path(proposal["staged_path"])
    if not staged.exists():
        raise ValueError(f"Staged toolchain not found: {staged}")

    # Install
    from skg.forge.generator import install_toolchain
    installed_path = install_toolchain(staged)

    # Update proposal
    proposal["status"]      = "accepted"
    proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    proposal["installed_path"] = str(installed_path)

    # Training corpus — positive example
    try:
        from skg.training.corpus import on_proposal_accept
        on_proposal_accept(proposal, {"generation_backend": proposal.get("generation_backend",""),
                                       "staging_path": proposal.get("staged_path","")})
    except Exception as _ce:
        log.debug(f"[proposals] corpus hook error: {_ce}")

    # Move to accepted archive
    ACCEPTED_DIR.mkdir(parents=True, exist_ok=True)
    archive = ACCEPTED_DIR / f"{proposal_id}.json"
    archive.write_text(json.dumps(proposal, indent=2))
    _proposal_path(proposal_id).unlink(missing_ok=True)

    log.info(f"[proposals] accepted: {proposal_id} → {installed_path}")

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

    proposal["status"]        = "rejected"
    proposal["reviewed_at"]   = now.isoformat()
    proposal["cooldown_until"] = cooldown_until
    proposal["reject_reason"] = reason

    # Move to rejected archive
    REJECTED_DIR.mkdir(parents=True, exist_ok=True)
    archive = REJECTED_DIR / f"{proposal_id}.json"
    archive.write_text(json.dumps(proposal, indent=2))
    _proposal_path(proposal_id).unlink(missing_ok=True)

    # Training corpus — negative example
    try:
        from skg.training.corpus import on_proposal_reject
        on_proposal_reject(proposal, reason)
    except Exception as _ce:
        log.debug(f"[proposals] corpus hook error: {_ce}")

    # Record cooldown in gap state so gap detector won't re-propose
    _record_cooldown(proposal["domain"], cooldown_until)

    log.info(f"[proposals] rejected: {proposal_id} ({proposal['domain']}, "
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

    log.info(f"[proposals] deferred: {proposal_id} until {defer_until[:10]}")
    return {"deferred": True, "domain": proposal["domain"], "until": defer_until[:10]}


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
        val_passed = p.get("validation", {}).get("passed", False)
        val_icon   = "✓" if val_passed else "⚠"
        hosts_str  = f"{p.get('hosts_count', len(p.get('hosts', [])))} host(s)"
        lines.append(
            f"  [{p['id'][:8]}] {p['domain']:20s} "
            f"{val_icon} {p.get('wicket_count',0)}w/{p.get('path_count',0)}p "
            f"| {hosts_str} | {p.get('category','')}"
        )
        lines.append(f"           {p.get('attack_surface','')[:72]}")
        if verbose:
            lines.append(f"           hosts: {', '.join(p.get('hosts', [])[:5])}")
            lines.append(f"           backend: {p.get('generation_backend','')}")
            errs = p.get("generation_errors", [])
            if errs:
                lines.append(f"           warnings: {'; '.join(errs[:2])}")
        lines.append("")

    lines.append("Commands:")
    lines.append("  skg proposals show   <id>   — view catalog and adapter")
    lines.append("  skg proposals accept <id>   — install toolchain")
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
    lines.append(f"Backend:  {proposal.get('generation_backend','')}")
    lines.append(f"Generated:{proposal.get('generated_at','')[:19]}")
    lines.append("")

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
