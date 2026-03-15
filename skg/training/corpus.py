"""
skg.training.corpus
====================
Accumulates training examples from SKG's own operational data.

Every accepted proposal, resonance draft, and confirmed wicket
projection is a labeled training pair. This module hooks into
existing state files — no new data collection required.

Example schema:
  {
    "id":         str,
    "ts":         ISO timestamp,
    "kind":       "catalog" | "adapter" | "wicket_map",
    "label":      "positive" | "negative",
    "source":     "proposal_accept" | "proposal_reject" | "draft_accept"
                  | "projection_confirm" | "projection_disconfirm",
    "domain":     str,
    "input":      str,   # prompt sent to model
    "output":     str,   # model output (positive) or corrected output (negative)
    "correction": str,   # operator edit if applicable
    "metadata":   dict,
  }

Storage: SKG_STATE_DIR/training/examples/YYYY-MM/
Corpus index: SKG_STATE_DIR/training/corpus.json
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.core.paths import SKG_STATE_DIR

log = logging.getLogger("skg.training.corpus")

TRAINING_DIR   = SKG_STATE_DIR / "training"
EXAMPLES_DIR   = TRAINING_DIR / "examples"
CORPUS_INDEX   = TRAINING_DIR / "corpus.json"
HOLDOUT_FILE   = TRAINING_DIR / "holdout.json"

# Minimum examples before a fine-tune run is worthwhile
MIN_EXAMPLES_FOR_RUN = 20
# Fraction held out for eval
HOLDOUT_FRACTION     = 0.15


def _ensure_dirs():
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)


def _month_dir() -> Path:
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    d = EXAMPLES_DIR / month
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_index() -> dict:
    if CORPUS_INDEX.exists():
        try:
            return json.loads(CORPUS_INDEX.read_text())
        except Exception:
            pass
    return {
        "total":          0,
        "positive":       0,
        "negative":       0,
        "by_kind":        {},
        "by_source":      {},
        "last_added":     None,
        "last_run_at":    None,
        "examples_since_last_run": 0,
    }


def _save_index(index: dict):
    _ensure_dirs()
    CORPUS_INDEX.write_text(json.dumps(index, indent=2))


def add_example(
    kind:       str,
    label:      str,
    source:     str,
    domain:     str,
    input_text: str,
    output_text: str,
    correction: str = "",
    metadata:   dict | None = None,
) -> str:
    """
    Add one training example to the corpus.
    Returns the example ID.
    """
    _ensure_dirs()
    example_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    example = {
        "id":         example_id,
        "ts":         now,
        "kind":       kind,
        "label":      label,
        "source":     source,
        "domain":     domain,
        "input":      input_text,
        "output":     output_text,
        "correction": correction,
        "metadata":   metadata or {},
    }

    # Write to monthly shard
    month_dir = _month_dir()
    shard = month_dir / f"{source}_{domain}_{example_id[:8]}.json"
    shard.write_text(json.dumps(example, indent=2))

    # Update index
    index = _load_index()
    index["total"]   += 1
    index[label]     = index.get(label, 0) + 1
    index["by_kind"][kind]     = index["by_kind"].get(kind, 0) + 1
    index["by_source"][source] = index["by_source"].get(source, 0) + 1
    index["last_added"] = now
    index["examples_since_last_run"] = index.get("examples_since_last_run", 0) + 1
    _save_index(index)

    log.info(f"[corpus] +1 {label} {kind} ({source}, {domain})")
    return example_id


def load_all_examples(label: str | None = None,
                      kind: str | None = None,
                      since: str | None = None) -> list[dict]:
    """Load all examples, optionally filtered."""
    _ensure_dirs()
    examples = []
    for f in sorted(EXAMPLES_DIR.rglob("*.json")):
        try:
            ex = json.loads(f.read_text())
            if label and ex.get("label") != label:
                continue
            if kind and ex.get("kind") != kind:
                continue
            if since and ex.get("ts", "") < since:
                continue
            examples.append(ex)
        except Exception:
            pass
    return examples


def split_train_holdout(examples: list[dict],
                        holdout_fraction: float = HOLDOUT_FRACTION
                        ) -> tuple[list[dict], list[dict]]:
    """Deterministic train/holdout split by example ID."""
    holdout, train = [], []
    for ex in examples:
        # Use last hex char of ID for deterministic split
        val = int(ex["id"][-1], 16)
        if val < int(holdout_fraction * 16):
            holdout.append(ex)
        else:
            train.append(ex)
    return train, holdout


def corpus_status() -> dict:
    index = _load_index()
    examples = load_all_examples()
    pos = [e for e in examples if e["label"] == "positive"]
    neg = [e for e in examples if e["label"] == "negative"]
    ready = index.get("examples_since_last_run", 0) >= MIN_EXAMPLES_FOR_RUN
    return {
        "total":          len(examples),
        "positive":       len(pos),
        "negative":       len(neg),
        "by_kind":        index.get("by_kind", {}),
        "by_source":      index.get("by_source", {}),
        "last_added":     index.get("last_added"),
        "last_run_at":    index.get("last_run_at"),
        "examples_since_last_run": index.get("examples_since_last_run", 0),
        "ready_for_run":  ready,
        "min_required":   MIN_EXAMPLES_FOR_RUN,
    }


def mark_run_complete():
    """Call after a successful fine-tune run."""
    index = _load_index()
    index["last_run_at"] = datetime.now(timezone.utc).isoformat()
    index["examples_since_last_run"] = 0
    _save_index(index)


# ---------------------------------------------------------------------------
# Hooks — called from other SKG subsystems
# ---------------------------------------------------------------------------

def on_proposal_accept(proposal: dict, generation_result: dict):
    """
    Positive training example from operator accepting a forge proposal.
    The model generated a catalog + adapter that was good enough to install.
    """
    domain  = proposal.get("domain", "unknown")
    backend = generation_result.get("generation_backend", "unknown")

    # Only learn from model-generated outputs, not template fallbacks
    if backend == "template":
        log.debug(f"[corpus] skipping template-generated proposal for {domain}")
        return

    staged = Path(proposal.get("staged_path", ""))
    catalog_files = list(staged.glob("contracts/catalogs/*.json")) if staged.exists() else []
    adapter_file  = staged / "adapters" / "ssh_collect" / "parse.py"
    if not adapter_file.exists():
        adapter_files = list(staged.glob("adapters/*/parse.py"))
        adapter_file  = adapter_files[0] if adapter_files else None

    if catalog_files:
        catalog_text = catalog_files[0].read_text()
        prompt = _build_catalog_prompt(domain, proposal.get("description", ""),
                                       proposal.get("attack_surface", ""))
        add_example(
            kind="catalog", label="positive",
            source="proposal_accept", domain=domain,
            input_text=prompt, output_text=catalog_text,
            metadata={"wicket_count": proposal.get("wicket_count"),
                      "backend": backend},
        )

    if adapter_file and adapter_file.exists():
        adapter_text = adapter_file.read_text()
        prompt = _build_adapter_prompt(domain, proposal.get("description", ""))
        add_example(
            kind="adapter", label="positive",
            source="proposal_accept", domain=domain,
            input_text=prompt, output_text=adapter_text,
            metadata={"backend": backend},
        )


def on_proposal_reject(proposal: dict, reason: str = ""):
    """
    Negative example — operator rejected the generated toolchain.
    Records what was generated so the model learns to avoid it.
    """
    domain  = proposal.get("domain", "unknown")
    backend = proposal.get("generation_backend", "unknown")
    if backend == "template":
        return

    staged = Path(proposal.get("staged_path", ""))
    catalog_files = list(staged.glob("contracts/catalogs/*.json")) if staged.exists() else []

    if catalog_files:
        try:
            catalog_text = catalog_files[0].read_text()
            prompt = _build_catalog_prompt(domain, proposal.get("description", ""),
                                           proposal.get("attack_surface", ""))
            add_example(
                kind="catalog", label="negative",
                source="proposal_reject", domain=domain,
                input_text=prompt, output_text=catalog_text,
                metadata={"reason": reason, "backend": backend},
            )
        except Exception as exc:
            log.debug(f"[corpus] reject example error: {exc}")


def on_draft_accept(domain: str, description: str,
                    prompt: str, catalog: dict):
    """
    Positive example from operator accepting a resonance draft.
    """
    add_example(
        kind="catalog", label="positive",
        source="draft_accept", domain=domain,
        input_text=prompt,
        output_text=json.dumps(catalog, indent=2),
        metadata={"wicket_count": len(catalog.get("wickets", {}))},
    )


def on_projection_confirm(domain: str, workload_id: str,
                          wicket_id: str, evidence_text: str,
                          predicted_status: str):
    """
    Positive wicket mapping — sensor predicted realized/blocked,
    subsequent sweep confirmed it.
    """
    add_example(
        kind="wicket_map", label="positive",
        source="projection_confirm", domain=domain,
        input_text=evidence_text,
        output_text=predicted_status,
        metadata={"workload_id": workload_id, "wicket_id": wicket_id},
    )


def on_projection_disconfirm(domain: str, workload_id: str,
                              wicket_id: str, evidence_text: str,
                              predicted_status: str, actual_status: str):
    """
    Negative wicket mapping — sensor got it wrong.
    """
    add_example(
        kind="wicket_map", label="negative",
        source="projection_disconfirm", domain=domain,
        input_text=evidence_text,
        output_text=predicted_status,
        correction=actual_status,
        metadata={"workload_id": workload_id, "wicket_id": wicket_id},
    )


def _build_catalog_prompt(domain: str, description: str,
                           attack_surface: str) -> str:
    return (f"Generate a SKG attack preconditions catalog for domain: {domain}\n"
            f"Description: {description}\n"
            f"Attack surface: {attack_surface}\n"
            f"Output only valid JSON matching the SKG catalog schema.")


def _build_adapter_prompt(domain: str, description: str) -> str:
    return (f"Generate a SKG collection adapter parse.py for domain: {domain}\n"
            f"Description: {description}\n"
            f"Output only Python code following the SKG adapter pattern.")
