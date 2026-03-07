"""
skg.resonance.observation_memory
=================================
Fourth FAISS index in the resonance engine.

Records closed-loop observations: what evidence was seen, what wicket
it was attributed to, and what the projection subsequently confirmed.

This is SKG learning from its own engagements.

Record structure
----------------
  ObservationRecord:
    record_id:       str   — uuid
    evidence_text:   str   — what the sensor saw (embedded)
    wicket_id:       str   — which wicket this evidence was attributed to
    domain:          str
    source_kind:     str   — ssh_collection | usb_collection | msf_loot | nvd_cve | ...
    evidence_rank:   int   — 1-6
    sensor_realized: bool|None  — what the sensor said
    projection_confirmed: str   — what projection confirmed (realized|blocked|unknown)
    confidence_at_emit:  float  — confidence when the sensor emitted this
    workload_id:     str
    ts:              str

How it's used
-------------
Before a sensor emits an event for wicket W, it calls:
  obs_memory.recall(evidence_text, wicket_id, k=10)

This returns the k most similar past observations for this wicket,
along with their projection outcomes. The sensor computes:
  historical_confirmation_rate = |confirmed_realized| / |total recalled|

And adjusts its confidence:
  adjusted_confidence = (sensor_base_confidence * 0.6) + (historical_rate * 0.4)

This is retrieval-augmented confidence calibration.
The weights (0.6/0.4) are intentionally conservative — the sensor's
direct evidence still dominates, but history informs.

The learning signal
-------------------
The feedback ingester (skg.temporal.feedback) walks INTERP_DIR after
each projection run and calls:
  obs_memory.record_outcome(record_id, projection_confirmed)

This closes the loop. The FAISS index is rebuilt on load, so new records
are immediately available for future queries.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

log = logging.getLogger("skg.resonance.observation_memory")


@dataclass
class ObservationRecord:
    record_id:            str
    evidence_text:        str        # what was embedded
    wicket_id:            str
    domain:               str
    source_kind:          str
    evidence_rank:        int
    sensor_realized:      bool | None
    projection_confirmed: str | None  # realized|blocked|unknown|None (pending)
    confidence_at_emit:   float
    workload_id:          str
    ts:                   str
    embed_text:           str         # evidence_text + wicket context (for indexing)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "ObservationRecord":
        return cls(**d)

    @staticmethod
    def make_embed_text(evidence_text: str, wicket_id: str, domain: str) -> str:
        return f"{domain} {wicket_id}: {evidence_text}"


class ObservationMemory:
    """
    FAISS-backed store of closed-loop sensor observations.
    Plugs into the resonance engine as a fourth memory store.
    """

    def __init__(self, index_dir: Path, records_dir: Path, embedder):
        self.index_path   = index_dir  / "observations.faiss"
        self.records_path = records_dir / "observations.jsonl"
        self.pending_path = records_dir / "observations_pending.jsonl"
        self._embedder    = embedder
        self._records: list[ObservationRecord] = []
        self._index = None
        self._dim   = embedder.dim

    def load(self):
        import faiss
        self.records_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)

        self._records = []
        for path in (self.records_path,):
            if path.exists():
                for line in path.read_text(errors="replace").splitlines():
                    if not line.strip():
                        continue
                    try:
                        self._records.append(ObservationRecord.from_dict(json.loads(line)))
                    except Exception as exc:
                        log.warning(f"Skipping malformed observation: {exc}")

        self._index = faiss.IndexFlatIP(self._dim)
        if self._records:
            embed_texts = [r.embed_text for r in self._records]
            vecs = self._embedder.embed(embed_texts)
            self._index.add(vecs)

        log.info(f"ObservationMemory: {len(self._records)} records loaded")

    def record_observation(
        self,
        evidence_text: str,
        wicket_id: str,
        domain: str,
        source_kind: str,
        evidence_rank: int,
        sensor_realized: bool | None,
        confidence_at_emit: float,
        workload_id: str,
        ts: str | None = None,
    ) -> str:
        """
        Record a new sensor observation (pending projection confirmation).
        Returns record_id for later outcome recording.
        """
        ts = ts or datetime.now(timezone.utc).isoformat()
        embed_text = ObservationRecord.make_embed_text(evidence_text, wicket_id, domain)
        rec = ObservationRecord(
            record_id=str(uuid.uuid4()),
            evidence_text=evidence_text,
            wicket_id=wicket_id,
            domain=domain,
            source_kind=source_kind,
            evidence_rank=evidence_rank,
            sensor_realized=sensor_realized,
            projection_confirmed=None,  # pending
            confidence_at_emit=confidence_at_emit,
            workload_id=workload_id,
            ts=ts,
            embed_text=embed_text,
        )

        # Write to pending (not yet in FAISS — no confirmed outcome)
        self.pending_path.parent.mkdir(parents=True, exist_ok=True)
        with self.pending_path.open("a") as fh:
            fh.write(rec.to_json() + "\n")

        return rec.record_id

    def record_outcome(self, record_id: str, projection_confirmed: str):
        """
        Close the loop: record what projection confirmed for a pending observation.
        Moves from pending to confirmed, adds to FAISS index.
        """
        # Find in pending
        if not self.pending_path.exists():
            return

        found: ObservationRecord | None = None
        remaining: list[str] = []

        for line in self.pending_path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = ObservationRecord.from_dict(json.loads(line))
                if rec.record_id == record_id:
                    rec.projection_confirmed = projection_confirmed
                    found = rec
                else:
                    remaining.append(line)
            except Exception:
                remaining.append(line)

        if found is None:
            return

        # Rewrite pending without this record
        self.pending_path.write_text("\n".join(remaining) + "\n" if remaining else "")

        # Add to confirmed records and FAISS
        with self.records_path.open("a") as fh:
            fh.write(found.to_json() + "\n")
        self._records.append(found)
        if self._index is not None:
            vec = self._embedder.embed_one(found.embed_text).reshape(1, -1)
            self._index.add(vec)

    def recall(
        self,
        evidence_text: str,
        wicket_id: str,
        domain: str,
        k: int = 10,
    ) -> list[tuple[ObservationRecord, float]]:
        """
        Retrieve the k most similar past observations for this evidence+wicket.
        Returns (record, similarity_score) pairs.
        """
        if self._index is None or len(self._records) == 0:
            return []

        embed_text = ObservationRecord.make_embed_text(evidence_text, wicket_id, domain)
        vec = self._embedder.embed_one(embed_text).reshape(1, -1)

        k = min(k, len(self._records))
        scores, indices = self._index.search(vec, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._records):
                continue
            rec = self._records[idx]
            # Only return observations for the same wicket
            if rec.wicket_id == wicket_id:
                results.append((rec, float(score)))

        return results

    def historical_confirmation_rate(
        self,
        evidence_text: str,
        wicket_id: str,
        domain: str,
        k: int = 10,
    ) -> float | None:
        """
        Query historical observations and compute confirmation rate.
        Returns None if insufficient history (< 3 observations).
        """
        similar = self.recall(evidence_text, wicket_id, domain, k=k)
        confirmed = [r for r, _ in similar if r.projection_confirmed is not None]

        if len(confirmed) < 3:
            return None  # insufficient history

        realized_count = sum(
            1 for r in confirmed if r.projection_confirmed == "realized"
        )
        return realized_count / len(confirmed)

    def calibrate_confidence(
        self,
        base_confidence: float,
        evidence_text: str,
        wicket_id: str,
        domain: str,
        k: int = 10,
        history_weight: float = 0.4,
    ) -> float:
        """
        Blend sensor's base confidence with historical confirmation rate.
        history_weight=0.4 means sensor evidence still dominates (60%).

        Returns adjusted confidence. If no history, returns base_confidence.
        """
        rate = self.historical_confirmation_rate(evidence_text, wicket_id, domain, k=k)
        if rate is None:
            return base_confidence
        adjusted = (base_confidence * (1 - history_weight)) + (rate * history_weight)
        return round(min(1.0, max(0.0, adjusted)), 4)

    def status(self) -> dict:
        pending_count = 0
        if self.pending_path.exists():
            pending_count = sum(
                1 for line in self.pending_path.read_text(errors="replace").splitlines()
                if line.strip()
            )
        confirmed = [r for r in self._records if r.projection_confirmed is not None]
        realized  = [r for r in confirmed if r.projection_confirmed == "realized"]
        return {
            "confirmed_observations": len(confirmed),
            "pending_observations":   pending_count,
            "confirmed_realized":     len(realized),
            "confirmation_rate": (
                round(len(realized) / len(confirmed), 3) if confirmed else None
            ),
        }
