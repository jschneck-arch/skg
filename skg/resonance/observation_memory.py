"""
skg.resonance.observation_memory
=================================
Closed-loop observation memory for SKG.

If FAISS is unavailable, falls back to an in-memory cosine search.
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


def _safe_condition_id(wicket_id: str | None = None, node_id: str | None = None) -> str:
    return node_id or wicket_id or ""


class _FallbackIndex:
    def __init__(self, dim: int):
        self.dim = dim
        self._vecs = np.empty((0, dim), dtype=np.float32)

    def add(self, vecs: np.ndarray):
        arr = np.asarray(vecs, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        self._vecs = np.vstack([self._vecs, arr])

    def search(self, query: np.ndarray, k: int):
        if self._vecs.shape[0] == 0:
            return np.zeros((1, 0), dtype=np.float32), np.zeros((1, 0), dtype=np.int64)
        q = np.asarray(query, dtype=np.float32)
        if q.ndim == 1:
            q = q.reshape(1, -1)
        sims = self._vecs @ q[0]
        order = np.argsort(-sims)[:k]
        scores = sims[order].astype(np.float32)
        idxs = order.astype(np.int64)
        return scores.reshape(1, -1), idxs.reshape(1, -1)


def _make_index(dim: int):
    try:
        import faiss  # type: ignore
        return faiss.IndexFlatIP(dim), True
    except Exception as exc:
        log.warning(f"faiss unavailable for observations — using fallback ({exc})")
        return _FallbackIndex(dim), False


@dataclass
class ObservationRecord:
    record_id: str
    evidence_text: str
    wicket_id: str
    domain: str
    source_kind: str
    evidence_rank: int
    sensor_realized: bool | None
    projection_confirmed: str | None
    confidence_at_emit: float
    workload_id: str
    ts: str
    embed_text: str
    local_energy_at_emit: float = 0.0
    phase_at_emit: float = 0.0
    is_latent_at_emit: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["node_id"] = self.wicket_id
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "ObservationRecord":
        if "wicket_id" not in d and "node_id" in d:
            d = dict(d)
            d["wicket_id"] = d["node_id"]
        return cls(**{k: v for k, v in d.items() if k != "node_id"})

    @staticmethod
    def make_embed_text(evidence_text: str, wicket_id: str, domain: str) -> str:
        return f"{domain} {wicket_id}: {evidence_text}"

    @property
    def node_id(self) -> str:
        return self.wicket_id


class ObservationMemory:
    """
    Store of closed-loop sensor observations.
    Uses FAISS if available, otherwise in-memory fallback.
    """

    def __init__(self, index_dir: Path, records_dir: Path, embedder):
        self.index_path = index_dir / "observations.faiss"
        self.records_path = records_dir / "observations.jsonl"
        self.pending_path = records_dir / "observations_pending.jsonl"
        self._embedder = embedder
        self._records: list[ObservationRecord] = []
        self._index = None
        self._dim = embedder.dim
        self._using_faiss = False

    def load(self):
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

        self._index, self._using_faiss = _make_index(self._dim)
        if self._records:
            embed_texts = [r.embed_text for r in self._records]
            vecs = self._embedder.embed(embed_texts)
            self._index.add(vecs)

        backend = "faiss" if self._using_faiss else "fallback"
        log.info(f"ObservationMemory: {len(self._records)} records loaded ({backend})")

    def record_observation(
        self,
        evidence_text: str,
        wicket_id: str | None = None,
        domain: str = "",
        source_kind: str = "",
        evidence_rank: int = 3,
        sensor_realized: bool | None = None,
        confidence_at_emit: float = 0.0,
        workload_id: str = "",
        ts: str | None = None,
        node_id: str | None = None,
        local_energy_at_emit: float = 0.0,
        phase_at_emit: float = 0.0,
        is_latent_at_emit: bool = False,
    ) -> str:
        ts = ts or datetime.now(timezone.utc).isoformat()
        condition_id = _safe_condition_id(wicket_id=wicket_id, node_id=node_id)
        embed_text = ObservationRecord.make_embed_text(evidence_text, condition_id, domain)

        rec = ObservationRecord(
            record_id=str(uuid.uuid4()),
            evidence_text=evidence_text,
            wicket_id=condition_id,
            domain=domain,
            source_kind=source_kind,
            evidence_rank=evidence_rank,
            sensor_realized=sensor_realized,
            projection_confirmed=None,
            confidence_at_emit=float(confidence_at_emit),
            workload_id=workload_id,
            ts=ts,
            embed_text=embed_text,
            local_energy_at_emit=float(local_energy_at_emit or 0.0),
            phase_at_emit=float(phase_at_emit or 0.0),
            is_latent_at_emit=bool(is_latent_at_emit),
        )

        self.pending_path.parent.mkdir(parents=True, exist_ok=True)
        with self.pending_path.open("a") as fh:
            fh.write(rec.to_json() + "\n")

        return rec.record_id

    def record_outcome(self, record_id: str, projection_confirmed: str):
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

        self.pending_path.write_text("\n".join(remaining) + "\n" if remaining else "")

        with self.records_path.open("a") as fh:
            fh.write(found.to_json() + "\n")

        self._records.append(found)
        if self._index is not None:
            vec = self._embedder.embed_one(found.embed_text).reshape(1, -1)
            self._index.add(vec)

    def recall(
        self,
        evidence_text: str,
        wicket_id: str | None = None,
        domain: str = "",
        k: int = 10,
        node_id: str | None = None,
    ) -> list[tuple[ObservationRecord, float]]:
        if self._index is None or len(self._records) == 0:
            return []

        condition_id = _safe_condition_id(wicket_id=wicket_id, node_id=node_id)
        embed_text = ObservationRecord.make_embed_text(evidence_text, condition_id, domain)
        vec = self._embedder.embed_one(embed_text).reshape(1, -1)

        k = min(k, len(self._records))
        scores, indices = self._index.search(vec, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._records):
                continue
            rec = self._records[int(idx)]
            if rec.wicket_id == condition_id:
                results.append((rec, float(score)))

        return results

    def historical_confirmation_rate(
        self,
        evidence_text: str,
        wicket_id: str | None = None,
        domain: str = "",
        k: int = 10,
        node_id: str | None = None,
    ) -> float | None:
        similar = self.recall(
            evidence_text=evidence_text,
            wicket_id=wicket_id,
            node_id=node_id,
            domain=domain,
            k=k,
        )
        confirmed = [r for r, _ in similar if r.projection_confirmed is not None]

        if len(confirmed) < 3:
            return None

        realized_count = sum(1 for r in confirmed if r.projection_confirmed == "realized")
        return realized_count / len(confirmed)

    def calibrate_confidence(
        self,
        base_confidence: float,
        evidence_text: str,
        wicket_id: str | None = None,
        domain: str = "",
        k: int = 10,
        history_weight: float = 0.4,
        node_id: str | None = None,
    ) -> float:
        rate = self.historical_confirmation_rate(
            evidence_text=evidence_text,
            wicket_id=wicket_id,
            node_id=node_id,
            domain=domain,
            k=k,
        )
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
        realized = [r for r in confirmed if r.projection_confirmed == "realized"]

        return {
            "confirmed_observations": len(confirmed),
            "pending_observations": pending_count,
            "confirmed_realized": len(realized),
            "confirmation_rate": (
                round(len(realized) / len(confirmed), 3) if confirmed else None
            ),
        }
