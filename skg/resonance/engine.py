"""
skg.resonance.engine
====================
Core resonance engine. Owns vector indexes and JSONL backing stores.

JSONL files are the source of truth.
If FAISS is available, it is used as an accelerator.
If FAISS is unavailable, the engine falls back to an in-memory cosine search.
"""
from __future__ import annotations

import json, logging, re
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar, Generic, Type

import numpy as np

from skg.resonance.memory import (
    WicketMemory, AdapterMemory, DomainMemory
)
from skg.resonance.observation_memory import ObservationMemory
from skg.resonance.embedder import make_embedder

log = logging.getLogger("skg.resonance.engine")

T = TypeVar("T")


class _FallbackIndex:
    """
    Minimal numpy-backed cosine-search index.
    Stores normalized vectors in memory.
    """
    def __init__(self, dim: int):
        self.dim = dim
        self._vecs = np.empty((0, dim), dtype=np.float32)

    def add(self, vecs: np.ndarray):
        if vecs is None:
            return
        arr = np.asarray(vecs, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.shape[1] != self.dim:
            raise ValueError(f"Vector dimension mismatch: got {arr.shape[1]}, expected {self.dim}")
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
    """
    Prefer FAISS if present; otherwise use numpy fallback.
    Returns: (index, using_faiss: bool)
    """
    try:
        import faiss  # type: ignore
        return faiss.IndexFlatIP(dim), True
    except Exception as exc:
        log.warning(f"faiss unavailable — using in-memory fallback index ({exc})")
        return _FallbackIndex(dim), False


class MemoryStore(Generic[T]):
    """
    One vector index + one JSONL backing store for a single record type.
    The JSONL file is the source of truth.
    """

    def __init__(self, name: str, record_cls: Type[T],
                 index_dir: Path, records_dir: Path,
                 embedder):
        self.name         = name
        self.record_cls   = record_cls
        self.index_path   = index_dir / f"{name}.faiss"
        self.records_path = records_dir / f"{name}.jsonl"
        self._embedder    = embedder
        self._records: list[T] = []
        self._index = None
        self._dim = embedder.dim
        self._using_faiss = False

    def load(self):
        """Load records from JSONL and rebuild vector index."""
        self.records_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)

        self._records = []
        if self.records_path.exists():
            for line in self.records_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    self._records.append(self.record_cls.from_dict(json.loads(line)))
                except Exception as e:
                    log.warning(f"Skipping malformed record in {self.records_path}: {e}")

        self._index, self._using_faiss = _make_index(self._dim)
        if self._records:
            embed_texts = [r.embed_text for r in self._records]
            vecs = self._embedder.embed(embed_texts)
            self._index.add(vecs)

        backend = "faiss" if self._using_faiss else "fallback"
        log.info(f"MemoryStore[{self.name}]: loaded {len(self._records)} records ({backend})")

    def save_record(self, record: T):
        """Append a single record to the JSONL file and add to the index."""
        self._records.append(record)
        with open(self.records_path, "a", encoding="utf-8") as f:
            f.write(record.to_json() + "\n")

        vec = self._embedder.embed_one(record.embed_text).reshape(1, -1)
        self._index.add(vec)

    def query(self, text: str, k: int = 5) -> list[tuple[T, float]]:
        """
        Return the k most similar records to the query text.
        """
        if not self._records:
            return []

        k = min(k, len(self._records))
        vec = self._embedder.embed_one(text).reshape(1, -1)
        scores, indices = self._index.search(vec, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._records):
                continue
            results.append((self._records[int(idx)], float(score)))
        return results

    def get_by_id(self, record_id: str) -> T | None:
        for r in self._records:
            if r.record_id == record_id:
                return r
        return None

    def has(self, record_id: str) -> bool:
        return any(r.record_id == record_id for r in self._records)

    @property
    def count(self) -> int:
        return len(self._records)

    @property
    def all_records(self) -> list[T]:
        return list(self._records)


class ResonanceEngine:
    """
    The resonance engine. Owns three MemoryStores and exposes
    a unified interface for storing, querying, and surfacing memory.
    """

    def __init__(self, resonance_dir: Path):
        self._dir         = resonance_dir
        self._index_dir   = resonance_dir / "index"
        self._records_dir = resonance_dir / "records"
        self._drafts_dir  = resonance_dir / "drafts"
        self._embedder    = None
        self._wickets: MemoryStore[WicketMemory] | None = None
        self._adapters: MemoryStore[AdapterMemory] | None = None
        self._domains: MemoryStore[DomainMemory] | None = None
        self.observations: ObservationMemory | None = None
        self._ready       = False

    def boot(self):
        """Initialize embedder and load all stores. Called by daemon on boot."""
        for d in [self._index_dir, self._records_dir, self._drafts_dir]:
            d.mkdir(parents=True, exist_ok=True)

        log.info("Resonance engine booting — loading embedder...")
        self._embedder = make_embedder()

        self._wickets  = MemoryStore("wickets",  WicketMemory,
                                     self._index_dir, self._records_dir, self._embedder)
        self._adapters = MemoryStore("adapters", AdapterMemory,
                                     self._index_dir, self._records_dir, self._embedder)
        self._domains  = MemoryStore("domains",  DomainMemory,
                                     self._index_dir, self._records_dir, self._embedder)

        self._wickets.load()
        self._adapters.load()
        self._domains.load()

        self.observations = ObservationMemory(
            self._index_dir, self._records_dir, self._embedder
        )
        self.observations.load()

        self._ready = True
        log.info(
            f"Resonance engine ready — "
            f"wickets={self._wickets.count} "
            f"adapters={self._adapters.count} "
            f"domains={self._domains.count}"
        )

    def _check_ready(self):
        if not self._ready:
            raise RuntimeError("ResonanceEngine.boot() has not been called")

    def store_wicket(self, record: WicketMemory) -> bool:
        self._check_ready()
        if self._wickets.has(record.record_id):
            return False
        self._wickets.save_record(record)
        return True

    def store_adapter(self, record: AdapterMemory) -> bool:
        self._check_ready()
        if self._adapters.has(record.record_id):
            return False
        self._adapters.save_record(record)
        return True

    def store_domain(self, record: DomainMemory) -> bool:
        self._check_ready()
        if self._domains.has(record.record_id):
            return False
        self._domains.save_record(record)
        return True

    def query_wickets(self, text: str, k: int = 5) -> list[tuple[WicketMemory, float]]:
        self._check_ready()
        return self._wickets.query(text, k)

    def query_adapters(self, text: str, k: int = 5) -> list[tuple[AdapterMemory, float]]:
        self._check_ready()
        return self._adapters.query(text, k)

    def query_domains(self, text: str, k: int = 3) -> list[tuple[DomainMemory, float]]:
        self._check_ready()
        return self._domains.query(text, k)

    def surface(self, query: str, k_each: int = 3) -> dict:
        """
        Surface relevant memory across all types for a given query.
        """
        self._check_ready()
        return {
            "query": query,
            "wickets": [
                {"record": r.to_dict(), "score": round(score, 6)}
                for r, score in self.query_wickets(query, k_each)
            ],
            "adapters": [
                {"record": r.to_dict(), "score": round(score, 6)}
                for r, score in self.query_adapters(query, k_each)
            ],
            "domains": [
                {"record": r.to_dict(), "score": round(score, 6)}
                for r, score in self.query_domains(query, k_each)
            ],
        }

    def status(self) -> dict:
        self._check_ready()
        return {
            "ready": self._ready,
            "memory": {
                "wickets": self._wickets.count if self._wickets else 0,
                "adapters": self._adapters.count if self._adapters else 0,
                "domains": self._domains.count if self._domains else 0,
                "observations": self.observations.status() if self.observations else None,
            },
        }

    def status_offline(self) -> dict:
        return {
            "ready": False,
            "memory": {
                "wickets": 0,
                "adapters": 0,
                "domains": 0,
                "observations": None,
            },
        }

    def save_draft(self, domain_name: str, catalog: dict) -> Path:
        """
        Persist a resonance draft into the engine's draft store.

        Drafts are the source material for later operator review and eventual
        catalog/toolchain promotion, so they live under resonance/drafts rather
        than being dropped into a temp path.
        """
        self._check_ready()
        self._drafts_dir.mkdir(parents=True, exist_ok=True)

        safe_domain = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(domain_name)).strip("_") or "draft"
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        draft_path = self._drafts_dir / f"draft_{safe_domain}_{ts}.json"

        payload = {
            "domain": domain_name,
            "saved_at": ts,
            "catalog": catalog,
        }
        draft_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return draft_path
