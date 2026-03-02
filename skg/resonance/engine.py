"""
skg.resonance.engine
====================
Core resonance engine. Owns FAISS indexes and JSONL backing stores.
One index + one records file per memory type (wicket, adapter, domain).

Layout under RESONANCE_DIR:
  index/wickets.faiss       — FAISS flat L2 index of wicket embeddings
  index/adapters.faiss      — FAISS flat L2 index of adapter embeddings
  index/domains.faiss       — FAISS flat L2 index of domain embeddings
  records/wickets.jsonl     — WicketMemory records (order matches index)
  records/adapters.jsonl    — AdapterMemory records
  records/domains.jsonl     — DomainMemory records

Thread safety: not designed for concurrent writes. The daemon is single-process
so this is fine. If concurrent access is ever needed, add a filelock.
"""

from __future__ import annotations
import json, logging, uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import TypeVar, Generic, Type

import numpy as np

from skg.resonance.memory import (
    WicketMemory, AdapterMemory, DomainMemory, RECORD_TYPES
)
from skg.resonance.embedder import make_embedder

log = logging.getLogger("skg.resonance.engine")

T = TypeVar("T")


class MemoryStore(Generic[T]):
    """
    One FAISS index + one JSONL backing store for a single record type.
    The JSONL file is the source of truth. The FAISS index is rebuilt
    from it on load if the index is missing or dimensionally mismatched.
    """

    def __init__(self, name: str, record_cls: Type[T],
                 index_dir: Path, records_dir: Path,
                 embedder):
        self.name        = name
        self.record_cls  = record_cls
        self.index_path  = index_dir  / f"{name}.faiss"
        self.records_path = records_dir / f"{name}.jsonl"
        self._embedder   = embedder
        self._records: list[T] = []
        self._index = None
        self._dim   = embedder.dim

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self):
        """Load records from JSONL and rebuild FAISS index."""
        import faiss

        self.records_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)

        self._records = []
        if self.records_path.exists():
            for line in self.records_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    self._records.append(self.record_cls.from_dict(json.loads(line)))
                except Exception as e:
                    log.warning(f"Skipping malformed record in {self.records_path}: {e}")

        # Build FAISS index from records
        self._index = faiss.IndexFlatIP(self._dim)  # inner product on normalized vecs = cosine
        if self._records:
            embed_texts = [r.embed_text for r in self._records]
            vecs = self._embedder.embed(embed_texts)
            self._index.add(vecs)

        log.info(f"MemoryStore[{self.name}]: loaded {len(self._records)} records")

    def save_record(self, record: T):
        """Append a single record to the JSONL file and add to FAISS index."""
        self._records.append(record)
        with open(self.records_path, "a", encoding="utf-8") as f:
            f.write(record.to_json() + "\n")
        vec = self._embedder.embed_one(record.embed_text).reshape(1, -1)
        self._index.add(vec)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(self, text: str, k: int = 5) -> list[tuple[T, float]]:
        """
        Return the k most similar records to the query text.
        Returns list of (record, score) tuples, score in [0, 1].
        """
        if not self._records:
            return []
        k = min(k, len(self._records))
        vec = self._embedder.embed_one(text).reshape(1, -1)
        scores, indices = self._index.search(vec, k)
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue
            results.append((self._records[idx], float(score)))
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

        self._ready = True
        log.info(f"Resonance engine ready — "
                 f"wickets={self._wickets.count} "
                 f"adapters={self._adapters.count} "
                 f"domains={self._domains.count}")

    def _check_ready(self):
        if not self._ready:
            raise RuntimeError("ResonanceEngine.boot() has not been called")

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def store_wicket(self, record: WicketMemory) -> bool:
        """Store a wicket record. Returns True if new, False if already present."""
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

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query_wickets(self, text: str, k: int = 5) -> list[tuple[WicketMemory, float]]:
        """Find wickets semantically similar to the query text."""
        self._check_ready()
        return self._wickets.query(text, k)

    def query_adapters(self, text: str, k: int = 5) -> list[tuple[AdapterMemory, float]]:
        """Find adapters semantically similar to the query text."""
        self._check_ready()
        return self._adapters.query(text, k)

    def query_domains(self, text: str, k: int = 3) -> list[tuple[DomainMemory, float]]:
        """Find domains semantically similar to the query text."""
        self._check_ready()
        return self._domains.query(text, k)

    # ------------------------------------------------------------------
    # Surface — context injection for draft generation
    # ------------------------------------------------------------------

    def surface(self, query: str, k_each: int = 3) -> dict:
        """
        Surface relevant memory across all types for a given query.
        Used by the drafter to understand the existing pattern space
        before proposing wickets for a new domain.
        """
        self._check_ready()
        return {
            "wickets":  [(r.to_dict(), s) for r, s in self.query_wickets(query, k_each)],
            "adapters": [(r.to_dict(), s) for r, s in self.query_adapters(query, k_each)],
            "domains":  [(r.to_dict(), s) for r, s in self.query_domains(query, k_each)],
        }

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        self._check_ready()
        return {
            "ready":    True,
            "embedder": type(self._embedder).__name__,
            "dim":      self._embedder.dim,
            "memory": {
                "wickets":  self._wickets.count,
                "adapters": self._adapters.count,
                "domains":  self._domains.count,
            },
            "paths": {
                "index":   str(self._index_dir),
                "records": str(self._records_dir),
                "drafts":  str(self._drafts_dir),
            },
        }

    def status_offline(self) -> dict:
        return {"ready": False, "reason": "engine not booted"}

    # ------------------------------------------------------------------
    # Drafts
    # ------------------------------------------------------------------

    def save_draft(self, domain_name: str, catalog: dict) -> Path:
        """Persist a proposed catalog draft for human review."""
        self._check_ready()
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        path = self._drafts_dir / f"draft_{domain_name}_{ts}.json"
        path.write_text(
            json.dumps({"meta": {"domain": domain_name, "drafted_at": ts,
                                  "status": "pending_review"},
                        "catalog": catalog}, indent=2),
            encoding="utf-8"
        )
        log.info(f"Draft saved: {path.name}")
        return path

    def list_drafts(self) -> list[dict]:
        """List all pending drafts."""
        self._check_ready()
        drafts = []
        for p in sorted(self._drafts_dir.glob("draft_*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                drafts.append({"file": p.name, "meta": d.get("meta", {})})
            except Exception:
                pass
        return drafts
