"""
skg.resonance.embedder
======================
Text → dense vector embedding for the resonance engine.

Primary:  sentence-transformers (all-MiniLM-L6-v2, 384 dimensions)
Fallback: TF-IDF cosine similarity (numpy only, no ML deps)

The embedder detects availability at import time and uses the best option.
The FAISS index dimension must match the embedder dimension — the engine
checks this on load and rebuilds if there's a mismatch.
"""

from __future__ import annotations
import logging
import os
import numpy as np
from pathlib import Path

log = logging.getLogger("skg.resonance.embedder")

# Canonical model — small, fast, good at semantic similarity for short text
ST_MODEL_NAME = "all-MiniLM-L6-v2"
ST_DIM        = 384

# TF-IDF fallback dimension
TFIDF_DIM = 256


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _load_embedding_config() -> dict:
    try:
        import yaml
        from skg_core.config.paths import SKG_CONFIG_DIR, SKG_HOME
    except Exception:
        return {}

    candidates = [
        SKG_CONFIG_DIR / "skg_config.yaml",
        SKG_HOME / "config" / "skg_config.yaml",
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        resonance = data.get("resonance", {}) or {}
        embedding = resonance.get("embedding", {}) or {}
        if isinstance(embedding, dict):
            return embedding
    return {}


def _try_import_st():
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer
    except ImportError:
        return None


class SentenceTransformerEmbedder:
    """Primary embedder using sentence-transformers."""

    dim = ST_DIM

    def __init__(self, model_name: str = ST_MODEL_NAME):
        from sentence_transformers import SentenceTransformer
        log.info(f"Loading sentence-transformers model: {model_name}")
        self._model = SentenceTransformer(model_name)
        log.info("Embedder ready.")

    def embed(self, texts: list[str]) -> np.ndarray:
        """Embed a list of strings. Returns float32 ndarray shape (N, dim)."""
        vecs = self._model.encode(texts, convert_to_numpy=True,
                                   normalize_embeddings=True)
        return vecs.astype(np.float32)

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]


class TFIDFEmbedder:
    """
    Fallback embedder using TF-IDF vectors truncated/padded to TFIDF_DIM.
    Fit on first call, updated as new texts arrive.
    Not as semantically rich as sentence-transformers but zero extra deps.
    """

    dim = TFIDF_DIM

    def __init__(self):
        self._vocab: dict[str, int] = {}
        self._idf:   dict[str, float] = {}
        self._corpus: list[str] = []
        log.warning("sentence-transformers not available — using TF-IDF fallback embedder")

    def _tokenize(self, text: str) -> list[str]:
        import re
        return re.findall(r"[a-z0-9_]+", text.lower())

    def _fit(self, texts: list[str]):
        import math
        all_tokens = set()
        for t in texts:
            all_tokens.update(self._tokenize(t))
        self._vocab = {tok: i for i, tok in enumerate(sorted(all_tokens))}
        N = len(texts)
        doc_freq: dict[str, int] = {}
        for t in texts:
            for tok in set(self._tokenize(t)):
                doc_freq[tok] = doc_freq.get(tok, 0) + 1
        self._idf = {tok: math.log((N + 1) / (df + 1)) + 1
                     for tok, df in doc_freq.items()}

    def _vectorize(self, text: str) -> np.ndarray:
        tokens = self._tokenize(text)
        vec = np.zeros(max(len(self._vocab), 1), dtype=np.float32)
        for tok in tokens:
            if tok in self._vocab:
                vec[self._vocab[tok]] += self._idf.get(tok, 1.0)
        # Truncate or pad to TFIDF_DIM
        if len(vec) >= self.dim:
            vec = vec[:self.dim]
        else:
            vec = np.pad(vec, (0, self.dim - len(vec)))
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def embed(self, texts: list[str]) -> np.ndarray:
        # Accumulate corpus for future rebuild calls, but only fit the IDF
        # basis once.  Refitting on every call would change the embedding
        # weights for all previously indexed vectors, making the append-only
        # index inconsistent.
        self._corpus.extend(texts)
        if not self._vocab:
            self._fit(self._corpus)
        return np.stack([self._vectorize(t) for t in texts])

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]

    def rebuild(self) -> None:
        """
        Refit the TF-IDF basis on all texts seen so far.
        All previously indexed vectors become stale after this call —
        callers must re-index if they need consistent similarity search.
        """
        if self._corpus:
            self._fit(self._corpus)


def make_embedder() -> SentenceTransformerEmbedder | TFIDFEmbedder:
    """Return best available embedder."""
    cfg = _load_embedding_config()

    if _truthy(os.getenv("SKG_RESONANCE_OFFLINE")) or _truthy(cfg.get("offline")):
        log.info("Resonance embedding offline mode enabled — using TF-IDF fallback embedder")
        return TFIDFEmbedder()

    if _truthy(cfg.get("prefer_tfidf")):
        log.info("Resonance embedding prefer_tfidf enabled — using TF-IDF fallback embedder")
        return TFIDFEmbedder()

    model_name = str(cfg.get("model") or ST_MODEL_NAME)
    ST = _try_import_st()
    if ST is not None:
        try:
            return SentenceTransformerEmbedder(model_name=model_name)
        except Exception as e:
            log.warning(f"sentence-transformers failed to load: {e} — falling back to TF-IDF")
    return TFIDFEmbedder()
