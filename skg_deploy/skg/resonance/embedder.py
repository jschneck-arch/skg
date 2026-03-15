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
import numpy as np
from pathlib import Path

log = logging.getLogger("skg.resonance.embedder")

# Canonical model — small, fast, good at semantic similarity for short text
ST_MODEL_NAME = "all-MiniLM-L6-v2"
ST_DIM        = 384

# TF-IDF fallback dimension
TFIDF_DIM = 256


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
        all_texts = self._corpus + texts
        self._fit(all_texts)
        self._corpus = all_texts
        return np.stack([self._vectorize(t) for t in texts])

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]


def make_embedder() -> SentenceTransformerEmbedder | TFIDFEmbedder:
    """Return best available embedder."""
    ST = _try_import_st()
    if ST is not None:
        try:
            return SentenceTransformerEmbedder()
        except Exception as e:
            log.warning(f"sentence-transformers failed to load: {e} — falling back to TF-IDF")
    return TFIDFEmbedder()
