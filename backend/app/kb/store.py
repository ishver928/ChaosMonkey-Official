"""CWE knowledge base + retrieval (RAG).

Loads ``data/cwe_seed.json``, builds one searchable document per CWE, and retrieves
the top-k relevant entries for a code chunk. Embeddings come from Ollama's
``nomic-embed-text`` when available; otherwise it falls back to scikit-learn TF-IDF.
Similarity is plain numpy cosine (no external vector DB needed), which keeps the whole
thing deterministic and offline.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

import numpy as np

from ..config import REPO_DIR, settings

logger = logging.getLogger("chaosmonkey.kb")

SEED_PATH = REPO_DIR / "data" / "cwe_seed.json"


@dataclass
class CweEntry:
    id: str
    name: str
    description: str
    consequences: str
    mitigation: str
    indicators: list[str]
    pattern_rules: list[str]
    examples: dict

    def document(self) -> str:
        return " ".join([
            self.id, self.name, self.description, self.consequences,
            self.mitigation, " ".join(self.indicators),
        ])


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z_][a-zA-Z_0-9]*", text.lower())


class KnowledgeBase:
    """In-memory CWE store with deterministic top-k retrieval."""

    def __init__(self, seed_path: Path = SEED_PATH):
        self.seed_path = seed_path
        self.entries: list[CweEntry] = []
        self.by_id: dict[str, CweEntry] = {}
        self._embeddings: Optional[np.ndarray] = None
        self._vectorizer = None
        self.embed_backend = "none"
        self._load()
        self._build_index()

    def _load(self) -> None:
        data = json.loads(self.seed_path.read_text(encoding="utf-8"))
        self.entries = [CweEntry(**e) for e in data]
        self.by_id = {e.id: e for e in self.entries}

    # ---- indexing -------------------------------------------------------
    def _build_index(self) -> None:
        docs = [e.document() for e in self.entries]
        vectors = self._embed_ollama(docs)
        if vectors is not None:
            self._embeddings = vectors
            self.embed_backend = f"ollama:{settings.embed_model}"
            return
        # Offline fallback: TF-IDF
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer

            self._vectorizer = TfidfVectorizer(token_pattern=r"[a-zA-Z_][a-zA-Z_0-9]*", lowercase=True)
            mat = self._vectorizer.fit_transform(docs)
            self._embeddings = mat.toarray().astype(np.float32)
            self.embed_backend = "tfidf"
        except Exception as exc:  # pragma: no cover - sklearn always present per requirements
            logger.warning("TF-IDF unavailable (%s); using keyword overlap only", exc)
            self._embeddings = None
            self.embed_backend = "keyword"

    def _embed_ollama(self, texts: list[str]) -> Optional[np.ndarray]:
        if settings.llm_mock:
            return None
        try:
            import httpx

            vecs = []
            with httpx.Client(timeout=5.0) as client:
                for t in texts:
                    r = client.post(
                        f"{settings.ollama_url}/api/embeddings",
                        json={"model": settings.embed_model, "prompt": t},
                    )
                    if r.status_code != 200:
                        return None
                    vecs.append(r.json()["embedding"])
            arr = np.asarray(vecs, dtype=np.float32)
            return arr
        except Exception:
            return None

    def _embed_query(self, text: str) -> Optional[np.ndarray]:
        if self.embed_backend.startswith("ollama"):
            v = self._embed_ollama([text])
            return v[0] if v is not None else None
        if self.embed_backend == "tfidf" and self._vectorizer is not None:
            return self._vectorizer.transform([text]).toarray().astype(np.float32)[0]
        return None

    # ---- retrieval ------------------------------------------------------
    def retrieve(self, code: str, top_k: int = 4) -> list[CweEntry]:
        """Return the top-k CWE entries for a code chunk, deterministically."""
        qv = self._embed_query(code) if self._embeddings is not None else None
        if qv is not None and self._embeddings is not None:
            mat = self._embeddings
            denom = (np.linalg.norm(mat, axis=1) * np.linalg.norm(qv)) + 1e-9
            sims = (mat @ qv) / denom
            # Deterministic tie-break: score desc, then id asc.
            order = sorted(range(len(sims)), key=lambda i: (-float(sims[i]), self.entries[i].id))
            return [self.entries[i] for i in order[:top_k] if sims[i] > 0]
        return self._keyword_retrieve(code, top_k)

    def _keyword_retrieve(self, code: str, top_k: int) -> list[CweEntry]:
        tokens = set(_tokenize(code))
        scored = []
        for e in self.entries:
            score = len(tokens.intersection(set(e.indicators)))
            if score > 0:
                scored.append((score, e))
        scored.sort(key=lambda x: (-x[0], x[1].id))
        return [e for _, e in scored[:top_k]]

    def get(self, cwe_id: str) -> Optional[CweEntry]:
        return self.by_id.get(cwe_id)

    def search(self, q: str, limit: int = 10) -> list[CweEntry]:
        ql = q.lower()
        exact = [e for e in self.entries if ql in e.id.lower() or ql in e.name.lower()]
        if exact:
            return exact[:limit]
        return self.retrieve(q, limit)

    def size(self) -> int:
        return len(self.entries)


@lru_cache(maxsize=1)
def get_kb() -> KnowledgeBase:
    return KnowledgeBase()
