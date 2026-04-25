"""Semantic embedding wrapper — Voyage AI with TF-IDF fallback.

Uses Voyage AI voyage-3-lite for semantic embeddings ($0.02/M tokens, 512-dim).
Falls back to TF-IDF vectors if VOYAGE_API_KEY is not set or API fails.

Semantic embeddings capture meaning: "GPU shortage" and "chip scarcity"
have high similarity even though they share no words — unlike TF-IDF which
is purely lexical (bag-of-words).
"""

import os
import logging

import httpx
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity as sklearn_cosine

logger = logging.getLogger(__name__)

VOYAGE_API_KEY = os.getenv("VOYAGE_API_KEY")
VOYAGE_MODEL = "voyage-3-lite"
VOYAGE_URL = "https://api.voyageai.com/v1/embeddings"
VOYAGE_BATCH_SIZE = 128


async def _voyage_embed(texts: list[str]) -> np.ndarray | None:
    if not VOYAGE_API_KEY:
        return None

    all_embeddings: list[list[float]] = []
    async with httpx.AsyncClient(timeout=30) as client:
        for i in range(0, len(texts), VOYAGE_BATCH_SIZE):
            batch = texts[i : i + VOYAGE_BATCH_SIZE]
            try:
                resp = await client.post(
                    VOYAGE_URL,
                    headers={
                        "Authorization": f"Bearer {VOYAGE_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": VOYAGE_MODEL,
                        "input": batch,
                        "input_type": "document",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                batch_embs = sorted(data["data"], key=lambda d: d["index"])
                all_embeddings.extend(d["embedding"] for d in batch_embs)
            except Exception as e:
                logger.error("Voyage AI error (batch %d): %s", i // VOYAGE_BATCH_SIZE, e)
                return None

    return np.array(all_embeddings, dtype=np.float32)


async def embed_texts(texts: list[str]) -> tuple[np.ndarray, bool]:
    """Embed texts into dense vectors.

    Returns (matrix[n_texts, dim], is_semantic).
    Uses Voyage AI if VOYAGE_API_KEY is set, TF-IDF fallback otherwise.
    """
    if not texts:
        return np.zeros((0, 0), dtype=np.float32), False

    voyage_embs = await _voyage_embed(texts)
    if voyage_embs is not None:
        logger.info("Voyage AI: embedded %d texts (%d dims)", len(texts), voyage_embs.shape[1])
        return voyage_embs, True

    logger.info("TF-IDF fallback: %d texts", len(texts))
    try:
        vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            min_df=1,
            max_df=0.95,
        )
        tfidf = vectorizer.fit_transform(texts)
        return np.asarray(tfidf.todense(), dtype=np.float32), False
    except ValueError:
        return np.zeros((len(texts), 1), dtype=np.float32), False


def cosine_similarity(vectors_a: np.ndarray, vectors_b: np.ndarray | None = None) -> np.ndarray:
    """Thin wrapper around sklearn cosine_similarity."""
    if vectors_a.size == 0:
        n = vectors_a.shape[0]
        m = vectors_b.shape[0] if vectors_b is not None else n
        return np.zeros((n, m), dtype=np.float32)
    if vectors_b is None:
        return sklearn_cosine(vectors_a)
    return sklearn_cosine(vectors_a, vectors_b)


def is_semantic_available() -> bool:
    return bool(VOYAGE_API_KEY)
