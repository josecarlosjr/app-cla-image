"""Semantic embedding wrapper — Voyage AI with TF-IDF fallback.

Uses Voyage AI voyage-3-lite for semantic embeddings ($0.02/M tokens, 512-dim).
Falls back to TF-IDF vectors if VOYAGE_API_KEY is not set or API fails.

embed_texts_cached() stores Voyage vectors in SQLite so already-seen articles
are never re-embedded — saves API cost on repeat runs.
"""

import os
import logging

import httpx
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity as sklearn_cosine

from database import get_embeddings_batch, save_embeddings_batch, prune_embeddings

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


def _tfidf_embed(texts: list[str]) -> tuple[np.ndarray, bool]:
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


async def embed_texts(texts: list[str]) -> tuple[np.ndarray, bool]:
    """Embed texts into dense vectors (no caching).

    Returns (matrix[n_texts, dim], is_semantic).
    """
    if not texts:
        return np.zeros((0, 0), dtype=np.float32), False

    voyage_embs = await _voyage_embed(texts)
    if voyage_embs is not None:
        logger.info("Voyage AI: embedded %d texts (%d dims)", len(texts), voyage_embs.shape[1])
        return voyage_embs, True

    return _tfidf_embed(texts)


async def embed_texts_cached(
    texts: list[str],
    urls: list[str | None],
) -> tuple[np.ndarray, bool]:
    """Embed with SQLite-backed vector cache for Voyage embeddings.

    urls[i] is the cache key for texts[i], or None if not cacheable
    (e.g. pattern analysis texts). Cached vectors avoid repeat Voyage API calls.
    Falls back to TF-IDF (uncached) when Voyage is unavailable.
    """
    if not texts:
        return np.zeros((0, 0), dtype=np.float32), False

    if not VOYAGE_API_KEY:
        return _tfidf_embed(texts)

    cacheable_urls = [u for u in urls if u]
    cached = get_embeddings_batch(cacheable_urls, VOYAGE_MODEL) if cacheable_urls else {}

    need_indices = []
    for i, url in enumerate(urls):
        if not url or url not in cached:
            need_indices.append(i)

    if not need_indices:
        dim = next(iter(cached.values())).shape[0]
        result = np.zeros((len(texts), dim), dtype=np.float32)
        for i, url in enumerate(urls):
            if url and url in cached:
                result[i] = cached[url]
        logger.info("Embedding cache: all %d texts cached (%d dims)", len(texts), dim)
        return result, True

    uncached_texts = [texts[i] for i in need_indices]
    voyage_embs = await _voyage_embed(uncached_texts)

    if voyage_embs is None:
        return _tfidf_embed(texts)

    new_pairs = []
    for j, idx in enumerate(need_indices):
        url = urls[idx]
        if url:
            new_pairs.append((url, voyage_embs[j]))
    if new_pairs:
        save_embeddings_batch(new_pairs, VOYAGE_MODEL)
        prune_embeddings()

    dim = voyage_embs.shape[1]
    result = np.zeros((len(texts), dim), dtype=np.float32)
    j = 0
    for i in range(len(texts)):
        url = urls[i]
        if url and url in cached:
            result[i] = cached[url]
        else:
            result[i] = voyage_embs[j]
            j += 1

    cached_count = len(texts) - len(need_indices)
    logger.info(
        "Voyage AI: %d cached + %d computed = %d (%d dims)",
        cached_count, len(need_indices), len(texts), dim,
    )
    return result, True


def cosine_similarity(vectors_a: np.ndarray, vectors_b: np.ndarray | None = None) -> np.ndarray:
    if vectors_a.size == 0:
        n = vectors_a.shape[0]
        m = vectors_b.shape[0] if vectors_b is not None else n
        return np.zeros((n, m), dtype=np.float32)
    if vectors_b is None:
        return sklearn_cosine(vectors_a)
    return sklearn_cosine(vectors_a, vectors_b)


def is_semantic_available() -> bool:
    return bool(VOYAGE_API_KEY)
