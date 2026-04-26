"""Relevance filter — cross-source scoring for dashboard articles.

Scores each article based on:
1. Pattern match: semantic similarity with detected patterns (0-35)
2. Cross-source semantic match: similarity with articles from other sources (0-20)
3. Cross-source entity/topic overlap: shared entities/topics from Haiku enrichment (0-10)
4. User interest match: keyword overlap with user facts (0-25)
5. Base: 10

Uses Voyage AI semantic embeddings when VOYAGE_API_KEY is set.
Falls back to TF-IDF (lexical) when Voyage is unavailable; entity/topic
component runs only when semantic embeddings are available.
"""

import os
import json
import logging

import numpy as np

from embeddings import embed_texts_cached, cosine_similarity
from enrichment import enrich_articles, entity_topic_score
from database import update_article_scores, clear_stale_scores

DATA_DIR = os.getenv("DATA_DIR", "/data")
MEMORY_FILE = os.path.join(DATA_DIR, "memory.json")

logger = logging.getLogger(__name__)

TRUSTED_SOURCES = {
    "ACM TechNews",
    "IEEE Spectrum",
    "Inovacao Tecnologica",
    "Science Direct",
    "CNBC Investing",
    "MarketWatch",
    "Nasdaq",
}

TOPIC_KEYWORDS = {
    "semiconductor", "gpu", "nvidia", "tsmc", "llm", "agi", "ai ",
    "chip", "intel", "amd", "foundry", "neural", "machine learning",
    "deep learning", "robot", "automat",
    "nuclear", "solar", "wind", "grid", "battery", "datacenter",
    "energy", "power", "renewable", "smr", "fusion",
    "rare earth", "copper", "lithium", "cobalt", "critical mineral",
    "mining",
    "sanctions", "brics", "tariff", "trade war", "geopolit", "nato",
    "us china", "eu digital",
    "cyber", "hack", "ransomware", "vulnerability", "breach", "malware",
    "zero-day", "apt",
    "quantum", "superconductor", "material science", "physics",
    "satellite", "hypersonic", "space", "missile", "defense", "orbit",
    "stock", "recession", "inflation", "crypto", "etf", "market",
    "interest rate", "earnings", "nasdaq", "s&p 500", "dow jones",
    "trading", "dividend", "wall street", "hedge fund",
    "devops", "kubernetes", "docker", "cloud", "infrastructure",
    "platform", "pipeline", "terraform", "cicd", "ci/cd",
    "5g", "6g", "wireless", "telecom",
}

RELEVANCE_THRESHOLD = 15
MAX_SCORED = 500
SCORED_RETENTION_DAYS = 7
ENRICH_MAX_NEW_PER_RUN = 30


def _load_user_facts() -> list[str]:
    if os.path.exists(MEMORY_FILE):
        try:
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("facts", []) if isinstance(data, dict) else []
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _extract_fact_keywords(facts: list[str]) -> set[str]:
    keywords = set()
    for fact in facts:
        for word in fact.lower().split():
            if len(word) > 4:
                keywords.add(word)
    return keywords


async def score_articles(
    articles: list[dict],
    patterns: list[dict],
    user_facts: list[str] | None = None,
) -> list[dict]:
    """Score and filter articles by cross-source relevance.

    Uses semantic embeddings (Voyage AI) when available, TF-IDF fallback.
    Returns scored articles sorted by relevance_score DESC.
    """
    if not articles:
        return []

    if user_facts is None:
        user_facts = _load_user_facts()

    fact_keywords = _extract_fact_keywords(user_facts)
    pattern_texts = [p.get("analysis", "") for p in patterns if p.get("analysis")]

    article_texts = [
        f"{a.get('title', '')} {a.get('summary', '')}" for a in articles
    ]

    all_texts = article_texts + pattern_texts
    if len(all_texts) < 2:
        return _fallback_score(articles, fact_keywords)

    article_urls = [a.get("url") for a in articles]
    all_urls: list[str | None] = article_urls + [None] * len(pattern_texts)
    embs, is_semantic = await embed_texts_cached(all_texts, all_urls)
    if embs.size == 0:
        return _fallback_score(articles, fact_keywords)

    n_articles = len(articles)
    article_embs = embs[:n_articles]

    if pattern_texts:
        pattern_embs = embs[n_articles:]
        p_sims = cosine_similarity(article_embs, pattern_embs)
        max_pattern_sim = np.asarray(p_sims.max(axis=1)).flatten()
    else:
        max_pattern_sim = np.zeros(n_articles)

    a_sims = cosine_similarity(article_embs)

    if is_semantic:
        await enrich_articles(articles, max_new=ENRICH_MAX_NEW_PER_RUN)

    scored: list[dict] = []
    for i, article in enumerate(articles):
        source = article.get("source", "")
        is_trusted_source = source in TRUSTED_SOURCES
        text_lower = f"{article.get('title', '')} {article.get('summary', '')}".lower()

        on_topic = any(kw in text_lower for kw in TOPIC_KEYWORDS)
        trusted = is_trusted_source and on_topic

        # Pattern match component (0-35)
        p_score = 35 * float(max_pattern_sim[i])

        # Cross-source semantic component (0-20)
        cross_vals: list[float] = []
        entity_vals: list[float] = []
        for j in range(n_articles):
            if i == j or articles[j].get("source", "") == source:
                continue
            cross_vals.append(float(a_sims[i][j]))
            entity_vals.append(entity_topic_score(article, articles[j]))

        if cross_vals:
            cross_vals.sort(reverse=True)
            top5 = cross_vals[:5]
            c_score = 20 * (sum(top5) / len(top5))
        else:
            c_score = 0

        # Cross-source entity/topic component (0-10)
        if entity_vals:
            entity_vals.sort(reverse=True)
            top3 = entity_vals[:3]
            e_score = 10 * (sum(top3) / len(top3))
        else:
            e_score = 0

        # User interest component (0-25)
        if fact_keywords:
            text_words = set(text_lower.split())
            matched = len(fact_keywords & text_words)
            f_score = 25 * min(1.0, matched / 3)
        else:
            f_score = 0

        raw = 10 + p_score + c_score + e_score + f_score
        relevance = min(100, int(raw))

        if trusted:
            relevance = max(relevance, 50)

        if relevance >= RELEVANCE_THRESHOLD or trusted:
            entry = dict(article)
            entry["relevance_score"] = relevance
            entry["relevance_trusted"] = trusted
            scored.append(entry)

    scored.sort(key=lambda x: x["relevance_score"], reverse=True)
    return scored[:MAX_SCORED]


def _fallback_score(articles: list[dict], fact_keywords: set[str]) -> list[dict]:
    """Score when TF-IDF can't run (too few articles)."""
    scored = []
    for article in articles:
        source = article.get("source", "")
        text_lower = f"{article.get('title', '')} {article.get('summary', '')}".lower()
        on_topic = any(kw in text_lower for kw in TOPIC_KEYWORDS)
        trusted = source in TRUSTED_SOURCES and on_topic

        if fact_keywords:
            text_words = set(text_lower.split())
            matched = len(fact_keywords & text_words)
            f_score = 25 * min(1.0, matched / 3)
        else:
            f_score = 0

        relevance = min(100, int(10 + f_score))
        if trusted:
            relevance = max(relevance, 50)

        if relevance >= RELEVANCE_THRESHOLD or trusted:
            entry = dict(article)
            entry["relevance_score"] = relevance
            entry["relevance_trusted"] = trusted
            scored.append(entry)

    scored.sort(key=lambda x: x["relevance_score"], reverse=True)
    return scored[:MAX_SCORED]


def save_scored(scored: list[dict]):
    update_article_scores(scored)
    clear_stale_scores(days=SCORED_RETENTION_DAYS)
    logger.info("Relevance filter: %d articles scored.", len(scored))
