"""Relevance filter — cross-source scoring for dashboard articles.

Scores each article based on:
1. Pattern match: TF-IDF similarity with detected patterns
2. Cross-source match: TF-IDF similarity with articles from other sources
3. User interest match: keyword overlap with user facts

Trusted sources (IEEE, ACM, Science Direct, Inovacao Tecnologica) get a
score bonus but must still match at least one topic keyword.
"""

import os
import json
import logging
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

DATA_DIR = os.getenv("DATA_DIR", "/data")
MEMORY_FILE = os.path.join(DATA_DIR, "memory.json")
SCORED_FILE = os.path.join(DATA_DIR, "feeds_scored.json")

logger = logging.getLogger(__name__)

TRUSTED_SOURCES = {
    "ACM TechNews",
    "IEEE Spectrum",
    "Inovacao Tecnologica",
    "Science Direct",
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
    "interest rate",
    "devops", "kubernetes", "docker", "cloud", "infrastructure",
    "platform", "pipeline", "terraform", "cicd", "ci/cd",
    "5g", "6g", "wireless", "telecom",
}

RELEVANCE_THRESHOLD = 15
MAX_SCORED = 500
SCORED_RETENTION_DAYS = 7


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


def score_articles(
    articles: list[dict],
    patterns: list[dict],
    user_facts: list[str] | None = None,
) -> list[dict]:
    """Score and filter articles by cross-source relevance.

    Returns scored articles sorted by relevance_score DESC.
    Trusted sources always pass regardless of score.
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

    try:
        vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            min_df=1,
            max_df=0.95,
        )
        tfidf = vectorizer.fit_transform(all_texts)
    except ValueError:
        return _fallback_score(articles, fact_keywords)

    n_articles = len(articles)
    article_vectors = tfidf[:n_articles]
    pattern_vectors = tfidf[n_articles:]

    if pattern_vectors.shape[0] > 0:
        p_sims = cosine_similarity(article_vectors, pattern_vectors)
        max_pattern_sim = np.asarray(p_sims.max(axis=1)).flatten()
    else:
        max_pattern_sim = np.zeros(n_articles)

    a_sims = cosine_similarity(article_vectors)

    scored: list[dict] = []
    for i, article in enumerate(articles):
        source = article.get("source", "")
        is_trusted_source = source in TRUSTED_SOURCES
        text_lower = f"{article.get('title', '')} {article.get('summary', '')}".lower()

        on_topic = any(kw in text_lower for kw in TOPIC_KEYWORDS)
        trusted = is_trusted_source and on_topic

        # Pattern match component (0-40)
        p_score = 40 * float(max_pattern_sim[i])

        # Cross-source component (0-25)
        cross_vals = []
        for j in range(n_articles):
            if i != j and articles[j].get("source", "") != source:
                cross_vals.append(float(a_sims[i][j]))
        if cross_vals:
            cross_vals.sort(reverse=True)
            top5 = cross_vals[:5]
            c_score = 25 * (sum(top5) / len(top5))
        else:
            c_score = 0

        # User interest component (0-25)
        if fact_keywords:
            text_words = set(text_lower.split())
            matched = len(fact_keywords & text_words)
            f_score = 25 * min(1.0, matched / 3)
        else:
            f_score = 0

        raw = 10 + p_score + c_score + f_score
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
    cutoff = datetime.now(timezone.utc) - timedelta(days=SCORED_RETENTION_DAYS)

    existing: list[dict] = []
    if os.path.exists(SCORED_FILE):
        try:
            with open(SCORED_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = []

    seen_urls: set[str] = set()
    merged: list[dict] = []

    for article in scored:
        url = article.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            merged.append(article)

    for article in existing:
        url = article.get("url", "")
        if url and url not in seen_urls:
            try:
                fetched = datetime.fromisoformat(article.get("fetched_at", ""))
                if fetched.tzinfo is None:
                    fetched = fetched.replace(tzinfo=timezone.utc)
                if fetched < cutoff:
                    continue
            except (ValueError, KeyError):
                continue
            seen_urls.add(url)
            merged.append(article)

    merged.sort(key=lambda x: x.get("relevance_score", 0), reverse=True)
    merged = merged[:MAX_SCORED]

    with open(SCORED_FILE, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
    logger.info("Relevance filter: %d articles scored (7-day window).", len(merged))
