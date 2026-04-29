"""Article enrichment using Claude Haiku.

Extracts structured metadata (entities + topics) per article so the matcher
can combine semantic similarity with explicit entity/topic overlap. Helps
disambiguate articles that look semantically similar but are about different
companies, products, or places.

Cached by URL in SQLite — each article is enriched at most once.
Run-level cap (max_new) controls cost per invocation.
"""

import asyncio
import logging

from llm import generate_json, MODEL_HAIKU
from database import get_enrichments_batch, save_enrichment, prune_enrichments

logger = logging.getLogger(__name__)

MAX_CACHE_ENTRIES = 12000

ENRICHMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "3-8 named entities clearly stated in the text: companies "
                "(nvidia, tsmc), products (gpt-4, h100), people (sam altman), "
                "places (taiwan), technologies (transformer, kubernetes). "
                "Lowercase canonical form. Skip generic terms like 'ai' or 'tech'."
            ),
        },
        "topics": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "3-5 short noun phrases (2-4 words each, lowercase) that "
                "describe what the article is actually about. Examples: "
                "'gpu shortage', 'ai chip export controls', 'nuclear smr deployment'."
            ),
        },
    },
    "required": ["entities", "topics"],
    "additionalProperties": False,
}

ENRICHMENT_SYSTEM = (
    "You extract structured metadata from news articles to enable semantic "
    "clustering. Be precise. Only return entities and topics clearly stated "
    "in the text — do not infer or guess. Lowercase, canonical form."
)


async def _enrich_one(article: dict) -> dict | None:
    title = article.get("title", "")
    summary = article.get("summary", "")
    if not title:
        return None

    prompt = (
        f"Title: {title}\n\n"
        f"Summary: {summary[:600]}\n\n"
        f"Extract entities and topics."
    )

    result = await generate_json(
        prompt=prompt,
        schema=ENRICHMENT_SCHEMA,
        system=ENRICHMENT_SYSTEM,
        model=MODEL_HAIKU,
        max_tokens=512,
    )

    if not result:
        return None

    return {
        "entities": [
            e.lower().strip() for e in result.get("entities", []) if e and e.strip()
        ],
        "topics": [
            t.lower().strip() for t in result.get("topics", []) if t and t.strip()
        ],
    }


async def enrich_articles(
    articles: list[dict],
    max_new: int = 30,
    concurrency: int = 5,
) -> None:
    """Add `_entities` and `_topics` fields in-place to each article.

    Uses SQLite-backed URL-keyed cache. Articles already cached are hydrated
    for free. New articles are enriched via Haiku, capped at max_new per call.
    """
    urls = [a.get("url", "") for a in articles if a.get("url")]
    cached = get_enrichments_batch(urls)

    needs: list[dict] = []
    for article in articles:
        url = article.get("url", "")
        if url and url in cached:
            article["_entities"] = cached[url]["entities"]
            article["_topics"] = cached[url]["topics"]
        else:
            article["_entities"] = []
            article["_topics"] = []
            if url:
                needs.append(article)

    to_enrich = needs[:max_new]
    if not to_enrich:
        logger.info(
            "Enrichment: %d articles cached, 0 new",
            len(articles) - len(needs),
        )
        return

    sem = asyncio.Semaphore(concurrency)

    async def _worker(article: dict):
        async with sem:
            result = await _enrich_one(article)
            if result:
                save_enrichment(article["url"], result["entities"], result["topics"])
                article["_entities"] = result["entities"]
                article["_topics"] = result["topics"]

    await asyncio.gather(*[_worker(a) for a in to_enrich])
    prune_enrichments(MAX_CACHE_ENTRIES)

    cached_count = len(articles) - len(needs)
    deferred = max(0, len(needs) - max_new)
    logger.info(
        "Enrichment: %d cached, %d enriched, %d deferred to next run",
        cached_count, len(to_enrich), deferred,
    )


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def entity_topic_score(article_a: dict, article_b: dict) -> float:
    """Weighted entity + topic Jaccard (0-1).

    Returns 0 when either side has no enrichment data.
    Entities weighted more heavily (0.65) because they are more discriminating.
    """
    entities_a = set(article_a.get("_entities", []))
    entities_b = set(article_b.get("_entities", []))
    topics_a = set(article_a.get("_topics", []))
    topics_b = set(article_b.get("_topics", []))

    if not (entities_a or topics_a) or not (entities_b or topics_b):
        return 0.0

    return 0.65 * _jaccard(entities_a, entities_b) + 0.35 * _jaccard(topics_a, topics_b)
