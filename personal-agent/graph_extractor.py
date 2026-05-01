"""Dynamic knowledge graph extractor — Haiku-powered triple extraction.

Reads enriched articles and extracts (subject, predicate, object) triples
to build a dynamic knowledge graph. New entities and relationships start
as 'staged' and require human review before entering the active graph.

Cost: ~$1.20/month at 20 articles/run, 2 runs/day.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from llm import generate_json, MODEL_HAIKU
from database import (
    get_articles,
    get_enrichments_batch,
    upsert_graph_entity,
    upsert_graph_relationship,
    get_entity_id_by_canonical,
    get_graph_stats,
)
from pillars import CATEGORY_TO_PILLAR

logger = logging.getLogger(__name__)

EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Entity name as mentioned (e.g. 'TSMC', 'China').",
                    },
                    "canonical": {
                        "type": "string",
                        "description": (
                            "Lowercase canonical form for dedup (e.g. 'tsmc', 'china'). "
                            "Use underscore for multi-word: 'rare_earth', 'sam_altman'."
                        ),
                    },
                    "type": {
                        "type": "string",
                        "enum": [
                            "company", "country", "person", "technology",
                            "mineral", "product", "organization", "event",
                        ],
                    },
                },
                "required": ["name", "canonical", "type"],
            },
            "description": "3-6 key entities from the article. Skip generic terms.",
        },
        "relationships": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "subject": {
                        "type": "string",
                        "description": "Canonical form of subject entity.",
                    },
                    "predicate": {
                        "type": "string",
                        "enum": [
                            "produces", "supplies", "depends_on", "competes_with",
                            "regulates", "invests_in", "acquires", "partners_with",
                            "restricts", "exports", "imports", "develops",
                            "disrupts", "sanctions",
                        ],
                    },
                    "object": {
                        "type": "string",
                        "description": "Canonical form of object entity.",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "0.0-1.0 confidence that this relationship is stated.",
                    },
                },
                "required": ["subject", "predicate", "object", "confidence"],
            },
            "description": (
                "1-4 relationships clearly stated in the article. "
                "Only extract if the relationship is explicit, not inferred."
            ),
        },
    },
    "required": ["entities", "relationships"],
    "additionalProperties": False,
}

EXTRACTION_SYSTEM = (
    "You extract structured knowledge graph triples from news articles. "
    "Focus on geopolitical, technological, and supply chain relationships. "
    "Only extract entities and relationships CLEARLY STATED in the text. "
    "Use canonical lowercase forms for entity names (underscore for spaces). "
    "Be precise and conservative — fewer high-quality triples beat many noisy ones."
)

_PROCESSED_URLS_KEY = "_graph_extracted_urls"


async def _extract_triples(article: dict) -> dict | None:
    title = article.get("title", "")
    summary = article.get("summary", "")
    entities = article.get("_entities", [])
    topics = article.get("_topics", [])

    if not title:
        return None

    context_parts = [f"Title: {title}"]
    if summary:
        context_parts.append(f"Summary: {summary[:800]}")
    if entities:
        context_parts.append(f"Known entities: {', '.join(entities[:8])}")
    if topics:
        context_parts.append(f"Topics: {', '.join(topics[:5])}")
    context_parts.append(
        "Extract key entities and relationships from this article."
    )

    return await generate_json(
        prompt="\n\n".join(context_parts),
        schema=EXTRACTION_SCHEMA,
        system=EXTRACTION_SYSTEM,
        model=MODEL_HAIKU,
        max_tokens=1024,
    )


def _persist_extraction(
    result: dict, article: dict,
) -> tuple[int, int]:
    url = article.get("url", "")
    category = article.get("category", "")
    pillar = CATEGORY_TO_PILLAR.get(category, "")

    entity_map: dict[str, int] = {}
    entities_added = 0
    rels_added = 0

    for ent in result.get("entities", []):
        canonical = ent.get("canonical", "").strip().lower()
        if not canonical or len(canonical) < 2:
            continue
        eid = upsert_graph_entity(
            name=ent.get("name", canonical),
            canonical=canonical,
            entity_type=ent.get("type", "technology"),
            pillar=pillar,
            source_url=url,
        )
        entity_map[canonical] = eid
        entities_added += 1

    for rel in result.get("relationships", []):
        subj = rel.get("subject", "").strip().lower()
        obj = rel.get("object", "").strip().lower()
        pred = rel.get("predicate", "")
        conf = rel.get("confidence", 0.5)

        if not subj or not obj or not pred:
            continue
        if conf < 0.3:
            continue

        subj_id = entity_map.get(subj) or get_entity_id_by_canonical(subj)
        obj_id = entity_map.get(obj) or get_entity_id_by_canonical(obj)

        if not subj_id:
            subj_id = upsert_graph_entity(
                name=subj, canonical=subj,
                entity_type="technology", pillar=pillar, source_url=url,
            )
            entity_map[subj] = subj_id
        if not obj_id:
            obj_id = upsert_graph_entity(
                name=obj, canonical=obj,
                entity_type="technology", pillar=pillar, source_url=url,
            )
            entity_map[obj] = obj_id

        upsert_graph_relationship(
            subject_id=subj_id,
            predicate=pred,
            object_id=obj_id,
            confidence=conf,
            source_url=url,
        )
        rels_added += 1

    return entities_added, rels_added


async def extract_graph_triples(
    max_articles: int = 20,
    hours: int = 48,
    concurrency: int = 5,
) -> dict:
    articles = get_articles(hours=hours, scored_only=True, limit=200)
    if not articles:
        articles = get_articles(hours=hours, limit=100)

    urls = [a["url"] for a in articles if a.get("url")]
    enrichments = get_enrichments_batch(urls)

    for a in articles:
        url = a.get("url", "")
        if url in enrichments:
            a["_entities"] = enrichments[url].get("entities", [])
            a["_topics"] = enrichments[url].get("topics", [])

    existing_entities = {
        e["canonical"]
        for e in get_graph_entities_for_dedup()
    }

    candidates = []
    for a in articles:
        ents = set(a.get("_entities", []))
        if ents and not ents.issubset(existing_entities):
            candidates.append(a)
    if not candidates:
        candidates = articles

    to_process = candidates[:max_articles]
    if not to_process:
        return {"extracted": 0, "entities": 0, "relationships": 0}

    sem = asyncio.Semaphore(concurrency)
    total_entities = 0
    total_rels = 0
    extracted = 0

    async def _worker(article: dict):
        nonlocal total_entities, total_rels, extracted
        async with sem:
            result = await _extract_triples(article)
            if result:
                e, r = _persist_extraction(result, article)
                total_entities += e
                total_rels += r
                extracted += 1

    await asyncio.gather(*[_worker(a) for a in to_process])

    stats = get_graph_stats()
    logger.info(
        "Graph extraction: %d articles → %d entities, %d relationships. "
        "Staged: %d entities, %d rels",
        extracted, total_entities, total_rels,
        stats["entities"].get("staged", 0),
        stats["relationships"].get("staged", 0),
    )

    return {
        "extracted": extracted,
        "entities": total_entities,
        "relationships": total_rels,
        "stats": stats,
    }


def get_graph_entities_for_dedup() -> list[dict]:
    from database import get_graph_entities
    return get_graph_entities(limit=5000)
