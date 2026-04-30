"""Supply chain mention extractor — keyword NER + optional Haiku sentiment.

Scans articles for supply chain node keywords and records mentions
in the database. Runs as part of the pattern analysis CronJob.

Two-stage pipeline:
  1. Fast keyword scan (zero cost) — matches article text against node keywords
  2. Batch Haiku sentiment classification (optional, ~$0.001/article) — only for
     articles that match ≥1 node, classifies sentiment per node mention

Stage 2 is capped at MAX_SENTIMENT_PER_RUN to control cost.
"""

import asyncio
import logging
import re
from datetime import datetime, timezone

from database import (
    get_supply_chain_nodes,
    get_supply_chain_mentions,
    upsert_supply_chain_mentions_batch,
    prune_supply_chain_mentions,
    get_articles,
)
from supply_chain import ensure_seeded
from llm import generate_json, MODEL_HAIKU

logger = logging.getLogger(__name__)

MAX_SENTIMENT_PER_RUN = 40
LOOKBACK_HOURS = 48


def _build_keyword_index(nodes: list[dict]) -> list[tuple[str, list[re.Pattern]]]:
    index = []
    for node in nodes:
        patterns = []
        for kw in node.get("keywords", []):
            pat = re.compile(r'\b' + re.escape(kw.lower()) + r'\b')
            patterns.append(pat)
        index.append((node["id"], patterns))
    return index


def _scan_article(text_lower: str, keyword_index: list[tuple[str, list[re.Pattern]]]) -> list[str]:
    matched = []
    for node_id, patterns in keyword_index:
        for pat in patterns:
            if pat.search(text_lower):
                matched.append(node_id)
                break
    return matched


SENTIMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "mentions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "node_id": {"type": "string"},
                    "sentiment": {
                        "type": "string",
                        "enum": ["shortage", "surplus", "price_up", "price_down",
                                 "disruption", "expansion", "neutral"],
                    },
                },
                "required": ["node_id", "sentiment"],
            },
        },
    },
    "required": ["mentions"],
}

SENTIMENT_SYSTEM = (
    "You classify supply chain signals from news articles. "
    "For each mentioned mineral or component, determine the sentiment:\n"
    "- shortage: supply constraints, export bans, mine closures\n"
    "- surplus: oversupply, stockpile growth, demand drop\n"
    "- price_up: price increases, cost pressure\n"
    "- price_down: price drops, deflation\n"
    "- disruption: logistics problems, geopolitical risk, sanctions\n"
    "- expansion: new mines, new fabs, capacity growth, investment\n"
    "- neutral: mentioned but no clear signal\n"
    "Be precise. Only classify what is clearly stated."
)


async def _classify_sentiment(
    article: dict, node_ids: list[str], node_names: dict[str, str],
) -> list[dict]:
    title = article.get("title", "")
    summary = article.get("summary", "")[:600]
    nodes_desc = ", ".join(f"{nid} ({node_names.get(nid, nid)})" for nid in node_ids)

    prompt = (
        f"Article:\nTitle: {title}\nSummary: {summary}\n\n"
        f"Detected supply chain nodes: {nodes_desc}\n\n"
        f"Classify the sentiment for each node."
    )

    result = await generate_json(
        prompt=prompt,
        schema=SENTIMENT_SCHEMA,
        system=SENTIMENT_SYSTEM,
        model=MODEL_HAIKU,
        max_tokens=512,
        tool_name="classify_supply_chain",
        tool_description="Classify supply chain sentiment per node.",
    )

    if not result:
        return [{"node_id": nid, "sentiment": "neutral"} for nid in node_ids]

    classified = {m["node_id"]: m["sentiment"] for m in result.get("mentions", [])}
    return [
        {"node_id": nid, "sentiment": classified.get(nid, "neutral")}
        for nid in node_ids
    ]


async def extract_mentions(hours: int = LOOKBACK_HOURS) -> dict:
    ensure_seeded()

    nodes = get_supply_chain_nodes()
    if not nodes:
        return {"scanned": 0, "matches": 0, "mentions": 0}

    node_names = {n["id"]: n["name"] for n in nodes}
    keyword_index = _build_keyword_index(nodes)

    articles = get_articles(hours=hours)
    if not articles:
        return {"scanned": 0, "matches": 0, "mentions": 0}

    existing = get_supply_chain_mentions(hours=hours)
    existing_keys = {(m["node_id"], m["article_url"]) for m in existing}

    matches: list[tuple[dict, list[str]]] = []
    for article in articles:
        url = article.get("url", "")
        if not url:
            continue
        text = f"{article.get('title', '')} {article.get('summary', '')}".lower()
        node_ids = _scan_article(text, keyword_index)
        if not node_ids:
            continue
        new_nodes = [nid for nid in node_ids if (nid, url) not in existing_keys]
        if new_nodes:
            matches.append((article, new_nodes))

    all_mentions: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    needs_sentiment = matches[:MAX_SENTIMENT_PER_RUN]
    keyword_only = matches[MAX_SENTIMENT_PER_RUN:]

    if needs_sentiment:
        sem = asyncio.Semaphore(5)

        async def _worker(article: dict, node_ids: list[str]):
            async with sem:
                return await _classify_sentiment(article, node_ids, node_names)

        tasks = [_worker(a, nids) for a, nids in needs_sentiment]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (article, _), result in zip(needs_sentiment, results):
            if isinstance(result, Exception):
                logger.warning("Sentiment classification error: %s", result)
                continue
            for m in result:
                all_mentions.append({
                    "node_id": m["node_id"],
                    "article_url": article["url"],
                    "sentiment": m["sentiment"],
                    "timestamp": article.get("fetched_at", now),
                })

    for article, node_ids in keyword_only:
        for nid in node_ids:
            all_mentions.append({
                "node_id": nid,
                "article_url": article["url"],
                "sentiment": "neutral",
                "timestamp": article.get("fetched_at", now),
            })

    upsert_supply_chain_mentions_batch(all_mentions)
    prune_supply_chain_mentions(days=30)

    logger.info(
        "Supply chain extraction: %d articles scanned, %d matched, "
        "%d mentions recorded (%d with sentiment).",
        len(articles), len(matches), len(all_mentions), len(needs_sentiment),
    )

    return {
        "scanned": len(articles),
        "matches": len(matches),
        "mentions": len(all_mentions),
        "with_sentiment": len(needs_sentiment),
        "deferred": len(keyword_only),
    }


async def main():
    from log_config import setup_logging
    setup_logging()
    result = await extract_mentions()
    print(f"Supply chain extraction: {result}")


if __name__ == "__main__":
    asyncio.run(main())
