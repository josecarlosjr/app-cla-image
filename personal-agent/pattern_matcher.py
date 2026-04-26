import os
import json
import asyncio
import logging
from datetime import datetime, timezone

import httpx

from feeds import FeedManager
from llm import generate_text
from embeddings import embed_texts_cached, cosine_similarity
from enrichment import enrich_articles, entity_topic_score
from database import (
    insert_pattern, get_patterns, get_pattern_article_titles, prune_patterns,
)

DATA_DIR = os.getenv("DATA_DIR", "/data")
LOG_FILE = os.path.join(DATA_DIR, "agent.log")

os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_ALLOWED_USER_ID")

MAX_PATTERNS_STORED = 100
TFIDF_SIMILARITY_THRESHOLD = 0.3
SEMANTIC_SIMILARITY_THRESHOLD = 0.5
SEMANTIC_BOOSTED_THRESHOLD = 0.35
ENTITY_TOPIC_FLOOR = 0.3
MIN_SOURCES_FOR_STRONG = 2
ENRICH_MAX_NEW_PER_RUN = 50

CATEGORIES = [
    "chips_ia", "energia", "minerais", "geopolitica",
    "ciberseguranca", "ciencia", "espaco_defesa", "financas",
]

CATEGORY_KEYWORDS = {
    "chips_ia": [
        "semiconductor", "gpu", "nvidia", "tsmc", "llm", "agi",
        "ai chip", "intel", "amd", "chip", "foundry",
    ],
    "energia": [
        "nuclear", "solar", "wind", "grid", "battery", "datacenter",
        "energy", "power", "renewable", "smr",
    ],
    "minerais": [
        "rare earth", "copper", "lithium", "cobalt", "tin",
        "critical mineral", "mining",
    ],
    "geopolitica": [
        "us china", "strait of hormuz", "nato", "sanctions", "brics",
        "tariff", "trade war", "geopolit",
    ],
    "ciberseguranca": [
        "apt", "zero-day", "ransomware", "cyber", "hack",
        "vulnerability", "breach", "malware",
    ],
    "ciencia": [
        "quantum", "fusion", "superconductor", "material science",
        "physics", "research", "discovery",
    ],
    "espaco_defesa": [
        "satellite", "hypersonic", "aukus", "space", "missile",
        "defense", "orbit", "launch",
    ],
    "financas": [
        "stock", "ecb", "recession", "inflation", "crypto", "etf",
        "fed", "interest rate", "market", "ipo",
    ],
}


# ---------------------------------------------------------------------------
# Telegram sender
# ---------------------------------------------------------------------------

async def _send_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        for i in range(0, len(message), 4096):
            await client.post(
                url,
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": message[i : i + 4096],
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )


# ---------------------------------------------------------------------------
# Classify articles into categories
# ---------------------------------------------------------------------------

def _classify_article(article: dict) -> list[str]:
    text = f"{article.get('title', '')} {article.get('summary', '')}".lower()
    matched = []
    for cat, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            matched.append(cat)
    return matched if matched else ["other"]


# ---------------------------------------------------------------------------
# Semantic clustering (Voyage AI with TF-IDF fallback)
# ---------------------------------------------------------------------------

async def _cluster_articles(articles: list[dict]) -> list[list[dict]]:
    if len(articles) < 3:
        return []

    texts = [
        f"{a.get('title', '')} {a.get('summary', '')}" for a in articles
    ]
    urls = [a.get("url") for a in articles]

    embs, is_semantic = await embed_texts_cached(texts, urls)
    if embs.size == 0:
        return []

    sim_matrix = cosine_similarity(embs)

    if is_semantic:
        await enrich_articles(articles, max_new=ENRICH_MAX_NEW_PER_RUN)

    base_threshold = SEMANTIC_SIMILARITY_THRESHOLD if is_semantic else TFIDF_SIMILARITY_THRESHOLD

    def is_similar(i: int, j: int) -> bool:
        sem = float(sim_matrix[i][j])
        if sem >= base_threshold:
            return True
        if is_semantic and sem >= SEMANTIC_BOOSTED_THRESHOLD:
            return entity_topic_score(articles[i], articles[j]) >= ENTITY_TOPIC_FLOOR
        return False

    n = len(articles)
    assigned = [False] * n
    clusters: list[list[int]] = []

    for i in range(n):
        if assigned[i]:
            continue
        cluster = [i]
        assigned[i] = True
        for j in range(i + 1, n):
            if not assigned[j] and is_similar(i, j):
                cluster.append(j)
                assigned[j] = True
        if len(cluster) >= 2:
            clusters.append(cluster)

    return [[articles[i] for i in idx_list] for idx_list in clusters]


def _is_strong_pattern(cluster: list[dict]) -> bool:
    sources = {a.get("source", "") for a in cluster}
    return len(sources) >= MIN_SOURCES_FOR_STRONG


# ---------------------------------------------------------------------------
# Claude analysis for strong patterns
# ---------------------------------------------------------------------------

async def _analyze_pattern(cluster: list[dict], categories: list[str]) -> dict | None:
    titles_block = "\n".join(
        f"- [{a.get('source', '?')}] {a.get('title', '')}" for a in cluster
    )
    sources = list({a.get("source", "") for a in cluster})

    prompt = (
        f"Encontrei {len(cluster)} noticias de fontes independentes sobre o mesmo tema:\n"
        f"{titles_block}\n\n"
        f"Categorias detectadas: {', '.join(categories)}\n"
        f"Fontes: {', '.join(sources)}\n\n"
        "Analisa em portugues de Portugal com esta estrutura EXACTA:\n\n"
        "*PADRAO:* O que estas noticias em conjunto revelam (2 frases)\n\n"
        "*CAUSA RAIZ:* O que esta realmente a acontecer por detras (2 frases)\n\n"
        "*CADEIA DE IMPACTO:* A -> B -> C (como isto se propaga)\n\n"
        "*LIGACAO AO MAPA:* Qual categoria do mapa de dependencias e afectada\n\n"
        "*IMPACTO FINANCEIRO:* Oportunidades concretas "
        "(COMPRAR/VENDER/CAUTELA com activo especifico)\n\n"
        "*CONFIANCA:* ALTA/MEDIA/BAIXA baseado no numero e qualidade das fontes\n\n"
        "Se conciso. Maximo 200 palavras."
    )

    text = await generate_text(prompt=prompt, max_tokens=1024)
    if not text:
        return None

    confidence = "MEDIA"
    upper = text.upper()
    if "CONFIANCA:" in upper or "CONFIANÇA:" in upper:
        tail = upper.split("CONFIAN", 1)[1]
        if "ALTA" in tail[:50]:
            confidence = "ALTA"
        elif "BAIXA" in tail[:50]:
            confidence = "BAIXA"

    return {
        "articles": [
            {"title": a.get("title", ""), "source": a.get("source", ""), "url": a.get("url", "")}
            for a in cluster
        ],
        "categories": categories,
        "sources": sources,
        "num_sources": len(sources),
        "analysis": text,
        "confidence": confidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Public function for tools.py
# ---------------------------------------------------------------------------

async def search_patterns(topic: str = "") -> str:
    patterns = get_patterns()
    if not patterns:
        return "Nenhum padrao identificado ainda."

    if topic:
        topic_lower = topic.lower()
        patterns = [
            p for p in patterns
            if topic_lower in json.dumps(p, ensure_ascii=False).lower()
        ]

    if not patterns:
        return f"Nenhum padrao encontrado para '{topic}'."

    lines = []
    for p in patterns[:5]:
        conf = p.get("confidence", "?")
        cats = ", ".join(p.get("categories", []))
        n = p.get("num_sources", 0)
        lines.append(
            f"*[{conf}]* {cats} ({n} fontes)\n"
            f"{p.get('analysis', '')[:300]}\n"
        )
    return "\n---\n".join(lines)


# ---------------------------------------------------------------------------
# On-demand detection (called from API, no Telegram alerts)
# ---------------------------------------------------------------------------

async def detect_patterns_on_demand() -> dict:
    fm = FeedManager()
    articles = fm.get_all_cached()

    if len(articles) < 5:
        return {"new_patterns": 0, "clusters": 0, "articles": len(articles),
                "message": f"Poucos artigos ({len(articles)}). Clica 'Actualizar feeds' primeiro."}

    for article in articles:
        article["_categories"] = _classify_article(article)

    clusters = await _cluster_articles(articles)
    strong = [c for c in clusters if _is_strong_pattern(c)]

    existing_titles = get_pattern_article_titles()

    new_count = 0
    for cluster in strong[:5]:
        cluster_titles = {a.get("title", "") for a in cluster}
        if cluster_titles & existing_titles:
            continue

        all_cats: set[str] = set()
        for a in cluster:
            all_cats.update(a.get("_categories", []))
        all_cats.discard("other")
        categories = sorted(all_cats) if all_cats else ["general"]

        pattern = await _analyze_pattern(cluster, categories)
        if not pattern:
            continue

        insert_pattern(pattern)
        new_count += 1

    prune_patterns(MAX_PATTERNS_STORED)
    total = len(get_patterns())
    return {
        "new_patterns": new_count,
        "total_patterns": total,
        "clusters": len(clusters),
        "strong_clusters": len(strong),
        "articles": len(articles),
    }


# ---------------------------------------------------------------------------
# Main CronJob entry point
# ---------------------------------------------------------------------------

async def main():
    logger.info("Pattern matcher starting...")

    fm = FeedManager()
    await fm.fetch_all()
    articles = fm.get_recent(hours=48)

    if len(articles) < 5:
        logger.info("Not enough articles (%d) for pattern matching.", len(articles))
        return

    for article in articles:
        article["_categories"] = _classify_article(article)

    logger.info("Clustering %d articles...", len(articles))
    clusters = await _cluster_articles(articles)
    logger.info("Found %d clusters.", len(clusters))

    strong = [c for c in clusters if _is_strong_pattern(c)]
    logger.info("Strong patterns (2+ sources): %d", len(strong))

    new_count = 0

    for cluster in strong[:5]:
        all_cats: set[str] = set()
        for a in cluster:
            all_cats.update(a.get("_categories", []))
        all_cats.discard("other")
        categories = sorted(all_cats) if all_cats else ["general"]

        pattern = await _analyze_pattern(cluster, categories)
        if not pattern:
            continue

        insert_pattern(pattern)
        new_count += 1

        if pattern["confidence"] == "ALTA":
            cats_str = ", ".join(pattern["categories"])
            message = (
                f"*PADRAO DETECTADO [{pattern['confidence']}]*\n"
                f"Categorias: {cats_str}\n"
                f"Fontes: {pattern['num_sources']}\n\n"
                f"{pattern['analysis']}"
            )
            await _send_telegram(message)
            logger.info("High-confidence pattern alert sent.")

    prune_patterns(MAX_PATTERNS_STORED)
    logger.info("Pattern matcher done. %d new patterns.", new_count)


if __name__ == "__main__":
    asyncio.run(main())
