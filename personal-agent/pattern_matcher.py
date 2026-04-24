import os
import json
import asyncio
import logging
from datetime import datetime, timezone

import httpx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from feeds import FeedManager
from llm import generate_text

DATA_DIR = os.getenv("DATA_DIR", "/data")
PATTERNS_FILE = os.path.join(DATA_DIR, "patterns.json")
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
SIMILARITY_THRESHOLD = 0.3
MIN_SOURCES_FOR_STRONG = 2

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
# Persistence
# ---------------------------------------------------------------------------

def _load_patterns() -> list[dict]:
    if os.path.exists(PATTERNS_FILE):
        with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def _save_patterns(patterns: list[dict]):
    with open(PATTERNS_FILE, "w", encoding="utf-8") as f:
        json.dump(patterns[-MAX_PATTERNS_STORED:], f, indent=2, ensure_ascii=False)


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
# TF-IDF clustering
# ---------------------------------------------------------------------------

def _cluster_articles(articles: list[dict]) -> list[list[dict]]:
    if len(articles) < 3:
        return []

    texts = [
        f"{a.get('title', '')} {a.get('summary', '')}" for a in articles
    ]

    try:
        vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            min_df=1,
            max_df=0.95,
        )
        tfidf = vectorizer.fit_transform(texts)
        sim_matrix = cosine_similarity(tfidf)
    except ValueError:
        return []

    n = len(articles)
    assigned = [False] * n
    clusters: list[list[int]] = []

    for i in range(n):
        if assigned[i]:
            continue
        cluster = [i]
        assigned[i] = True
        for j in range(i + 1, n):
            if not assigned[j] and sim_matrix[i][j] >= SIMILARITY_THRESHOLD:
                cluster.append(j)
                assigned[j] = True
        if len(cluster) >= 2:
            clusters.append(cluster)

    article_clusters = []
    for idx_list in clusters:
        article_clusters.append([articles[i] for i in idx_list])

    return article_clusters


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
    patterns = _load_patterns()
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
    for p in patterns[-5:]:
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

    clusters = _cluster_articles(articles)
    strong = [c for c in clusters if _is_strong_pattern(c)]

    patterns = _load_patterns()
    existing_titles = {
        a.get("title", "")
        for p in patterns
        for a in p.get("articles", [])
    }

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

        patterns.append(pattern)
        new_count += 1

    _save_patterns(patterns)
    return {
        "new_patterns": new_count,
        "total_patterns": len(patterns),
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
    clusters = _cluster_articles(articles)
    logger.info("Found %d clusters.", len(clusters))

    strong = [c for c in clusters if _is_strong_pattern(c)]
    logger.info("Strong patterns (2+ sources): %d", len(strong))

    patterns = _load_patterns()
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

        patterns.append(pattern)
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

    _save_patterns(patterns)
    logger.info("Pattern matcher done. %d new patterns.", new_count)


if __name__ == "__main__":
    asyncio.run(main())
