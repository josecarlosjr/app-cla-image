import os
import json
import asyncio
import logging
from datetime import datetime

import httpx
import feedparser
from duckduckgo_search import DDGS

from llm import generate_text

DATA_DIR = os.getenv("DATA_DIR", "/data")
ANALYZED_FILE = os.path.join(DATA_DIR, "analyzed_news.json")
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

MAX_ALERTS_PER_RUN = 3

# ---------------------------------------------------------------------------
# Categories & keywords
# ---------------------------------------------------------------------------

CATEGORIES = {
    "chips_ia": {
        "name": "Chips & IA",
        "keywords": [
            "NVIDIA", "TSMC", "semiconductor", "AI chip",
            "GPU shortage", "chip export ban", "Intel foundry",
            "AMD AI", "chip manufacturing", "EUV lithography",
        ],
    },
    "minerais_criticos": {
        "name": "Minerais Criticos",
        "keywords": [
            "lithium price", "rare earth", "cobalt mining",
            "critical minerals", "battery metals",
            "mining Africa", "mineral supply chain",
        ],
    },
    "energia_ia": {
        "name": "Energia & IA",
        "keywords": [
            "data center energy", "AI power consumption",
            "nuclear energy AI", "energy grid AI",
            "renewable energy tech", "SMR nuclear",
            "power demand AI",
        ],
    },
    "geopolitica_tech": {
        "name": "Geopolitica Tech",
        "keywords": [
            "US China tech war", "EU digital sovereignty",
            "tech sanctions", "BRICS technology",
            "digital regulation EU", "tech decoupling",
            "cyber warfare",
        ],
    },
    "petroleo_tech": {
        "name": "Petroleo & Tech",
        "keywords": [
            "oil price OPEC", "energy transition",
            "peak oil demand", "oil technology",
            "refinery capacity", "crude oil forecast",
            "natural gas Europe",
        ],
    },
    "investimento_tech": {
        "name": "Investimento & Tech",
        "keywords": [
            "tech IPO", "venture capital AI",
            "tech stocks", "crypto regulation",
            "fintech Europe", "digital euro",
            "tech valuation",
        ],
    },
}

RSS_FEEDS = [
    "https://feeds.reuters.com/reuters/technologyNews",
    "https://feeds.reuters.com/reuters/businessNews",
    "https://feeds.bbci.co.uk/news/technology/rss.xml",
    "https://feeds.arstechnica.com/arstechnica/technology-lab",
]

# ---------------------------------------------------------------------------
# Analyzed-articles persistence
# ---------------------------------------------------------------------------

def _load_analyzed() -> dict:
    if os.path.exists(ANALYZED_FILE):
        with open(ANALYZED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"analyzed_urls": [], "last_run": None}


def _save_analyzed(data: dict):
    with open(ANALYZED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _is_analyzed(data: dict, url: str) -> bool:
    return url in data.get("analyzed_urls", [])


def _mark_analyzed(data: dict, url: str):
    data.setdefault("analyzed_urls", []).append(url)
    if len(data["analyzed_urls"]) > 500:
        data["analyzed_urls"] = data["analyzed_urls"][-300:]


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
# Article collection
# ---------------------------------------------------------------------------

async def _fetch_rss() -> list[dict]:
    articles: list[dict] = []
    async with httpx.AsyncClient() as client:
        for feed_url in RSS_FEEDS:
            try:
                resp = await client.get(feed_url, timeout=15)
                feed = feedparser.parse(resp.text)
                for entry in feed.entries[:10]:
                    articles.append({
                        "title": entry.get("title", ""),
                        "summary": entry.get("summary", ""),
                        "url": entry.get("link", ""),
                        "source": feed.feed.get("title", feed_url),
                        "published": entry.get("published", ""),
                    })
            except Exception as e:
                logger.error("Error fetching RSS %s: %s", feed_url, e)
    return articles


async def _search_by_category(cat_key: str, cfg: dict) -> list[dict]:
    articles: list[dict] = []
    try:
        with DDGS() as ddgs:
            for kw in cfg["keywords"][:3]:
                results = list(ddgs.news(kw, max_results=3))
                for r in results:
                    articles.append({
                        "title": r.get("title", ""),
                        "summary": r.get("body", ""),
                        "url": r.get("url", ""),
                        "source": r.get("source", "DuckDuckGo"),
                        "published": r.get("date", ""),
                        "category": cat_key,
                    })
    except Exception as e:
        logger.error("Error searching %s: %s", cat_key, e)
    return articles


# ---------------------------------------------------------------------------
# Scoring & analysis
# ---------------------------------------------------------------------------

def _score_article(article: dict, cat_cfg: dict) -> int:
    text = f"{article['title']} {article['summary']}".lower()
    return sum(1 for kw in cat_cfg["keywords"] if kw.lower() in text)


async def _analyze_article(article: dict, category_name: str) -> str | None:
    prompt = (
        f'Analisa esta noticia da categoria "{category_name}".\n'
        f"Titulo: {article['title']}\n"
        f"Resumo: {article['summary']}\n"
        f"Fonte: {article['source']}\n\n"
        "Responde em portugues de Portugal com esta estrutura EXACTA:\n\n"
        "*O que aconteceu:* [1-2 frases]\n\n"
        "*Porque:* [contexto e causas]\n\n"
        "*Quem ganha:* [beneficiarios]\n\n"
        "*Quem perde:* [prejudicados]\n\n"
        "*Impacto PT/Europa:* [impacto especifico para Portugal e Europa]\n\n"
        "*Oportunidade investimento:* [se aplicavel]\n\n"
        "*Ligacao ao mapa geopolitico:* [como se encaixa no contexto global]\n\n"
        "Se conciso e directo. Maximo 200 palavras total."
    )

    text = await generate_text(prompt=prompt, max_tokens=1024)
    return text or None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    logger.info("News analyzer starting...")
    analyzed_data = _load_analyzed()

    all_articles = await _fetch_rss()
    for cat_key, cat_cfg in CATEGORIES.items():
        cat_articles = await _search_by_category(cat_key, cat_cfg)
        for a in cat_articles:
            a.setdefault("category", cat_key)
        all_articles.extend(cat_articles)

    scored: list[dict] = []
    for article in all_articles:
        url = article.get("url", "")
        if not url or _is_analyzed(analyzed_data, url):
            continue

        best_score = 0
        best_cat = None
        for cat_key, cat_cfg in CATEGORIES.items():
            score = _score_article(article, cat_cfg)
            if score > best_score:
                best_score = score
                best_cat = cat_key

        if best_score >= 2:
            article["score"] = best_score
            article["matched_category"] = best_cat
            scored.append(article)

    scored.sort(key=lambda x: x["score"], reverse=True)

    alerts_sent = 0
    for article in scored[:MAX_ALERTS_PER_RUN]:
        cat_name = CATEGORIES[article["matched_category"]]["name"]
        analysis = await _analyze_article(article, cat_name)

        if analysis:
            message = (
                f"*{cat_name}*\n\n"
                f"*{article['title']}*\n"
                f"{article['url']}\n\n"
                f"{analysis}"
            )
            await _send_telegram(message)
            _mark_analyzed(analyzed_data, article["url"])
            alerts_sent += 1
            logger.info("News alert sent: %s...", article["title"][:50])

    analyzed_data["last_run"] = datetime.now().isoformat()
    _save_analyzed(analyzed_data)
    logger.info(
        "News analyzer done. %d alerts sent from %d articles scanned.",
        alerts_sent,
        len(all_articles),
    )


if __name__ == "__main__":
    asyncio.run(main())
