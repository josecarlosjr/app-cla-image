import os
import asyncio
import logging
from datetime import datetime, timezone
from xml.etree import ElementTree

import httpx

from database import upsert_articles, get_articles, prune_articles

DATA_DIR = os.getenv("DATA_DIR", "/data")
LOG_FILE = os.path.join(DATA_DIR, "agent.log")
MAX_CACHED = 3000

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

# ---------------------------------------------------------------------------
# Feed catalogue: 35+ feeds in 8 categories
# ---------------------------------------------------------------------------

FEEDS = {
    "TECNOLOGIA_IA": [
        ("ACM TechNews", "https://technews.acm.org/archives.cfm?fo=rss"),
        ("IEEE Spectrum", "https://spectrum.ieee.org/feeds/feed.rss"),
        ("TechCrunch", "https://techcrunch.com/feed/"),
        ("Ars Technica", "https://feeds.arstechnica.com/arstechnica/technology-lab"),
        ("Fast Company", "https://www.fastcompany.com/latest/rss"),
        ("The Next Web", "https://thenextweb.com/feed"),
        ("Olhar Digital", "https://olhardigital.com.br/feed/"),
        ("Hacker News", "https://hnrss.org/frontpage?count=30"),
        ("Reddit Technology", "https://www.reddit.com/r/technology/hot/.rss"),
    ],
    "CIBERSEGURANCA": [
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("Dark Reading", "https://www.darkreading.com/rss.xml"),
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
        ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/"),
        ("arXiv Cybersecurity", "https://rss.arxiv.org/rss/cs.CR"),
    ],
    "CIENCIA_ENERGIA": [
        ("Inovacao Tecnologica", "https://www.inovacaotecnologica.com.br/noticias/rss.xml"),
        ("Science Direct", "https://rss.sciencedirect.com/publication/science/25895346"),
        ("arXiv AI", "https://rss.arxiv.org/rss/cs.AI"),
    ],
    "GEOPOLITICA_FINANCAS": [
        ("BBC News World", "http://feeds.bbci.co.uk/news/world/rss.xml"),
        ("Reuters Technology", "https://feeds.reuters.com/reuters/technologyNews"),
        ("Reuters Business", "https://feeds.reuters.com/reuters/businessNews"),
        ("G1 Tecnologia", "https://g1.globo.com/rss/g1/tecnologia/"),
        ("G1 Mundo", "https://g1.globo.com/rss/g1/mundo/"),
    ],
    "DEFESA_ESPACO": [
        ("SpaceNews", "https://spacenews.com/feed/"),
        ("Telecompaper", "https://www.telecompaper.com/rss/headlines"),
    ],
    "DADOS": [
        ("FlowingData", "https://flowingdata.com/feed"),
    ],
    "DEVOPS_PLATFORM": [
        ("DZone DevOps", "https://feeds.dzone.com/devops"),
        ("DevOps.com", "https://devops.com/feed/"),
        ("The New Stack", "https://thenewstack.io/feed/"),
    ],
    "MERCADOS": [
        ("CNBC Investing", "https://www.cnbc.com/id/10000664/device/rss/rss.html"),
        ("MarketWatch", "https://feeds.marketwatch.com/marketwatch/topstories/"),
        ("Seeking Alpha", "https://seekingalpha.com/feed.xml"),
        ("Nasdaq", "https://www.nasdaq.com/feed/nasdaq-original/rss.xml"),
        ("Reddit Stocks", "https://www.reddit.com/r/stocks/hot/.rss"),
        ("Reddit Investing", "https://www.reddit.com/r/investing/hot/.rss"),
    ],
}

# ---------------------------------------------------------------------------
# Source quality weights (for trend_scorer)
# ---------------------------------------------------------------------------

SOURCE_WEIGHTS = {
    "Reuters Technology": 3, "Reuters Business": 3,
    "IEEE Spectrum": 3, "ACM TechNews": 3, "Science Direct": 3,
    "BBC News World": 2, "TechCrunch": 2,
    "Dark Reading": 2, "The Hacker News": 2,
    "SpaceNews": 2, "Ars Technica": 2,
    "G1 Tecnologia": 2, "G1 Mundo": 2,
    "DZone DevOps": 2, "DevOps.com": 2, "The New Stack": 2,
    "CNBC Investing": 3, "MarketWatch": 3, "Nasdaq": 3,
    "Seeking Alpha": 2, "Hacker News": 2,
    "Bleeping Computer": 2, "CISA Advisories": 3,
    "arXiv AI": 2, "arXiv Cybersecurity": 2,
}
DEFAULT_WEIGHT = 1


def get_source_weight(source: str) -> int:
    return SOURCE_WEIGHTS.get(source, DEFAULT_WEIGHT)


# ---------------------------------------------------------------------------
# RSS / Atom parsing with stdlib xml.etree.ElementTree
# ---------------------------------------------------------------------------

def _parse_feed_xml(xml_text: str, source: str, category: str) -> list[dict]:
    articles = []
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return articles

    # RSS 2.0: <rss><channel><item>
    for item in root.iter("item"):
        title = _text(item, "title")
        if not title:
            continue
        articles.append({
            "title": title,
            "summary": _strip_html(_text(item, "description")),
            "url": _text(item, "link"),
            "source": source,
            "category": category,
            "published": _text(item, "pubDate") or _text(item, "{http://purl.org/dc/elements/1.1/}date"),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        })

    # Atom: <feed><entry>
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
        title = _text(entry, "atom:title", ns) or _text(entry, "{http://www.w3.org/2005/Atom}title")
        if not title:
            continue
        link_el = entry.find("{http://www.w3.org/2005/Atom}link")
        link = link_el.get("href", "") if link_el is not None else ""
        summary_el = entry.find("{http://www.w3.org/2005/Atom}summary")
        if summary_el is None:
            summary_el = entry.find("{http://www.w3.org/2005/Atom}content")
        summary = _strip_html(summary_el.text or "") if summary_el is not None else ""
        pub_el = entry.find("{http://www.w3.org/2005/Atom}updated")
        published = pub_el.text if pub_el is not None else ""
        articles.append({
            "title": title,
            "summary": summary,
            "url": link,
            "source": source,
            "category": category,
            "published": published,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        })

    return articles


def _text(el, tag, ns=None):
    child = el.find(tag, ns) if ns else el.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""


def _strip_html(text: str) -> str:
    import re
    clean = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", clean).strip()


# ---------------------------------------------------------------------------
# FeedManager
# ---------------------------------------------------------------------------

class FeedManager:
    async def fetch_all(self) -> list[dict]:
        all_fetched: list[dict] = []

        headers = {"User-Agent": "PersonalAgent/1.0 (news-aggregator)"}
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True, headers=headers,
        ) as client:
            tasks = []
            for category, feeds in FEEDS.items():
                for source_name, url in feeds:
                    tasks.append(
                        self._fetch_one(client, source_name, url, category)
                    )
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error("Feed fetch error: %s", result)
                continue
            all_fetched.extend(result)

        new_articles = upsert_articles(all_fetched)
        prune_articles(MAX_CACHED)
        logger.info(
            "Feeds fetched: %d new articles, %d total.",
            len(new_articles), len(all_fetched),
        )
        return new_articles

    async def _fetch_one(
        self, client: httpx.AsyncClient, source: str, url: str, category: str
    ) -> list[dict]:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            return _parse_feed_xml(resp.text, source, category)[:15]
        except Exception as e:
            logger.warning("Failed to fetch %s (%s): %s", source, url, e)
            return []

    def get_by_category(self, category: str) -> list[dict]:
        return get_articles(category=category)

    def get_recent(self, hours: int = 24) -> list[dict]:
        return get_articles(hours=hours)

    def get_all_cached(self) -> list[dict]:
        return get_articles()


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

async def main():
    fm = FeedManager()
    articles = await fm.fetch_all()
    print(f"Fetched {len(articles)} new articles.")
    for cat in FEEDS:
        count = len(fm.get_by_category(cat))
        print(f"  {cat}: {count}")


if __name__ == "__main__":
    asyncio.run(main())
