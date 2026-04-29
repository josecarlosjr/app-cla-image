import os
import json
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from xml.etree import ElementTree

import httpx

from database import upsert_articles, get_articles, prune_articles
from temporal import record_article_stats

from log_config import setup_logging

setup_logging()

DATA_DIR = os.getenv("DATA_DIR", "/data")
MAX_CACHED = 8000
FEED_HEALTH_FILE = os.path.join(DATA_DIR, "feed_health.json")
MAX_CONSECUTIVE_FAILURES = 5
FEED_COOLDOWN_HOURS = 6

os.makedirs(DATA_DIR, exist_ok=True)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feed catalogue: 70+ feeds in 11 categories
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
        ("WIRED", "https://www.wired.com/feed/rss"),
        ("The Verge", "https://www.theverge.com/rss/index.xml"),
        ("MIT Technology Review", "https://www.technologyreview.com/feed/"),
        ("Tom's Hardware", "https://www.tomshardware.com/feeds/all"),
        ("Engadget", "https://www.engadget.com/rss.xml"),
        ("Gizmodo", "https://gizmodo.com/rss"),
        ("Berkeley AI Research", "https://bair.berkeley.edu/blog/feed.xml"),
        ("Google AI Blog", "https://blog.google/technology/ai/rss/"),
        ("Microsoft Research", "https://www.microsoft.com/en-us/research/feed/"),
    ],
    "CIBERSEGURANCA": [
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("Dark Reading", "https://www.darkreading.com/rss.xml"),
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
        ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/"),
        ("arXiv Cybersecurity", "https://rss.arxiv.org/rss/cs.CR"),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ("Schneier on Security", "https://www.schneier.com/blog/atom.xml"),
        ("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml"),
    ],
    "CIENCIA": [
        ("Inovacao Tecnologica", "https://www.inovacaotecnologica.com.br/noticias/rss.xml"),
        ("Science Direct", "https://rss.sciencedirect.com/publication/science/25895346"),
        ("arXiv AI", "https://rss.arxiv.org/rss/cs.AI"),
        ("Science Daily", "https://www.sciencedaily.com/rss/all.xml"),
        ("Chemical & Engineering News", "https://cen.acs.org/feeds/rss/topnews.xml"),
        ("Science Magazine", "https://www.science.org/rss/news_current.xml"),
    ],
    "ENERGIA": [
        ("CleanTechnica", "https://cleantechnica.com/feed/"),
        ("PV Tech", "https://www.pv-tech.org/feed/"),
        ("Utility Dive", "https://www.utilitydive.com/feeds/news/"),
        ("Nature Energy", "https://www.nature.com/nenergy.rss"),
        ("EnergyTrend", "https://www.energytrend.com/news/feed"),
        ("Guardian Energy", "https://www.theguardian.com/environment/energy/rss"),
        ("Oilprice", "https://oilprice.com/rss/main"),
    ],
    "MINERAIS_MINERACAO": [
        ("Mining Technology", "https://www.mining-technology.com/feed/"),
        ("The Northern Miner", "https://www.northernminer.com/feed/"),
        ("Mining.com", "https://www.mining.com/feed/"),
        ("Global Mining Review", "https://www.globalminingreview.com/rss"),
    ],
    "SUPPLY_CHAIN_LOGISTICA": [
        ("Supply Chain Dive", "https://www.supplychaindive.com/feeds/news/"),
        ("FreightWaves", "https://www.freightwaves.com/feed"),
        ("The Loadstar", "https://theloadstar.com/feed/"),
        ("Manufacturing Business Tech", "https://www.mbtmag.com/rss/all"),
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
        ("Defense One", "https://www.defenseone.com/rss/all/"),
        ("Breaking Defense", "https://breakingdefense.com/full-rss-feed/feed/"),
        ("DefenceTalk", "https://www.defencetalk.com/feed/"),
        ("The Aviationist", "https://theaviationist.com/feed/"),
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
        ("Yahoo Finance", "https://finance.yahoo.com/news/rssindex"),
        ("Motley Fool", "https://www.fool.com/feed/index.aspx"),
        ("Business Insider", "https://feeds.businessinsider.com/custom/all"),
        ("ETF Trends", "https://www.etftrends.com/feed/"),
        ("24/7 Wall St", "https://247wallst.com/feed/"),
        ("Abnormal Returns", "https://abnormalreturns.com/feed/"),
    ],
}

# ---------------------------------------------------------------------------
# Source quality weights (for trend_scorer)
# ---------------------------------------------------------------------------

SOURCE_WEIGHTS = {
    # Tier 3: peer-review, government advisories, established wire services
    "Reuters Technology": 3, "Reuters Business": 3,
    "IEEE Spectrum": 3, "ACM TechNews": 3, "Science Direct": 3,
    "CISA Advisories": 3, "CNBC Investing": 3, "MarketWatch": 3, "Nasdaq": 3,
    "MIT Technology Review": 3, "Nature Energy": 3, "Science Magazine": 3,
    "Science Daily": 3, "Chemical & Engineering News": 3,
    "Krebs on Security": 3, "Schneier on Security": 3,
    "Defense One": 3, "Breaking Defense": 3,
    "Berkeley AI Research": 3, "Google AI Blog": 3, "Microsoft Research": 3,
    # Tier 2: established trade publications and quality blogs
    "BBC News World": 2, "TechCrunch": 2,
    "Dark Reading": 2, "The Hacker News": 2, "Bleeping Computer": 2,
    "Malwarebytes Labs": 2,
    "SpaceNews": 2, "Ars Technica": 2,
    "G1 Tecnologia": 2, "G1 Mundo": 2,
    "DZone DevOps": 2, "DevOps.com": 2, "The New Stack": 2,
    "Seeking Alpha": 2, "Hacker News": 2,
    "arXiv AI": 2, "arXiv Cybersecurity": 2,
    "WIRED": 2, "The Verge": 2, "Engadget": 2, "Tom's Hardware": 2,
    "Gizmodo": 2,
    "CleanTechnica": 2, "PV Tech": 2, "Utility Dive": 2,
    "EnergyTrend": 2, "Guardian Energy": 2, "Oilprice": 2,
    "Mining Technology": 2, "The Northern Miner": 2, "Mining.com": 2,
    "Global Mining Review": 2,
    "Supply Chain Dive": 2, "FreightWaves": 2, "The Loadstar": 2,
    "Manufacturing Business Tech": 2,
    "DefenceTalk": 2, "The Aviationist": 2,
    "Yahoo Finance": 2, "Motley Fool": 2, "Business Insider": 2,
    "ETF Trends": 2, "24/7 Wall St": 2, "Abnormal Returns": 2,
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
    def __init__(self):
        self._health = self._load_health()

    def _load_health(self) -> dict:
        if os.path.exists(FEED_HEALTH_FILE):
            try:
                with open(FEED_HEALTH_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_health(self):
        with open(FEED_HEALTH_FILE, "w", encoding="utf-8") as f:
            json.dump(self._health, f, indent=2, ensure_ascii=False)

    def _is_feed_healthy(self, source: str) -> bool:
        entry = self._health.get(source)
        if not entry:
            return True
        if entry.get("consecutive_failures", 0) < MAX_CONSECUTIVE_FAILURES:
            return True
        skip_until = entry.get("skip_until", "")
        if skip_until and datetime.now(timezone.utc).isoformat() < skip_until:
            return False
        entry["consecutive_failures"] = 0
        return True

    def _record_success(self, source: str):
        self._health.pop(source, None)

    def _record_failure(self, source: str):
        entry = self._health.setdefault(source, {"consecutive_failures": 0})
        entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
        entry["last_failure"] = datetime.now(timezone.utc).isoformat()
        if entry["consecutive_failures"] >= MAX_CONSECUTIVE_FAILURES:
            entry["skip_until"] = (
                datetime.now(timezone.utc) + timedelta(hours=FEED_COOLDOWN_HOURS)
            ).isoformat()
            logger.warning(
                "Feed %s disabled for %dh after %d consecutive failures.",
                source, FEED_COOLDOWN_HOURS, entry["consecutive_failures"],
            )

    async def fetch_all(self) -> list[dict]:
        all_fetched: list[dict] = []
        skipped = 0

        headers = {"User-Agent": "PersonalAgent/1.0 (news-aggregator)"}
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True, headers=headers,
        ) as client:
            tasks = []
            for category, feeds in FEEDS.items():
                for source_name, url in feeds:
                    if not self._is_feed_healthy(source_name):
                        skipped += 1
                        continue
                    tasks.append(
                        self._fetch_one(client, source_name, url, category)
                    )
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error("Feed fetch error: %s", result)
                continue
            all_fetched.extend(result)

        self._save_health()

        new_articles = upsert_articles(all_fetched)
        record_article_stats(new_articles)
        prune_articles(MAX_CACHED)
        logger.info(
            "Feeds fetched: %d new articles, %d total fetched, %d feeds skipped (unhealthy).",
            len(new_articles), len(all_fetched), skipped,
        )
        return new_articles

    async def _fetch_one(
        self, client: httpx.AsyncClient, source: str, url: str, category: str
    ) -> list[dict]:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            articles = _parse_feed_xml(resp.text, source, category)[:15]
            self._record_success(source)
            return articles
        except Exception as e:
            logger.warning("Failed to fetch %s (%s): %s", source, url, e)
            self._record_failure(source)
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
