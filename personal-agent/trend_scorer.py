import os
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from feeds import FeedManager, get_source_weight
from relevance_filter import score_articles, save_scored
from database import (
    get_trend_scores_data, save_trend_scores,
    get_patterns as db_get_patterns,
)

from log_config import setup_logging

setup_logging()

DATA_DIR = os.getenv("DATA_DIR", "/data")

os.makedirs(DATA_DIR, exist_ok=True)

logger = logging.getLogger(__name__)

# Normalisation factor: ~20 weighted articles = score 70
NORM_FACTOR = 3.5
TREND_THRESHOLD = 10

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
# Classify an article into categories
# ---------------------------------------------------------------------------

def _classify(article: dict) -> list[str]:
    text = f"{article.get('title', '')} {article.get('summary', '')}".lower()
    matched = []
    for cat, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            matched.append(cat)
    return matched


# ---------------------------------------------------------------------------
# Load previous scores for trend comparison
# ---------------------------------------------------------------------------

def _load_previous_scores() -> dict:
    return get_trend_scores_data() or {}


# ---------------------------------------------------------------------------
# Calculate scores
# ---------------------------------------------------------------------------

def calculate_scores(articles: list[dict]) -> dict:
    cutoff_7d = datetime.now(timezone.utc) - timedelta(days=7)
    recent = []
    for a in articles:
        try:
            fetched = datetime.fromisoformat(a.get("fetched_at", ""))
            if fetched >= cutoff_7d:
                recent.append(a)
        except (ValueError, KeyError):
            recent.append(a)

    cat_scores: dict[str, dict] = {}
    for cat in CATEGORY_KEYWORDS:
        cat_scores[cat] = {"raw": 0, "articles": 0}

    for article in recent:
        categories = _classify(article)
        weight = get_source_weight(article.get("source", ""))
        for cat in categories:
            if cat in cat_scores:
                cat_scores[cat]["raw"] += weight
                cat_scores[cat]["articles"] += 1

    previous = _load_previous_scores()

    scores = {}
    for cat, data in cat_scores.items():
        score = min(100, int(data["raw"] * NORM_FACTOR))
        prev_score = previous.get(cat, {}).get("score", score)
        diff = score - prev_score

        if diff > TREND_THRESHOLD:
            trend = "rising"
        elif diff < -TREND_THRESHOLD:
            trend = "falling"
        else:
            trend = "stable"

        scores[cat] = {
            "score": score,
            "articles": data["articles"],
            "trend": trend,
        }

    return scores


# ---------------------------------------------------------------------------
# Calculate connections from patterns
# ---------------------------------------------------------------------------

def calculate_connections(patterns: list[dict]) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    connections: dict[tuple[str, str], dict] = {}

    for p in patterns:
        try:
            ts = datetime.fromisoformat(p.get("timestamp", ""))
            if ts < cutoff:
                continue
        except (ValueError, KeyError):
            pass

        cats = sorted(p.get("categories", []))
        confidence_score = {"ALTA": 90, "MEDIA": 60, "BAIXA": 30}.get(
            p.get("confidence", "MEDIA"), 60
        )

        for i, c1 in enumerate(cats):
            for c2 in cats[i + 1:]:
                key = (c1, c2)
                if key not in connections or connections[key]["score"] < confidence_score:
                    pattern_summary = p.get("analysis", "")[:100]
                    connections[key] = {
                        "from": c1,
                        "to": c2,
                        "score": confidence_score,
                        "pattern": pattern_summary,
                    }

    return list(connections.values())


# ---------------------------------------------------------------------------
# Public function for tools.py
# ---------------------------------------------------------------------------

def get_trend_scores() -> str:
    data = get_trend_scores_data()
    if data:
        lines = ["*Trend Scores (0-100):*\n"]
        for cat in CATEGORY_KEYWORDS:
            info = data.get(cat, {})
            score = info.get("score", 0)
            trend = info.get("trend", "?")
            articles = info.get("articles", 0)
            arrow = {"rising": "^", "falling": "v", "stable": "="}.get(trend, "?")
            lines.append(f"  {cat}: {score}/100 [{arrow}] ({articles} artigos)")

        conns = data.get("connections", [])
        if conns:
            lines.append("\n*Conexoes activas:*")
            for c in conns[:5]:
                lines.append(
                    f"  {c['from']} <-> {c['to']} (score {c['score']})"
                )

        return "\n".join(lines)

    return "Scores ainda nao calculados. O CronJob corre 2x/dia."


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def main():
    logger.info("Trend scorer starting...")

    fm = FeedManager()
    articles = fm.get_all_cached()
    logger.info("Scoring %d cached articles.", len(articles))

    scores = calculate_scores(articles)

    patterns = db_get_patterns()
    connections = calculate_connections(patterns)

    output = dict(scores)
    output["connections"] = connections
    output["updated_at"] = datetime.now(timezone.utc).isoformat()

    save_trend_scores(output)

    logger.info("Trend scores saved:")
    for cat, data in scores.items():
        logger.info("  %s: %d/100 [%s] (%d articles)",
                     cat, data["score"], data["trend"], data["articles"])
    logger.info("Connections: %d", len(connections))

    scored = await score_articles(articles, patterns)
    save_scored(scored)
    logger.info("Relevance filter: %d articles passed threshold.", len(scored))


if __name__ == "__main__":
    asyncio.run(main())
