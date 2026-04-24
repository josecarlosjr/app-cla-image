import os
import json
import asyncio
import logging
from datetime import datetime, timezone

import httpx
from duckduckgo_search import DDGS

from llm import generate_text

DATA_DIR = os.getenv("DATA_DIR", "/data")
SCAN_FILE = os.path.join(DATA_DIR, "crypto_scan.json")
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

MAX_ALERTS_PER_RUN = 5
MIN_CHANGE_PCT = 15.0
MAX_SCANS_STORED = 50
COINGECKO_BASE = "https://api.coingecko.com/api/v3"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _load_scans() -> list[dict]:
    if os.path.exists(SCAN_FILE):
        with open(SCAN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def _save_scans(scans: list[dict]):
    with open(SCAN_FILE, "w", encoding="utf-8") as f:
        json.dump(scans[-MAX_SCANS_STORED:], f, indent=2, ensure_ascii=False)


def _already_scanned(scans: list[dict], coin_id: str) -> bool:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return any(
        s["coin_id"] == coin_id and s["date"] == today for s in scans
    )


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
# CoinGecko data fetching
# ---------------------------------------------------------------------------

async def _fetch_trending(client: httpx.AsyncClient) -> list[dict]:
    try:
        resp = await client.get(f"{COINGECKO_BASE}/search/trending", timeout=10)
        data = resp.json()
        coins = []
        for item in data.get("coins", [])[:15]:
            c = item.get("item", {})
            coins.append({
                "coin_id": c.get("id", ""),
                "name": c.get("name", ""),
                "symbol": c.get("symbol", "").upper(),
                "price_change_24h": c.get("data", {}).get(
                    "price_change_percentage_24h", {}).get("usd", 0),
                "price_usd": c.get("data", {}).get("price", 0),
                "market_cap_rank": c.get("market_cap_rank", 999),
                "source": "trending",
            })
        return coins
    except Exception as e:
        logger.error("Trending fetch error: %s", e)
        return []


async def _fetch_top_gainers(client: httpx.AsyncClient) -> list[dict]:
    try:
        resp = await client.get(
            f"{COINGECKO_BASE}/coins/markets",
            params={
                "vs_currency": "usd",
                "order": "price_change_percentage_24h_desc",
                "per_page": 50,
                "page": 1,
                "sparkline": "false",
            },
            timeout=10,
        )
        data = resp.json()
        coins = []
        for c in data:
            coins.append({
                "coin_id": c.get("id", ""),
                "name": c.get("name", ""),
                "symbol": c.get("symbol", "").upper(),
                "price_change_24h": c.get("price_change_percentage_24h", 0) or 0,
                "price_usd": c.get("current_price", 0),
                "market_cap_rank": c.get("market_cap_rank", 999),
                "market_cap": c.get("market_cap", 0),
                "volume_24h": c.get("total_volume", 0),
                "source": "markets",
            })
        return coins
    except Exception as e:
        logger.error("Top gainers fetch error: %s", e)
        return []


# ---------------------------------------------------------------------------
# Web search + Gemini analysis
# ---------------------------------------------------------------------------

def _web_search_sync(query: str) -> str:
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=5))
        if not results:
            return "No results found."
        return "\n".join(
            f"- {r['title']}: {r['body']}" for r in results
        )
    except Exception as e:
        return f"Search error: {e}"


async def _analyze_coin(coin: dict, search_context: str) -> str | None:
    change = coin["price_change_24h"]
    prompt = (
        f"A criptomoeda {coin['name']} ({coin['symbol']}) subiu "
        f"{change:+.1f}% nas ultimas 24h. Preco actual: ${coin['price_usd']:,.4f}.\n"
        f"Market cap rank: #{coin.get('market_cap_rank', 'N/A')}\n\n"
        f"Contexto da pesquisa web:\n{search_context[:2000]}\n\n"
        "Analisa em portugues de Portugal com esta estrutura EXACTA:\n\n"
        "*PORQUE SUBIU:* [2-3 frases com a causa real]\n\n"
        "*OPORTUNIDADE OU ARMADILHA:* [avaliacao honesta — e pump & dump? "
        "Ha fundamentos? Argumentos pro e contra]\n\n"
        "*ACCAO SUGERIDA:* [aguardar/comprar/evitar e porque — se conciso]\n\n"
        "Se directo e honesto. Maximo 150 palavras."
    )

    text = await generate_text(prompt=prompt, max_tokens=768)
    return text or None


# ---------------------------------------------------------------------------
# Public function for tools.py integration
# ---------------------------------------------------------------------------

async def scan_trending() -> str:
    async with httpx.AsyncClient() as client:
        trending = await _fetch_trending(client)
        gainers = await _fetch_top_gainers(client)

    seen_ids = set()
    all_coins = []
    for coin in trending + gainers:
        if coin["coin_id"] and coin["coin_id"] not in seen_ids:
            seen_ids.add(coin["coin_id"])
            all_coins.append(coin)

    pumping = [c for c in all_coins if c["price_change_24h"] >= MIN_CHANGE_PCT]
    pumping.sort(key=lambda x: x["price_change_24h"], reverse=True)

    if not pumping:
        return "Nenhuma crypto com variacao superior a +15% nas ultimas 24h."

    lines = [f"*Top Gainers (>+{MIN_CHANGE_PCT:.0f}% 24h):*\n"]
    for c in pumping[:10]:
        lines.append(
            f"- {c['name']} ({c['symbol']}): {c['price_change_24h']:+.1f}% "
            f"| ${c['price_usd']:,.4f} | Rank #{c.get('market_cap_rank', 'N/A')}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main CronJob entry point
# ---------------------------------------------------------------------------

async def main():
    logger.info("Crypto scanner starting...")
    scans = _load_scans()

    async with httpx.AsyncClient() as client:
        trending = await _fetch_trending(client)
        gainers = await _fetch_top_gainers(client)

    seen_ids: set[str] = set()
    all_coins: list[dict] = []
    for coin in trending + gainers:
        if coin["coin_id"] and coin["coin_id"] not in seen_ids:
            seen_ids.add(coin["coin_id"])
            all_coins.append(coin)

    pumping = [c for c in all_coins if c["price_change_24h"] >= MIN_CHANGE_PCT]
    pumping.sort(key=lambda x: x["price_change_24h"], reverse=True)

    logger.info(
        "Found %d coins total, %d pumping (>+%.0f%%).",
        len(all_coins), len(pumping), MIN_CHANGE_PCT,
    )

    alerts_sent = 0
    for coin in pumping:
        if alerts_sent >= MAX_ALERTS_PER_RUN:
            break
        if _already_scanned(scans, coin["coin_id"]):
            continue

        search_query = f"why is {coin['name']} {coin['symbol']} pumping today 2026"
        search_context = _web_search_sync(search_query)

        analysis = await _analyze_coin(coin, search_context)
        if not analysis:
            continue

        message = (
            f"*CRYPTO SCANNER — {coin['symbol']}*\n\n"
            f"*{coin['name']}* ({coin['symbol']})\n"
            f"Preco: ${coin['price_usd']:,.4f}\n"
            f"Variacao 24h: {coin['price_change_24h']:+.1f}%\n"
            f"Rank: #{coin.get('market_cap_rank', 'N/A')}\n\n"
            f"{analysis}"
        )

        await _send_telegram(message)
        alerts_sent += 1

        scans.append({
            "coin_id": coin["coin_id"],
            "name": coin["name"],
            "symbol": coin["symbol"],
            "price_usd": coin["price_usd"],
            "change_24h": coin["price_change_24h"],
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analysis": analysis[:500],
        })

        logger.info("Alert sent: %s (+%.1f%%)", coin["symbol"], coin["price_change_24h"])

    _save_scans(scans)
    logger.info("Crypto scanner done. %d alerts sent.", alerts_sent)


if __name__ == "__main__":
    asyncio.run(main())
