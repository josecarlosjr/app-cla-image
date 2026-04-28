import os
import re
import json
import asyncio
import logging
from datetime import datetime, timedelta

import httpx
from duckduckgo_search import DDGS

DATA_DIR = os.getenv("DATA_DIR", "/data")
STATE_FILE = os.path.join(DATA_DIR, "monitor_state.json")
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

# ---------------------------------------------------------------------------
# Threshold configuration
# ---------------------------------------------------------------------------

CRYPTO_THRESHOLDS = {
    "bitcoin": {
        "name": "Bitcoin",
        "symbol": "BTC",
        "pct_change": 5.0,
        "abs_high": 100_000,
        "abs_low": 70_000,
        "cooldown_hours": 4,
    },
    "ethereum": {
        "name": "Ethereum",
        "symbol": "ETH",
        "pct_change": 7.0,
        "cooldown_hours": 6,
    },
}

COMMODITY_THRESHOLDS = {
    "brent": {
        "name": "Brent Crude Oil",
        "query": "brent crude oil price USD today",
        "pct_change": 3.0,
        "abs_high": 130,
        "abs_low": 80,
        "cooldown_hours": 8,
    },
    "gold": {
        "name": "Ouro",
        "query": "gold price per ounce USD today",
        "pct_change": 2.0,
        "cooldown_hours": 12,
    },
}


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"last_alerts": {}, "last_prices": {}}


def _save_state(state: dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def _can_alert(state: dict, key: str, cooldown_hours: int) -> bool:
    last = state.get("last_alerts", {}).get(key)
    if not last:
        return True
    return datetime.now() - datetime.fromisoformat(last) > timedelta(
        hours=cooldown_hours
    )


def _mark_alerted(state: dict, key: str):
    state.setdefault("last_alerts", {})[key] = datetime.now().isoformat()


# ---------------------------------------------------------------------------
# Telegram sender
# ---------------------------------------------------------------------------

async def _send_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        await client.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "Markdown",
            },
            timeout=10,
        )


# ---------------------------------------------------------------------------
# Crypto prices (CoinGecko)
# ---------------------------------------------------------------------------

async def _check_crypto(state: dict) -> list[str]:
    alerts: list[str] = []
    ids = ",".join(CRYPTO_THRESHOLDS.keys())

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.coingecko.com/api/v3/simple/price"
            f"?ids={ids}&vs_currencies=usd&include_24hr_change=true",
            timeout=10,
        )
        data = resp.json()

    for coin_id, cfg in CRYPTO_THRESHOLDS.items():
        if coin_id not in data:
            continue

        price = data[coin_id].get("usd", 0)
        change_24h = data[coin_id].get("usd_24h_change", 0)
        state.setdefault("last_prices", {})[coin_id] = price

        triggered = False
        reason = ""

        if abs(change_24h) >= cfg["pct_change"]:
            direction = "subiu" if change_24h > 0 else "caiu"
            reason = f"{cfg['name']} {direction} {abs(change_24h):.1f}% em 24h"
            triggered = True

        if "abs_high" in cfg and price >= cfg["abs_high"]:
            reason = f"{cfg['name']} acima de ${cfg['abs_high']:,.0f}"
            triggered = True

        if "abs_low" in cfg and price <= cfg["abs_low"]:
            reason = f"{cfg['name']} abaixo de ${cfg['abs_low']:,.0f}"
            triggered = True

        if triggered and _can_alert(state, f"crypto_{coin_id}", cfg["cooldown_hours"]):
            up = change_24h > 0
            alerts.append(
                f"{'📈' if up else '📉'} *ALERTA {cfg['symbol']}*\n\n"
                f"Preco: ${price:,.2f}\n"
                f"Variacao 24h: {change_24h:+.2f}%\n"
                f"Motivo: {reason}\n\n"
                f"*Se continuar:* "
                f"{'Rally pode se estender — considere manter posicao.' if up else 'Queda pode se aprofundar — avalie stop-loss.'}\n"
                f"*Se reverter:* "
                f"{'Possivel correcao apos subida forte — nao entre em FOMO.' if up else 'Possivel oportunidade de compra em suporte.'}\n\n"
                f"*Acao sugerida:* "
                f"{'Monitorar resistencias e definir take-profit.' if up else 'Verificar niveis de suporte e volume.'}"
            )
            _mark_alerted(state, f"crypto_{coin_id}")

    return alerts


# ---------------------------------------------------------------------------
# Commodity prices (DuckDuckGo scrape)
# ---------------------------------------------------------------------------

async def _check_commodities(state: dict) -> list[str]:
    alerts: list[str] = []

    for key, cfg in COMMODITY_THRESHOLDS.items():
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(cfg["query"], max_results=3))

            text_blob = " ".join(r.get("body", "") for r in results)
            prices = re.findall(r"\$?([\d,]+\.?\d*)", text_blob)
            if not prices:
                continue

            price = float(prices[0].replace(",", ""))
            last_price = state.get("last_prices", {}).get(key)
            state.setdefault("last_prices", {})[key] = price

            if not last_price:
                continue

            pct_change = ((price - last_price) / last_price) * 100
            triggered = False
            reason = ""

            if abs(pct_change) >= cfg["pct_change"]:
                direction = "subiu" if pct_change > 0 else "caiu"
                reason = (
                    f"{cfg['name']} {direction} {abs(pct_change):.1f}% "
                    "desde ultima verificacao"
                )
                triggered = True

            if "abs_high" in cfg and price >= cfg["abs_high"]:
                reason = f"{cfg['name']} acima de ${cfg['abs_high']:,.0f}"
                triggered = True

            if "abs_low" in cfg and price <= cfg["abs_low"]:
                reason = f"{cfg['name']} abaixo de ${cfg['abs_low']:,.0f}"
                triggered = True

            if triggered and _can_alert(
                state, f"commodity_{key}", cfg["cooldown_hours"]
            ):
                up = pct_change > 0
                alerts.append(
                    f"{'📈' if up else '📉'} *ALERTA {cfg['name']}*\n\n"
                    f"Preco: ${price:,.2f}\n"
                    f"Variacao: {pct_change:+.2f}%\n"
                    f"Motivo: {reason}\n\n"
                    f"*Se continuar:* "
                    f"{'Pressao de alta — monitorar fatores geopoliticos.' if up else 'Pressao de baixa — verificar estoques e producao.'}\n"
                    f"*Se reverter:* "
                    f"{'Possivel correcao — nao persiga o preco.' if up else 'Potencial recuperacao — avalie entrada gradual.'}\n\n"
                    f"*Acao sugerida:* Analisar noticias geopoliticas relacionadas."
                )
                _mark_alerted(state, f"commodity_{key}")

        except Exception as e:
            logger.error("Error checking %s: %s", key, e)

    return alerts


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    logger.info("Market monitor starting...")
    state = _load_state()

    all_alerts: list[str] = []
    all_alerts.extend(await _check_crypto(state))
    all_alerts.extend(await _check_commodities(state))

    for alert in all_alerts:
        await _send_telegram(alert)
        logger.info("Alert sent: %s...", alert[:60])

    _save_state(state)
    logger.info("Monitor done. %d alerts sent.", len(all_alerts))


if __name__ == "__main__":
    asyncio.run(main())
