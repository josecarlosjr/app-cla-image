"""Daily digest generator.

- Morning digest (9h): top trends, overnight patterns, crypto alerts, news,
  jobs pending -> synthesised by Claude into a readable brief
- Evening report (21h): day summary, new facts learned, recommendations

Run mode is controlled via arg: `python digest.py morning` or `python digest.py evening`.
"""

import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx

from llm import generate_text
import database as db

from log_config import setup_logging

setup_logging()

DATA_DIR = os.getenv("DATA_DIR", "/data")
MEMORY_FILE = os.path.join(DATA_DIR, "memory.json")
JOBS_FILE = os.path.join(DATA_DIR, "jobs_tracker.json")
CRYPTO_FILE = os.path.join(DATA_DIR, "crypto_scan.json")
MONITOR_FILE = os.path.join(DATA_DIR, "monitor_state.json")
DIGEST_STATE = os.path.join(DATA_DIR, "digest_state.json")

os.makedirs(DATA_DIR, exist_ok=True)

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_ALLOWED_USER_ID")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: str, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return default
    return default


def _save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


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


def _filter_recent(items: list, key: str, hours: int) -> list:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    out = []
    for item in items:
        try:
            ts_raw = item.get(key, "")
            ts = datetime.fromisoformat(ts_raw)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                out.append(item)
        except (ValueError, KeyError, AttributeError):
            continue
    return out


# ---------------------------------------------------------------------------
# Data gathering
# ---------------------------------------------------------------------------

def _gather_morning_data() -> dict:
    """Data since last evening (approx last 12h)."""
    trends = db.get_trend_scores_data() or {}
    patterns = db.get_patterns()
    cryptos = _load_json(CRYPTO_FILE, [])
    feeds = db.get_articles(hours=16)
    jobs = _load_json(JOBS_FILE, [])
    monitor = _load_json(MONITOR_FILE, {})
    memory = _load_json(MEMORY_FILE, {"facts": []})

    active_jobs = [
        j for j in (jobs if isinstance(jobs, list) else [])
        if j.get("status", "").lower() in {"applied", "interview", "pending"}
    ]

    top_trends = []
    if isinstance(trends, dict):
        for cat in ["chips_ia", "energia", "minerais", "geopolitica",
                    "ciberseguranca", "ciencia", "espaco_defesa", "financas"]:
            info = trends.get(cat, {})
            top_trends.append({
                "category": cat,
                "score": info.get("score", 0),
                "trend": info.get("trend", "stable"),
            })
        top_trends.sort(key=lambda x: x["score"], reverse=True)

    return {
        "trends": top_trends[:5],
        "recent_patterns": _filter_recent(patterns, "timestamp", 16)[:3],
        "recent_crypto": _filter_recent(
            cryptos if isinstance(cryptos, list) else [],
            "timestamp", 16,
        )[:5],
        "top_news": feeds[:15],
        "active_jobs_count": len(active_jobs),
        "stale_jobs": [
            j for j in active_jobs
            if _is_stale(j.get("updated", ""), 7)
        ],
        "facts": memory.get("facts", []) if isinstance(memory, dict) else [],
        "prices": monitor.get("last_prices", {}) if isinstance(monitor, dict) else {},
    }


def _gather_evening_data() -> dict:
    """Data from today only."""
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    patterns = db.get_patterns()
    cryptos = _load_json(CRYPTO_FILE, [])
    memory = _load_json(MEMORY_FILE, {"history": [], "facts": []})
    jobs = _load_json(JOBS_FILE, [])

    history = memory.get("history", []) if isinstance(memory, dict) else []
    today_msgs = []
    for m in history:
        try:
            ts = datetime.fromisoformat(m.get("timestamp", ""))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= today_start:
                today_msgs.append(m)
        except (ValueError, KeyError):
            continue

    today_patterns = _filter_recent(patterns, "timestamp", 14)
    today_cryptos = _filter_recent(
        cryptos if isinstance(cryptos, list) else [],
        "timestamp", 14,
    )

    return {
        "conversations": len(today_msgs) // 2,
        "facts": memory.get("facts", []) if isinstance(memory, dict) else [],
        "facts_count": len(memory.get("facts", []) if isinstance(memory, dict) else []),
        "patterns_today": today_patterns[:5],
        "cryptos_today": today_cryptos[:5],
        "jobs_touched": [
            j for j in (jobs if isinstance(jobs, list) else [])
            if _is_updated_today(j.get("updated", ""))
        ],
    }


def _is_stale(date_str: str, days: int) -> bool:
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt) > timedelta(days=days)
    except (ValueError, TypeError):
        return False


def _is_updated_today(date_str: str) -> bool:
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.date() == datetime.now(timezone.utc).date()
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Claude synthesis
# ---------------------------------------------------------------------------

async def _synthesise(mode: str, data: dict) -> str:
    if mode == "morning":
        prompt = f"""\
Gere um BRIEFING MATINAL (09h) em portugues do Brasil para o usuario \
Jose Carlos (DevOps/Platform Engineer). Seja direto, conciso \
e acionavel. Use emojis com moderacao.

Estrutura obrigatoria:

*BOM DIA, JOSE CARLOS* [saudacao breve + data de hoje]

*MERCADOS* [precos + variacoes noturnas, so os relevantes]
{json.dumps(data.get('prices', {}), indent=2, ensure_ascii=False)[:500]}

*CRIPTO DESTAQUE* [cryptos com movimento significativo, top 3]
{json.dumps(data.get('recent_crypto', [])[:3], indent=2, ensure_ascii=False)[:1500]}

*TRENDS ATIVAS* [categorias com scores mais altos]
{json.dumps(data.get('trends', []), indent=2, ensure_ascii=False)[:600]}

*PADROES DETECTADOS* [padroes geopoliticos/tech relevantes]
{json.dumps(data.get('recent_patterns', []), indent=2, ensure_ascii=False)[:2000]}

*FOCO DO DIA* [prioridades baseadas em:
- {data.get('active_jobs_count', 0)} candidaturas ativas
- {len(data.get('stale_jobs', []))} candidaturas sem update ha 7+ dias
- Padroes e oportunidades detectadas acima]

Sugira 3 acoes concretas para hoje. Maximo 300 palavras total.\
"""
    else:
        prompt = f"""\
Gere um RELATORIO NOTURNO (21h) em portugues do Brasil para o usuario \
Jose Carlos. Reflexivo mas conciso.

Estrutura obrigatoria:

*BOA NOITE* [data de hoje, saudacao breve]

*RESUMO DO DIA*
- {data.get('conversations', 0)} conversas com o agente
- {len(data.get('jobs_touched', []))} candidaturas atualizadas hoje
- {len(data.get('patterns_today', []))} padroes novos
- {len(data.get('cryptos_today', []))} alertas cripto

*NOVOS FATOS APRENDIDOS HOJE* [ultimos 5 fatos que o agente registrou]
Total de fatos: {data.get('facts_count', 0)}
Ultimos fatos: {json.dumps(data.get('facts', [])[-5:], ensure_ascii=False)[:500]}

*DESTAQUES*
Patterns: {json.dumps(data.get('patterns_today', [])[:3], ensure_ascii=False)[:1500]}

*RECOMENDACOES PARA AMANHA*
Sugira 2-3 acoes concretas para amanha, baseadas nos padroes e no estado \
das candidaturas.

*REFLEXAO* [1 frase final, motivacional mas realista]

Maximo 300 palavras.\
"""

    text = await generate_text(prompt=prompt, max_tokens=1500)
    return text or "Erro ao gerar digest."


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "morning"
    if mode not in ("morning", "evening"):
        logger.error("Invalid mode: %s (use 'morning' or 'evening')", mode)
        sys.exit(1)

    logger.info("Digest starting in %s mode...", mode)

    if mode == "morning":
        data = _gather_morning_data()
    else:
        data = _gather_evening_data()

    text = await _synthesise(mode, data)
    await _send_telegram(text)

    state = _load_json(DIGEST_STATE, {})
    state[f"last_{mode}"] = datetime.now(timezone.utc).isoformat()
    _save_json(DIGEST_STATE, state)

    logger.info("Digest %s sent (%d chars).", mode, len(text))


if __name__ == "__main__":
    asyncio.run(main())
