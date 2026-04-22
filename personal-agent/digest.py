"""Daily digest generator.

- Morning digest (9h): top trends, overnight patterns, crypto alerts, news,
  jobs pending -> synthesised by Gemini into a readable brief
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
import google.generativeai as genai

DATA_DIR = os.getenv("DATA_DIR", "/data")
LOG_FILE = os.path.join(DATA_DIR, "agent.log")
MEMORY_FILE = os.path.join(DATA_DIR, "memory.json")
JOBS_FILE = os.path.join(DATA_DIR, "jobs_tracker.json")
PATTERNS_FILE = os.path.join(DATA_DIR, "patterns.json")
CRYPTO_FILE = os.path.join(DATA_DIR, "crypto_scan.json")
FEEDS_FILE = os.path.join(DATA_DIR, "feeds_cache.json")
TRENDS_FILE = os.path.join(DATA_DIR, "trend_scores.json")
MONITOR_FILE = os.path.join(DATA_DIR, "monitor_state.json")
DIGEST_STATE = os.path.join(DATA_DIR, "digest_state.json")

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
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


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
    trends = _load_json(TRENDS_FILE, {})
    patterns = _load_json(PATTERNS_FILE, [])
    cryptos = _load_json(CRYPTO_FILE, [])
    feeds = _load_json(FEEDS_FILE, [])
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
        "recent_patterns": _filter_recent(
            patterns if isinstance(patterns, list) else [],
            "timestamp", 16,
        )[:3],
        "recent_crypto": _filter_recent(
            cryptos if isinstance(cryptos, list) else [],
            "timestamp", 16,
        )[:5],
        "top_news": (feeds if isinstance(feeds, list) else [])[-15:],
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

    patterns = _load_json(PATTERNS_FILE, [])
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

    today_patterns = _filter_recent(
        patterns if isinstance(patterns, list) else [],
        "timestamp", 14,
    )
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
# Gemini synthesis
# ---------------------------------------------------------------------------

async def _synthesise(mode: str, data: dict) -> str:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")

    if mode == "morning":
        prompt = f"""\
Gera um BRIEFING MATINAL (09h) em portugues de Portugal para o user \
Jose Carlos (DevOps/Platform Engineer em Portugal). Se directo, conciso \
e accionavel. Usa emojis moderadamente.

Estrutura obrigatoria:

*BOM DIA, JOSE CARLOS* [saudacao breve + data de hoje]

*MERCADOS* [precos + variacoes noturnas, so os relevantes]
{json.dumps(data.get('prices', {}), indent=2, ensure_ascii=False)[:500]}

*CRIPTO DESTAQUE* [cryptos com movimento significativo, top 3]
{json.dumps(data.get('recent_crypto', [])[:3], indent=2, ensure_ascii=False)[:1500]}

*TRENDS ACTIVAS* [categorias com scores mais altos]
{json.dumps(data.get('trends', []), indent=2, ensure_ascii=False)[:600]}

*PADROES DETECTADOS* [padroes geopolitics/tech relevantes]
{json.dumps(data.get('recent_patterns', []), indent=2, ensure_ascii=False)[:2000]}

*FOCO DO DIA* [prioridades baseadas em:
- {data.get('active_jobs_count', 0)} candidaturas activas
- {len(data.get('stale_jobs', []))} candidaturas sem update ha 7+ dias
- Padroes e oportunidades detectadas acima]

Sugere 3 accoes concretas para hoje. Maximo 300 palavras total.\
"""
    else:
        prompt = f"""\
Gera um RELATORIO NOCTURNO (21h) em portugues de Portugal para o user \
Jose Carlos. Reflexivo mas conciso.

Estrutura obrigatoria:

*BOA NOITE* [data de hoje, saudacao breve]

*RESUMO DO DIA*
- {data.get('conversations', 0)} conversas com o agente
- {len(data.get('jobs_touched', []))} candidaturas actualizadas hoje
- {len(data.get('patterns_today', []))} padroes novos
- {len(data.get('cryptos_today', []))} alertas cripto

*NOVOS FACTOS APRENDIDOS HOJE* [ultimos 5 factos que o agente registou]
Total de factos: {data.get('facts_count', 0)}
Ultimos factos: {json.dumps(data.get('facts', [])[-5:], ensure_ascii=False)[:500]}

*DESTAQUES*
Patterns: {json.dumps(data.get('patterns_today', [])[:3], ensure_ascii=False)[:1500]}

*RECOMENDACOES PARA AMANHA*
Sugere 2-3 accoes concretas para amanha, baseadas nos patterns e no estado \
das candidaturas.

*REFLEXAO* [1 frase final, motivacional mas realista]

Maximo 300 palavras.\
"""

    try:
        response = await asyncio.to_thread(model.generate_content, prompt)
        return response.text or "Erro a gerar digest."
    except Exception as e:
        logger.error("Gemini digest error: %s", e)
        return f"Digest generation failed: {e}"


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
