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
from telegram_format import to_telegram_html

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

# Month names hardcoded on purpose: the slim python image doesn't ship
# the pt_BR locale, so locale.setlocale / strftime("%B") would fall back
# to English (or fail). This keeps the digest date in Portuguese with
# zero system dependency.
_PT_MONTHS = [
    "janeiro", "fevereiro", "marco", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
]


def _today_str() -> str:
    """Today's date as e.g. '19 de maio de 2026'.

    The bug this fixes: the synthesis prompt asked the LLM for "data de
    hoje" but never told it what today was, so the model filled in a
    hallucinated date (observed: "19 de maio de 2025" — a year off).
    We now compute it here and pass it in explicitly.

    DIGEST_UTC_OFFSET (integer hours, default 0) shifts UTC to the
    user's civil timezone so the date is correct near midnight. e.g.
    -3 for America/Sao_Paulo, +1 for Europe/Lisbon (summer). Default 0
    keeps behaviour unchanged for UTC deployments.
    """
    try:
        offset = int(os.getenv("DIGEST_UTC_OFFSET", "0"))
    except (ValueError, TypeError):
        offset = 0
    now = datetime.now(timezone.utc) + timedelta(hours=offset)
    return f"{now.day} de {_PT_MONTHS[now.month - 1]} de {now.year}"


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
    safe = to_telegram_html(message)
    async with httpx.AsyncClient() as client:
        for i in range(0, len(safe), 4000):
            await client.post(
                url,
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": safe[i : i + 4000],
                    "parse_mode": "HTML",
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
    today = _today_str()

    # Authoritative date directive at the very top of the prompt. The
    # model never knows the real date on its own; without this it
    # hallucinates (observed a full year off). Stated explicitly here
    # AND referenced from the structure placeholders below.
    date_directive = (
        f"IMPORTANTE: hoje e {today}. Use EXATAMENTE esta data sempre "
        f"que a estrutura pedir a data de hoje. NUNCA invente, suponha "
        f"ou use outra data ou outro ano.\n\n"
    )

    if mode == "morning":
        prompt = date_directive + f"""\
Gere um BRIEFING MATINAL (09h) em portugues do Brasil para o usuario \
Jose Carlos (DevOps/Platform Engineer). Seja direto, conciso \
e acionavel. Use emojis com moderacao.

Estrutura obrigatoria:

*BOM DIA, JOSE CARLOS* [saudacao breve + a data de hoje ({today})]

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
        prompt = date_directive + f"""\
Gere um RELATORIO NOTURNO (21h) em portugues do Brasil para o usuario \
Jose Carlos. Reflexivo mas conciso.

Estrutura obrigatoria:

*BOA NOITE* [a data de hoje ({today}), saudacao breve]

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
# Macro digest (Onda 12 Sprint 1 — B1).
#
# Minimal Telegram brief: current value + diff vs the immediately
# preceding observation per indicator, plus a stale warning when the
# upstream source has lagged. Reads from macro_indicators via
# macro_repository (same SQLite path morning/evening already use), NOT
# via /api/macro/latest — the digest container has DB access already,
# and HTTPing localhost just to read the same DB is wasted work that
# would add a runtime dependency on the API pod being up.
#
# Deterministic and LLM-free: numbers only, no interpretation. The
# "vs prior_ts" framing (not "vs yesterday") is honest about which
# point we compared against — survives weekends, holidays and FRED
# lag without silent lies.
# ---------------------------------------------------------------------------

# Order is intentional: daily/volatile first (VIX vol → credit OAS →
# equity → rates), then the slow-moving monthly CAPE at the bottom.
_MACRO_ORDER = ("vix", "hy_oas", "sp500_close", "tnx_yield", "cape_shiller")

_MACRO_LABELS = {
    "vix":          ("VIX",     "{:.2f}"),
    "hy_oas":       ("HY OAS",  "{:.2f}%"),
    "sp500_close":  ("S&P 500", "{:.2f}"),
    "tnx_yield":    ("10Y",     "{:.2f}%"),
    "cape_shiller": ("CAPE",    "{:.2f}"),
}


def _short_date_pt(ts: str) -> str:
    """ISO ``YYYY-MM-DD`` (or fuller ISO) -> ``DD/MM`` (PT convention)."""
    return datetime.fromisoformat(ts[:10]).strftime("%d/%m")


def _short_month_pt(ts: str) -> str:
    """ISO ``YYYY-MM-DD`` -> ``<mmm>/<yyyy>`` with a 3-letter PT month."""
    dt = datetime.fromisoformat(ts[:10])
    return f"{_PT_MONTHS[dt.month - 1][:3]}/{dt.year}"


def _gather_macro_data() -> dict:
    """Pure read: per-indicator freshness + the latest 2 observations.

    Returns ``{by_indicator: {ind: {freshness, recent}}, fred_latest_ts}``.
    ``fred_latest_ts`` is the freshest *daily* ts (used for the header
    date and the footer line); CAPE's monthly ts is intentionally
    excluded from that aggregation — labelling the brief with a
    4-week-old monthly ts as "latest FRED close" would be a lie.
    """
    import macro_repository as mr  # lazy: keep morning/evening import graph clean

    freshness = {f["indicator"]: f for f in mr.get_freshness()}
    by_indicator: dict[str, dict] = {}
    daily_latest_ts: list[str] = []
    for ind in _MACRO_ORDER:
        f = freshness.get(ind, {})
        recent = [] if f.get("no_data") else mr.get_recent(ind, n=2)
        by_indicator[ind] = {"freshness": f, "recent": recent}
        if recent and f.get("cadence") == "daily":
            daily_latest_ts.append(recent[0]["ts"])
    return {
        "by_indicator": by_indicator,
        "fred_latest_ts": max(daily_latest_ts) if daily_latest_ts else None,
    }


def _format_macro_message(data: dict) -> str:
    """Render the Telegram body. Pure function of ``data`` so the same
    builder can be exercised offline against fixture dicts."""
    fred_ts = data["fred_latest_ts"]
    if fred_ts:
        header_dt = datetime.fromisoformat(fred_ts[:10])
        header = f"*Macro - {header_dt.strftime('%d/%m/%Y')}*"
    else:
        header = "*Macro - sem dados*"

    lines: list[str] = [header]
    warnings: list[str] = []

    for ind in _MACRO_ORDER:
        b = data["by_indicator"][ind]
        f = b["freshness"]
        label, fmt = _MACRO_LABELS[ind]
        recent = b["recent"]

        if not recent:
            lines.append(f"{label}: sem dados")
            warnings.append(f"WARNING: {label} sem dados")
            continue

        latest = recent[0]
        value_str = fmt.format(latest["value"])

        # Monthly: label-only suffix (no daily-style diff — MoM deltas
        # can come later as a separate framing decision).
        if f.get("cadence") == "monthly":
            suffix = f"(mensal, {_short_month_pt(latest['ts'])})"
        elif len(recent) >= 2:
            prior = recent[1]
            diff = latest["value"] - prior["value"]
            suffix = f"({diff:+.2f} vs {_short_date_pt(prior['ts'])})"
        else:
            suffix = "(sem observacao anterior)"

        lines.append(f"{label}: {value_str} {suffix}")

        if f.get("is_stale"):
            age = f.get("age_days")
            unit = "dias uteis" if f.get("cadence") == "daily" else "dias"
            warnings.append(f"WARNING: {label} stale ha {age} {unit}")

    if warnings:
        lines.append("")
        lines.extend(warnings)

    lines.append("")
    if fred_ts:
        # "fecho mais recente" (não "fecho de hoje") porque o brief pode
        # correr num dia em que FRED ainda não publicou — a data aqui é
        # SEMPRE max(daily_latest_ts) do DB, nunca today. Header acompanha
        # a mesma data pelo mesmo motivo (consistência total).
        footer_dt = datetime.fromisoformat(fred_ts[:10])
        lines.append(
            f"Dados FRED: fecho mais recente {footer_dt.strftime('%d/%m/%Y')}; "
            "lag tipico 1-2 dias uteis"
        )
    else:
        lines.append(
            "Dados FRED: sem observacoes recentes; lag tipico 1-2 dias uteis"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "morning"
    if mode not in ("morning", "evening", "macro"):
        logger.error("Invalid mode: %s (use 'morning', 'evening' or 'macro')", mode)
        sys.exit(1)

    logger.info("Digest starting in %s mode...", mode)

    if mode == "macro":
        # Deterministic numeric brief — no LLM call.
        text = _format_macro_message(_gather_macro_data())
    elif mode == "morning":
        text = await _synthesise(mode, _gather_morning_data())
    else:  # evening
        text = await _synthesise(mode, _gather_evening_data())

    await _send_telegram(text)

    state = _load_json(DIGEST_STATE, {})
    state[f"last_{mode}"] = datetime.now(timezone.utc).isoformat()
    _save_json(DIGEST_STATE, state)

    logger.info("Digest %s sent (%d chars).", mode, len(text))


if __name__ == "__main__":
    asyncio.run(main())
