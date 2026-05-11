"""Quant alerts — bubble/crisis detection notifications via Telegram.

Phase 5 of Onda 12 Quant Layer. Reads the latest LPPL + GSADF features
written by quant_detectors, filters anything crossing severity
thresholds, synthesises a short Portuguese narrative via Haiku, and
posts to Telegram.

Triggering rules per ticker:

  lppl_bubble_prob > 0.85  -> HIGH   (severe bubble signature)
  lppl_bubble_prob > 0.70  -> MEDIUM (bubble warning)
  gsadf_explosive == True  -> HIGH   (95% explosive rejection of unit-root)

Cooldown: 7 days per ticker. Re-alert sooner only if severity escalates
from MEDIUM to HIGH. This keeps the bot from screaming every night
about the same condition until something materially changes.

Run after quant_detectors -- schedule 23:30 UTC.
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx

from llm import generate_text, MODEL_HAIKU
import pg_database as pg
from telegram_format import to_telegram_html
from log_config import setup_logging

setup_logging()

DATA_DIR = os.getenv("DATA_DIR", "/data")
STATE_FILE = os.path.join(DATA_DIR, "quant_alerts_state.json")
os.makedirs(DATA_DIR, exist_ok=True)

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_ALLOWED_USER_ID")

LPPL_HIGH = 0.85
LPPL_MED = 0.70
COOLDOWN_DAYS = 7
MAX_TICKERS_IN_NARRATIVE = 5


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("State file corrupt, starting fresh.")
    return {"last_alerts": {}, "last_run": None}


def _save_state(data: dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Severity + cooldown logic
# ---------------------------------------------------------------------------

def _severity_for_row(row: dict) -> tuple[str | None, list[str]]:
    """Return (severity, reasons). severity in {HIGH, MEDIUM, None}."""
    reasons: list[str] = []
    sev: str | None = None

    lppl = row.get("lppl_bubble_prob")
    if lppl is not None:
        if lppl > LPPL_HIGH:
            sev = "HIGH"
            reasons.append(f"LPPL={lppl:.2f} (severo, >{LPPL_HIGH})")
        elif lppl > LPPL_MED:
            sev = "MEDIUM"
            reasons.append(f"LPPL={lppl:.2f} (alerta, >{LPPL_MED})")

    if row.get("gsadf_explosive"):
        sev = "HIGH"
        g = row.get("gsadf_bsadf")
        reasons.append(
            f"GSADF={g:.2f} (explosivo, >1.49)" if g is not None
            else "GSADF explosivo"
        )

    return sev, reasons


def _should_alert(state: dict, ticker: str, severity: str) -> bool:
    """Cooldown logic. Re-alert if severity escalates or cooldown expired."""
    prev = state["last_alerts"].get(ticker)
    if not prev:
        return True

    if severity == "HIGH" and prev.get("severity") == "MEDIUM":
        return True  # escalation always alerts

    try:
        last_ts = datetime.fromisoformat(prev["ts"])
        if last_ts.tzinfo is None:
            last_ts = last_ts.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - last_ts
        return age > timedelta(days=COOLDOWN_DAYS)
    except (ValueError, KeyError, TypeError):
        return True


# ---------------------------------------------------------------------------
# Narrative synthesis (Haiku) + Telegram send
# ---------------------------------------------------------------------------

async def _synthesise_narrative(alerts: list[dict]) -> str:
    payload = json.dumps(
        [
            {
                "ticker": a["ticker"],
                "severity": a["severity"],
                "reasons": a["reasons"],
                "close": a.get("close"),
                "change_pct_30d": a.get("change_pct_30d"),
            }
            for a in alerts[:MAX_TICKERS_IN_NARRATIVE]
        ],
        ensure_ascii=False,
        indent=2,
    )

    prompt = f"""\
Voce e o assistente quantitativo do Jose Carlos. Os tickers abaixo \
cruzaram thresholds de detectores de bolha (LPPL) e/ou explosividade \
estatistica (GSADF). Gere um alerta curto e direto em portugues do Brasil.

Dados:
{payload}

Estrutura obrigatoria:

*ALERTA QUANT*

Para cada ticker:
*[TICKER]* (severidade)
- Motivos: [lista resumida dos sinais]
- Contexto: [1 frase sobre preco/momentum recente]

*INTERPRETACAO*
[1-2 frases sobre o que isso significa no conjunto. Mencione \
concentracao setorial se aplicavel.]

*ACAO SUGERIDA*
[1 sugestao conservadora: 'considere revisar', 'avalie stop', \
'pondere reducao'. Nao prescritivo, nao alarmista.]

Lembrete obrigatorio no final: 'LPPL e GSADF detectam padroes \
estatisticos, NAO predizem timing exato de correcao.'

Maximo 250 palavras.\
"""

    text = await generate_text(
        prompt=prompt, max_tokens=1024, model=MODEL_HAIKU,
    )
    return text or "Erro ao gerar narrativa de alerta quant."


async def _send_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    safe = to_telegram_html(message)
    async with httpx.AsyncClient() as client:
        for i in range(0, len(safe), 4000):
            await client.post(
                url,
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": safe[i:i + 4000],
                    "parse_mode": "HTML",
                },
                timeout=10,
            )


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

async def main():
    logger.info("Quant alerts starting...")
    state = _load_state()

    try:
        watchlist = pg.get_watchlist()
    except Exception as e:
        logger.error("Failed to fetch watchlist from postgres: %s", e)
        return

    candidates: list[dict] = []
    suppressed: list[str] = []
    for row in watchlist:
        severity, reasons = _severity_for_row(row)
        if not severity:
            continue
        if not _should_alert(state, row["ticker"], severity):
            suppressed.append(f"{row['ticker']}({severity})")
            continue
        candidates.append({
            "ticker": row["ticker"],
            "severity": severity,
            "reasons": reasons,
            "close": row.get("close"),
            "change_pct_30d": row.get("change_pct_30d"),
        })

    if suppressed:
        logger.info("Suppressed by cooldown: %s", ", ".join(suppressed))

    if not candidates:
        logger.info("No alerts to send (%d tickers scanned).", len(watchlist))
        state["last_run"] = datetime.now(timezone.utc).isoformat()
        _save_state(state)
        return

    # HIGH first, then alphabetical within each severity bucket.
    candidates.sort(key=lambda a: (a["severity"] != "HIGH", a["ticker"]))

    narrative = await _synthesise_narrative(candidates)
    await _send_telegram(narrative)

    now_iso = datetime.now(timezone.utc).isoformat()
    for a in candidates:
        state["last_alerts"][a["ticker"]] = {
            "severity": a["severity"],
            "ts": now_iso,
            "reasons": a["reasons"],
        }
    state["last_run"] = now_iso
    _save_state(state)

    n_high = sum(1 for a in candidates if a["severity"] == "HIGH")
    n_med = sum(1 for a in candidates if a["severity"] == "MEDIUM")
    logger.info(
        "Quant alert sent: %d tickers (HIGH=%d MEDIUM=%d).",
        len(candidates), n_high, n_med,
    )


if __name__ == "__main__":
    asyncio.run(main())
