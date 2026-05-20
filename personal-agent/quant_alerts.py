"""Quant alerts — bubble/crisis detection notifications via Telegram.

Phase 5 of Onda 12 Quant Layer. Reads the latest LPPL + GSADF features
written by quant_detectors, filters anything crossing severity
thresholds, synthesises a short Portuguese narrative via Haiku, and
posts to Telegram.

Phase C (Knowledge Graph integration): each alerting ticker is
enriched with a 1-2 hop walk of the approved knowledge graph so the
narrative can talk about plausible contagion chains.

Integration phase A (this revision): the narrative also gets a
background macro-risk block — latest BIS credit-to-GDP gap for the US
and Portugal, and the Eurostat HPI year-on-year for Portugal. These
feed in as broad context (not ticker-specific) so the Interpretation
section can reach for credit-bubble or housing-bubble framing when
relevant. Empty / unreachable -> the block is omitted; the alert is
the critical path, the macro context is enrichment.

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
import database as db
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

# Phase C — knowledge-graph enrichment tuning.
MAX_GRAPH_EDGES_PER_TICKER = 6

# Map each watchlist ticker to canonical-name fragments likely to show
# up in the news-derived knowledge graph. Matching is fuzzy (substring,
# both directions, lowercase) so "sp500" / "s&p_500" / "spy_etf" all
# hook SPY without an exhaustive alias table. Unknown tickers fall back
# to the bare symbol (e.g. "DOGE-USD" -> "doge").
TICKER_ENTITY_HINTS: dict[str, list[str]] = {
    "SPY": ["sp500", "s&p", "sp_500", "us_equities", "equities",
            "stock_market", "spy"],
    "QQQ": ["nasdaq", "tech_stocks", "big_tech", "qqq"],
    "IWM": ["russell", "small_cap", "iwm"],
    "BTC-USD": ["bitcoin", "btc"],
    "ETH-USD": ["ethereum", "eth"],
    "XLK": ["technology_sector", "tech_sector", "semiconductor",
            "software", "xlk"],
    "XLE": ["energy_sector", "crude_oil", "oil", "opec", "xle"],
    "XLF": ["financial_sector", "banks", "financials", "xlf"],
    "GLD": ["gold", "precious_metal", "gld"],
    "TLT": ["treasur", "long_bond", "bonds", "federal_reserve", "tlt"],
    "HYG": ["high_yield", "junk_bond", "corporate_bond", "credit", "hyg"],
}


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
# Phase C — knowledge-graph context
# ---------------------------------------------------------------------------

def _ticker_seed_canonicals(ticker: str, entities: list[dict]) -> set[str]:
    """Graph entities whose canonical name fuzzy-matches the ticker."""
    hints = TICKER_ENTITY_HINTS.get(ticker)
    if not hints:
        hints = [ticker.split("-")[0].lower()]
    seeds: set[str] = set()
    for ent in entities:
        canon = (ent.get("canonical") or "").lower()
        if not canon:
            continue
        if any(h in canon or canon in h for h in hints):
            seeds.add(ent["canonical"])
    return seeds


def _fetch_graph_context(ticker: str, graph: dict) -> list[str]:
    """1-2 hop walk of the approved knowledge graph around `ticker`.

    Returns human-readable edge strings (subject --predicate--> object),
    ranked by mention_count*confidence and capped so the prompt stays
    tight. Empty list when the graph has nothing relevant.
    """
    entities = graph.get("entities", [])
    rels = graph.get("relationships", [])
    if not rels:
        return []

    seeds = _ticker_seed_canonicals(ticker, entities)
    if not seeds:
        return []

    hop1: list[dict] = []
    frontier: set[str] = set()
    for r in rels:
        s = r.get("subject_canonical", "")
        o = r.get("object_canonical", "")
        if s in seeds or o in seeds:
            hop1.append(r)
            frontier.add(o if s in seeds else s)

    seen_ids = {r.get("id") for r in hop1}
    hop2 = [
        r for r in rels
        if r.get("id") not in seen_ids
        and (r.get("subject_canonical") in frontier
             or r.get("object_canonical") in frontier)
    ]

    ranked = sorted(
        hop1 + hop2,
        key=lambda r: r.get("mention_count", 1) * r.get("confidence", 0.5),
        reverse=True,
    )[:MAX_GRAPH_EDGES_PER_TICKER]

    return [
        f"{r.get('subject_name') or r.get('subject_canonical')} "
        f"--{r.get('predicate')}--> "
        f"{r.get('object_name') or r.get('object_canonical')} "
        f"({r.get('mention_count', 1)}x)"
        for r in ranked
    ]


def _load_approved_graph() -> dict:
    """Fetch the approved graph once. Never raises — graph context is
    enrichment, not the alerting critical path."""
    try:
        return db.get_graph_for_display(status="approved")
    except Exception as e:
        logger.warning("Knowledge-graph fetch failed (%s); "
                        "continuing without graph context", e)
        return {"entities": [], "relationships": []}


# ---------------------------------------------------------------------------
# Integration phase A — macro-risk background context
# ---------------------------------------------------------------------------

def _fetch_macro_context() -> dict:
    """Latest macro background for the alert narrative.

    Returns a small dict with the BIS credit-to-GDP gap for US and PT
    plus the Eurostat HPI year-on-year for PT. Any of them missing
    just means that ingester hasn't run yet — the corresponding line
    is simply omitted from the prompt.

    Never raises: this is enrichment, the alert itself is the
    critical path.
    """
    out: dict[str, float] = {}
    try:
        gaps = pg.get_latest_by_prefix("BIS_CREDIT_GAP_")
        for country, key in (("BIS_CREDIT_GAP_US", "credit_gap_us"),
                              ("BIS_CREDIT_GAP_PT", "credit_gap_pt")):
            rec = gaps.get(country)
            if rec is not None:
                out[key] = float(rec["value"])
    except Exception as e:
        logger.warning(
            "Macro context: BIS gap fetch failed (%s); continuing", e,
        )

    try:
        yoy = pg.get_yoy_change("EUROSTAT_HPI_PT")
        if yoy is not None:
            out["hpi_pt_yoy_pct"] = yoy
    except Exception as e:
        logger.warning(
            "Macro context: HPI y-o-y fetch failed (%s); continuing", e,
        )

    return out


def _format_macro_instruction(macro: dict) -> str:
    """Build the prompt fragment for whatever macro fields we have."""
    parts: list[str] = []
    if "credit_gap_us" in macro:
        parts.append(f"BIS credit-to-GDP gap US = {macro['credit_gap_us']:+.1f}%")
    if "credit_gap_pt" in macro:
        parts.append(f"BIS credit-to-GDP gap PT = {macro['credit_gap_pt']:+.1f}%")
    if "hpi_pt_yoy_pct" in macro:
        parts.append(
            f"Eurostat HPI Portugal (var. ano-a-ano) = {macro['hpi_pt_yoy_pct']:+.1f}%"
        )
    if not parts:
        return ""
    return (
        "\n\nContexto macro de fundo (nao especifico aos tickers acima):\n- "
        + "\n- ".join(parts)
        + "\nConvencoes: BIS gap >2% = trigger CCyB Basel III, >10% = "
          "maximo historico de bolha de credito. HPI y/y >10% sugere "
          "froth imobiliario. Use na *INTERPRETACAO* SE for relevante "
          "(ex.: alerta inclui financials/HYG e credit gap esta elevado, "
          "ou cluster imobiliario). Nao force."
    )


# ---------------------------------------------------------------------------
# Narrative synthesis (Haiku) + Telegram send
# ---------------------------------------------------------------------------

async def _synthesise_narrative(alerts: list[dict]) -> str:
    graph = _load_approved_graph()
    macro = _fetch_macro_context()

    enriched: list[dict] = []
    any_graph = False
    for a in alerts[:MAX_TICKERS_IN_NARRATIVE]:
        ctx = _fetch_graph_context(a["ticker"], graph)
        if ctx:
            any_graph = True
        enriched.append({
            "ticker": a["ticker"],
            "severity": a["severity"],
            "reasons": a["reasons"],
            "close": a.get("close"),
            "change_pct_30d": a.get("change_pct_30d"),
            "graph_context": ctx,
        })

    payload = json.dumps(enriched, ensure_ascii=False, indent=2)

    graph_instruction = ""
    if any_graph:
        graph_instruction = (
            "\n\nAlguns tickers trazem 'graph_context': relacoes "
            "(subject --predicado--> object) extraidas automaticamente "
            "da cobertura de noticias. Use-as para enriquecer a "
            "*INTERPRETACAO* com cadeias de dependencia/contagio "
            "plausiveis. OBRIGATORIO: ao citar qualquer relacao do "
            "graph_context, deixe explicito que sao padroes MENCIONADOS "
            "na cobertura, NAO relacoes causais comprovadas."
        )

    macro_instruction = _format_macro_instruction(macro)

    prompt = f"""\
Voce e o assistente quantitativo do Jose Carlos. Os tickers abaixo \
cruzaram thresholds de detectores de bolha (LPPL) e/ou explosividade \
estatistica (GSADF). Gere um alerta curto e direto em portugues do Brasil.

Dados:
{payload}{graph_instruction}{macro_instruction}

Estrutura obrigatoria:

*ALERTA QUANT*

Para cada ticker:
*[TICKER]* (severidade)
- Motivos: [lista resumida dos sinais]
- Contexto: [1 frase sobre preco/momentum recente]

*INTERPRETACAO*
[1-2 frases sobre o que isso significa no conjunto. Mencione \
concentracao setorial se aplicavel. Se houver graph_context relevante, \
trace a cadeia de contagio plausivel aqui. Se o contexto macro de \
fundo for relevante (credit gap elevado, froth imobiliario), \
incorpore SEM forcar.]

*ACAO SUGERIDA*
[1 sugestao conservadora: 'considere revisar', 'avalie stop', \
'pondere reducao'. Nao prescritivo, nao alarmista.]

Lembrete obrigatorio no final: 'LPPL e GSADF detectam padroes \
estatisticos, NAO predizem timing exato de correcao. Relacoes do grafo \
sao mencoes na cobertura, nao causalidade comprovada.'

Maximo 300 palavras.\
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
