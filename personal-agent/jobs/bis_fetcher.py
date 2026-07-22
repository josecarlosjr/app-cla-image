"""BIS credit-to-GDP fetcher (Onda 12 Sprint C1, Camada B).

Async job entry point. Fetches the 28 BIS indicators in
``macro_repository.INDICATORS`` (14 countries × {narrow gap, ratio}) from
the BIS SDMX-CSV REST API and upserts them via ``macro_repository``.
Idempotent via ``update_on_change`` — a re-run on the same publication
cycle inserts / updates 0 rows.

Design invariants
-----------------
- Zero acoplamento com ``quant_bis.py`` (o outro pipeline BIS, que
  escreve no Postgres/TimescaleDB para o Bubble Engine). Helpers
  ``_bis_period_to_iso`` e ``_bis_parse_sdmx_csv`` são duplicados a
  propósito — se uma das camadas quiser evoluir o parser, a outra não
  é forçada a acompanhar.
- Contrato "fetcher ↔ backfill": ``SUPPORTED_INDICATORS: tuple`` público
  espelha o de ``macro_fetcher.SUPPORTED_INDICATORS``. Um futuro
  ``jobs/bis_backfill.py`` itera por aqui, nunca por ``mr.INDICATORS``
  directamente.
- Bot-wall guard: se BIS devolver HTML (anti-bot típico), a resposta é
  registada como erro e o indicador dropa nesse run — os outros 27
  continuam. Nunca aborta a run inteira por causa de um.
- Zero excepções propagam de ``fetch_one``: qualquer falha é registada
  em ``log_event`` estruturado e devolvida no dict de resultado.

Contrato de rede
----------------
- User-Agent: browser hardcoded (BIS bloqueia UAs default; ver
  ``quant_bis.py`` para o mesmo quirk documentado).
- Auth: nenhuma. API é livre, sem key.
- Retry: 1× em erro de rede OU HTTP 429. Zero retries em 4xx
  deterministicos (dá sinal claro no log em vez de mascarar bug).
- Timeout: 30s por request. Fanout 28× em paralelo via
  ``asyncio.gather`` — BIS não documenta rate limit, comunidade
  reporta throttling em ~5–10 concorrentes; 28 é confortável.

START_PERIOD = "1980" hardcoded (não no catálogo, decisão de Fase 2a):
o backtester futuro da Camada C precisa cobrir Nordic 1990, Asian
1998, DotCom 2000, GFC 2008 — eventos críticos para calibração.
Países com série mais curta (BR pós-1994, CN pós-1985, IN esparsa
pré-2000) devolvem o que há; não rebentam.

Env overrides
-------------
  BIS_API_BASE    override do endpoint (default v1). Ex: v2 SDMX-JSON.
  DATA_DIR        SQLite root — herdado do ``database`` module.

Invocação:
    python jobs/bis_fetcher.py
(CronJob WORKDIR: ``/app/personal-agent``.)
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
import re
import sys
from datetime import datetime, timezone

import httpx

_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_SELF_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr                      # noqa: E402
from log_config import setup_logging, log_event    # noqa: E402

setup_logging()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BIS_API_BASE = os.getenv("BIS_API_BASE", "https://stats.bis.org/api/v1").rstrip("/")

# Range histórico — ver docstring do módulo. Não vive no catálogo porque é
# uma decisão de FETCHING, não do indicador em si.
START_PERIOD = "1980"

# BIS bloqueia httpx-default e requests-default no host de dados (anti-bot).
# Copiado LITERALMENTE de quant_bis.py — coerência interna > vaidade nos logs
# de terceiros. Zero razão para divergir; se BIS um dia apertar o filtro,
# ambas as camadas actualizam num só passo.
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/vnd.sdmx.data+csv, text/csv, */*",
}

_TIMEOUT = 30.0

# Missing markers observados em BIS SDMX-CSV. Case-insensitive.
_MISSING_MARKERS = frozenset({"", "nan", "na", ".", "n/a"})

# BIS quarterly / annual period parsing. BIS emite "YYYY-Qn" mais frequente,
# "YYYYQn" ocasional, "YYYY" nas séries anuais dispersas.
_QUARTER_END = {1: (3, 31), 2: (6, 30), 3: (9, 30), 4: (12, 31)}
_PERIOD_Q = re.compile(r"^(\d{4})-?Q([1-4])$", re.IGNORECASE)
_PERIOD_Y = re.compile(r"^(\d{4})$")


# ---------------------------------------------------------------------------
# Public: indicator set this fetcher handles
# ---------------------------------------------------------------------------
#
# Snapshot filtrado no import — todos os entries de mr.INDICATORS onde
# source=="bis". Iterar por aqui (não por mr.INDICATORS directamente)
# garante que futuras extensões do catálogo com source diferente não
# entram acidentalmente neste fetcher.

SUPPORTED_INDICATORS: tuple[str, ...] = tuple(
    ind for ind, cfg in mr.INDICATORS.items() if cfg["source"] == "bis"
)


# ---------------------------------------------------------------------------
# Helpers (locais — DUPLICADOS de quant_bis.py, não importados)
# ---------------------------------------------------------------------------

def _bis_period_to_iso(period: str) -> str | None:
    """BIS ``TIME_PERIOD`` → ISO 8601 UTC no fim do período.

    ``2024-Q3`` → ``2024-09-30T00:00:00+00:00``.
    ``2024Q3`` (forma compacta) → mesmo output.
    ``2024`` (fallback anual) → ``2024-12-31T00:00:00+00:00``.
    Qualquer coisa não-reconhecida → ``None`` (caller filtra).
    """
    p = (period or "").strip()
    m = _PERIOD_Q.match(p)
    if m:
        year, q = int(m.group(1)), int(m.group(2))
        month, day = _QUARTER_END[q]
        return f"{year:04d}-{month:02d}-{day:02d}T00:00:00+00:00"
    m = _PERIOD_Y.match(p)
    if m:
        return f"{int(m.group(1)):04d}-12-31T00:00:00+00:00"
    return None


def _find_col(fieldnames: list[str], *needles: str) -> str | None:
    """Locate an SDMX-CSV column by case-insensitive substring.

    BIS emite variantes: ``TIME_PERIOD`` vs ``TIME_PERIOD:Time period``,
    ``OBS_VALUE`` vs ``OBS_VALUE:Observation value``. Match por fragmento
    é robusto a ambas.
    """
    for fn in fieldnames:
        low = fn.lower()
        if any(n in low for n in needles):
            return fn
    return None


def _bis_parse_sdmx_csv(text: str) -> list[tuple[str, float]]:
    """Return ``[(iso_ts, value), ...]`` from a BIS SDMX-CSV payload.

    Rows com marker de missing (``""``, ``"NaN"``, ``"NA"``, ``"."``,
    ``"n/a"`` case-insensitive) são silenciosamente dropadas — não é
    falha, é gap legítimo da série.
    """
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    time_col = _find_col(reader.fieldnames, "time_period", "time period")
    val_col = _find_col(reader.fieldnames, "obs_value", "observation value")
    if not time_col or not val_col:
        logger.error(
            "BIS CSV missing expected columns; headers=%s",
            reader.fieldnames,
        )
        return []

    out: list[tuple[str, float]] = []
    for row in reader:
        raw = (row.get(val_col) or "").strip()
        if raw.lower() in _MISSING_MARKERS:
            continue
        ts = _bis_period_to_iso(row.get(time_col, ""))
        if ts is None:
            continue
        try:
            out.append((ts, float(raw)))
        except (ValueError, TypeError):
            continue
    return out


def _is_botwall(body: str, resp: "httpx.Response") -> bool:
    """True se a resposta cheirar a HTML / bot-wall.

    Duas heurísticas em OR: content-type contém "html", ou o body começa
    com "<". Cobre 99% dos casos (redirect a página de erro, WAF a
    devolver HTML, anti-bot a servir Cloudflare challenge).
    """
    ct = (resp.headers.get("content-type") or "").lower()
    if "html" in ct:
        return True
    head = body.lstrip()[:1].lower()
    return head == "<"


# ---------------------------------------------------------------------------
# Single-indicator fetch
# ---------------------------------------------------------------------------

async def fetch_one(
    client: httpx.AsyncClient,
    indicator_id: str,
    *,
    start_period: str | None = None,
) -> dict:
    """Fetch one BIS indicator; upsert to ``macro_indicators`` via
    ``macro_repository``.

    ``start_period`` optional override — defaults to the module-level
    ``START_PERIOD`` constant (``"1980"``). Backfill uses this to accept
    an operator ``--start-period`` CLI argument without mutating the
    module global.

    Nunca levanta. Devolve dict de diagnóstico::

        {"indicator": ..., "ok": bool, "n_obs": int,
         "n_inserted": int, "n_updated": int, "error": str | None}

    Cada falha emite um ``log_event`` estruturado (``bis_fetch_error``,
    ``bis_fetch_botwall``, ``bis_fetch_empty``, ou o happy path
    ``bis_fetch``). O caller (``run()``) agrega.
    """
    if indicator_id not in mr.INDICATORS:
        return {"indicator": indicator_id, "ok": False, "n_obs": 0,
                "n_inserted": 0, "n_updated": 0,
                "error": "unknown_indicator"}
    cfg = mr.INDICATORS[indicator_id]
    if cfg["source"] != "bis":
        return {"indicator": indicator_id, "ok": False, "n_obs": 0,
                "n_inserted": 0, "n_updated": 0,
                "error": "wrong_source"}

    period = start_period if start_period is not None else START_PERIOD
    url = f"{BIS_API_BASE}/data/{cfg['dataflow']}/{cfg['series_key']}/all"
    params = {"format": "csv", "startPeriod": period}

    result = {
        "indicator": indicator_id, "ok": False, "n_obs": 0,
        "n_inserted": 0, "n_updated": 0, "error": None,
    }

    # Retry: 1× em erro de rede OU 429. Zero retries em 4xx determinístico.
    resp = None
    for attempt in (0, 1):
        try:
            resp = await client.get(
                url, params=params, headers=_HEADERS, timeout=_TIMEOUT,
            )
        except httpx.RequestError as e:
            if attempt == 0:
                await asyncio.sleep(1.0)
                continue
            log_event(
                "bis_fetch_error", indicator=indicator_id,
                error="network", detail=str(e)[:200],
            )
            result["error"] = f"network: {e}"[:200]
            return result
        if resp.status_code == 429 and attempt == 0:
            await asyncio.sleep(1.0)
            continue
        break

    if resp is None:
        # Defensive; teoricamente inalcançável dado o loop acima.
        log_event("bis_fetch_error", indicator=indicator_id,
                  error="no_response", detail=None)
        result["error"] = "no_response"
        return result

    if resp.status_code >= 400:
        log_event(
            "bis_fetch_error", indicator=indicator_id,
            error="http_status", status=resp.status_code,
            detail=(resp.text or "")[:120],
        )
        result["error"] = f"http_{resp.status_code}"
        return result

    body = resp.text
    if _is_botwall(body, resp):
        log_event(
            "bis_fetch_botwall", indicator=indicator_id,
            content_type=resp.headers.get("content-type"),
            snippet=body[:120],
        )
        result["error"] = "botwall"
        return result

    obs = _bis_parse_sdmx_csv(body)
    result["n_obs"] = len(obs)
    if not obs:
        # 0 rows num CSV bem formado — série vazia. Não é erro.
        log_event("bis_fetch_empty", indicator=indicator_id)
        result["ok"] = True
        return result

    scraped_at = datetime.now(timezone.utc).isoformat()
    metadata = {
        "source": "bis",
        "dataflow": cfg["dataflow"],
        "series_key": cfg["series_key"],
        "scraped_at": scraped_at,
    }
    rows = [
        {"ts": ts, "value": val, "metadata": metadata}
        for ts, val in obs
    ]
    try:
        ups = mr.upsert_observations(indicator_id, rows)
    except Exception as e:
        log_event(
            "bis_fetch_error", indicator=indicator_id,
            error="upsert_failed", detail=str(e)[:200],
        )
        result["error"] = f"upsert: {e}"[:200]
        return result

    result["n_inserted"] = ups["inserted"]
    result["n_updated"] = ups["updated"]
    result["ok"] = True
    log_event(
        "bis_fetch", indicator=indicator_id, n_obs=len(obs),
        n_inserted=ups["inserted"], n_updated=ups["updated"],
        n_skipped_dup=ups["skipped_dup"],
    )
    return result


# ---------------------------------------------------------------------------
# Full run
# ---------------------------------------------------------------------------

async def run(*, start_period: str | None = None) -> tuple[int, int, list[dict]]:
    """Fetch all 28 supported indicators in parallel; return
    ``(ok_count, error_count, per_indicator_results)``.

    ``start_period`` optional override (see ``fetch_one``); defaults to
    the module constant. Backfill uses it for the ``--start-period`` CLI
    override; the CronJob passes nothing so runs against the default.

    Emite ``bis_fetcher_run`` no fim com totais agregados.
    """
    logger.info(
        "BIS fetch: %d indicators (%s..)",
        len(SUPPORTED_INDICATORS),
        ",".join(SUPPORTED_INDICATORS[:3]),
    )
    t0 = datetime.now(timezone.utc)
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[
            fetch_one(client, ind, start_period=start_period)
            for ind in SUPPORTED_INDICATORS
        ])
    ok = sum(1 for r in results if r["ok"])
    err = len(results) - ok
    total_inserted = sum(r["n_inserted"] for r in results)
    total_updated = sum(r["n_updated"] for r in results)
    dur_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)
    log_event(
        "bis_fetcher_run",
        n_supported=len(SUPPORTED_INDICATORS),
        n_ok=ok, n_error=err,
        total_inserted=total_inserted, total_updated=total_updated,
        duration_ms=dur_ms,
    )
    logger.info(
        "BIS fetch done: %d ok, %d errors, %d inserted, %d updated (%dms)",
        ok, err, total_inserted, total_updated, dur_ms,
    )
    return ok, err, results


def main() -> int:
    ok, err, _ = asyncio.run(run())
    return 0 if err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
