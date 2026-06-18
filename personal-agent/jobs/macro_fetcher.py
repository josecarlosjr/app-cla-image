"""Macro indicators daily fetcher (Onda 12 Sprint 1, Camada B).

Daily cron entry point. For each of the 5 indicators in
``macro_repository.INDICATORS``, hits the upstream source (FRED for 4,
multpl.com scrape for CAPE), upserts via ``macro_repository`` (idempotent
INSERT OR IGNORE), and emits structured ``log_event`` records.

Invocation:
    python jobs/macro_fetcher.py
(CronJob WORKDIR is ``/app/personal-agent``; the bootstrap below ensures
relative imports work regardless of how the script is launched.)
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime, timezone

# Make sibling modules (macro_repository, log_config) importable when this
# script is launched as ``python jobs/macro_fetcher.py`` from inside
# /app/personal-agent.
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_SELF_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr                    # noqa: E402
from log_config import setup_logging, log_event  # noqa: E402

setup_logging()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared HTTP config + per-indicator defensive value ranges. Ranges live
# here (not in ``macro_repository``) because they are an internal validation
# concern, not part of the public ``GET /api/macro/indicators`` shape.
# ---------------------------------------------------------------------------

_HTTP_UA = "PIA-bot/1.0 (personal-research)"
_HTTP_TIMEOUT = 20.0
_RETRY_WAIT_S = 30.0

_VALUE_RANGES: dict[str, tuple[float, float]] = {
    "cape_shiller": (4.0, 60.0),      # historical real range ~4.78..44.2
    "vix":          (5.0, 150.0),     # VIX peaks ~89 in 2008; 150 = headroom
    "hy_oas":       (1.0, 25.0),      # pct points
    "sp500_close":  (100.0, 20000.0),
    "tnx_yield":    (0.0, 20.0),      # percent
}

# ---------------------------------------------------------------------------
# Shiller CAPE — scraped from multpl.com (Yale XLSX is updated manually and
# lagged >2y; multpl carries the full monthly series 1871->present).
# ---------------------------------------------------------------------------

MULTPL_CAPE_URL = "https://www.multpl.com/shiller-pe/table/by-month"
_CAPE_MIN_ROWS = 1800              # ~155y monthly; if layout broke we'd get few
_CAPE_REQUIRE_YEAR = "2026"        # at least one current-year row must survive


# ---------------------------------------------------------------------------
# FRED — VIX, HY_OAS, SP500, TNX. Single parameterised pattern.
#
# ⚠️ SP500 caveat: per the FRED licensing terms, the SP500 series is
#    capped to ~10 years of daily history. Longer history would require
#    a different source (e.g. ^GSPC via yfinance or Shiller's own price
#    column). We do NOT auto-fallback — the operator decides at PR review.
# ---------------------------------------------------------------------------

_FRED_BASE_URL = "https://api.stlouisfed.org/fred/series/observations"


# ---------------------------------------------------------------------------
# Internal exception used to signal "fetcher already emitted macro_fetch_error
# before raising" — keeps the orchestrator from double-emitting on the same
# failure. Subclass of RuntimeError so callers can still ``except RuntimeError``.
# ---------------------------------------------------------------------------

class _AlreadyLogged(RuntimeError):
    """Marker exception: the fetcher has already emitted ``macro_fetch_error``
    for this failure; the orchestrator should NOT emit a second event."""


def _redact(s: str, api_key: str | None) -> str:
    """Strip the api_key from ``s`` before logging. Safe-by-construction
    helper: every call site that could touch upstream-error text routes
    through this."""
    if api_key and s and api_key in s:
        return s.replace(api_key, "REDACTED")
    return s


# ---------------------------------------------------------------------------
# Fetchers — each returns ``tuple[list[dict], int]``:
#   rows           : ready for ``mr.upsert_observations`` (ASC, validated)
#   dropped_source : upstream rows filtered out at the source
#                    (CAPE: live intra-month row; FRED: ``value == "."``)
# The orchestrator surfaces ``dropped_source`` in the per-run summary so
# source-quality drift is visible. Fetchers raise on hard failure:
#   - ``_AlreadyLogged``  -> macro_fetch_error already emitted (no retry/HTTP)
#   - ``RuntimeError``    -> parse / validation failure (orchestrator emits)
# ---------------------------------------------------------------------------

def _http_get_text(url: str) -> tuple[int, str]:
    """GET ``url`` and return ``(status_code, text)``. Isolated so tests can
    inject a fake fetcher without monkeypatching httpx."""
    import httpx
    resp = httpx.get(
        url, timeout=_HTTP_TIMEOUT, follow_redirects=True,
        headers={"User-Agent": _HTTP_UA},
    )
    return resp.status_code, resp.text


def _parse_multpl_cape(
    html: str,
    scraped_at: str,
    *,
    start: str | None = None,
    min_rows: int = _CAPE_MIN_ROWS,
    value_range: tuple[float, float] | None = None,
    require_year: str | None = _CAPE_REQUIRE_YEAR,
) -> tuple[list[dict], int]:
    """Parse the multpl.com Shiller-PE monthly table into observation rows.

    Keeps only clean monthly observations (``day == 1``); the table's first
    row is an intra-month *live* value dated today, which would otherwise
    create a fresh row each daily run and break ``PRIMARY KEY (indicator,
    ts)`` idempotency. ``dropped_source`` counts the live/non-day-1 rows
    that were filtered out, so source-quality drift is visible in the
    ``macro_fetcher_run`` summary.

    Defensive (raises ``RuntimeError``, nothing inserted): no table present,
    fewer than ``min_rows`` data rows, no row for ``require_year``, or the
    most-recent value outside ``value_range``.
    """
    from bs4 import BeautifulSoup

    lo, hi = value_range if value_range is not None else _VALUE_RANGES["cape_shiller"]
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        raise RuntimeError("multpl CAPE: no <table> found in HTML (layout changed?)")
    # The data table is by far the largest; auxiliary tables are tiny.
    table = max(tables, key=lambda t: len(t.find_all("tr")))

    parsed: list[tuple[str, float, str]] = []  # (iso_ts, value, raw_date)
    data_row_count = 0
    dropped_source = 0
    for tr in table.find_all("tr"):
        cells = [c.get_text(strip=True) for c in tr.find_all(["td", "th"])]
        if len(cells) < 2:
            continue
        raw_date, raw_value = cells[0], cells[1]
        try:
            dt = datetime.strptime(raw_date, "%b %d, %Y")
        except ValueError:
            continue  # header row ("Date") or anything non-date
        data_row_count += 1
        if dt.day != 1:
            dropped_source += 1
            continue  # drop the intra-month live row
        try:
            value = float(raw_value)
        except ValueError:
            dropped_source += 1
            continue
        parsed.append((dt.strftime("%Y-%m-%d"), value, raw_date))

    if data_row_count < min_rows:
        raise RuntimeError(
            f"multpl CAPE: only {data_row_count} data rows (< {min_rows}); "
            "layout likely changed"
        )
    if not parsed:
        raise RuntimeError("multpl CAPE: no monthly (day==1) rows after parse")

    # parsed is descending (table is newest-first); most-recent == parsed[0]
    latest_ts, latest_value, _ = parsed[0]
    if not (lo <= latest_value <= hi):
        raise RuntimeError(
            f"multpl CAPE: latest value {latest_value} ({latest_ts}) outside "
            f"sane range [{lo}, {hi}]"
        )
    if require_year and not any(ts.startswith(require_year) for ts, _, _ in parsed):
        raise RuntimeError(
            f"multpl CAPE: no observation for year {require_year} (stale source?)"
        )

    rows: list[dict] = []
    for iso_ts, value, raw_date in parsed:
        if start and iso_ts < start:
            continue
        rows.append({
            "ts": iso_ts,
            "value": value,
            "metadata": {
                "source": "multpl.com",
                "url": MULTPL_CAPE_URL,
                "scraped_at": scraped_at,
                "raw_date_string": raw_date,
            },
        })
    rows.sort(key=lambda r: r["ts"])  # emit ASC
    return rows, dropped_source


def fetch_shiller_cape(
    *,
    start: str | None = None,
    _fetch=None,
    _retry_wait_s: float = _RETRY_WAIT_S,
) -> tuple[list[dict], int]:
    """Scrape the Shiller CAPE monthly series from multpl.com.

    Transient failures (HTTP non-200 incl. 429, or a network/timeout
    exception) get **one** retry after ``_retry_wait_s``; if the second
    attempt also fails we emit a ``macro_fetch_error`` event and raise
    ``_AlreadyLogged``. Parse/validation failures (see
    :func:`_parse_multpl_cape`) are deterministic — they propagate
    immediately as ``RuntimeError``, no retry. ``_fetch`` is a test seam.
    """
    fetch = _fetch or _http_get_text
    last_status: int | None = None
    last_detail = ""

    for attempt in (1, 2):
        try:
            status, text = fetch(MULTPL_CAPE_URL)
        except Exception as e:  # network/timeout — transient
            last_status, last_detail = None, f"{type(e).__name__}: {e}"
        else:
            if status == 200:
                # Deterministic from here: parse errors propagate (no retry).
                scraped_at = datetime.now(timezone.utc).isoformat()
                return _parse_multpl_cape(text, scraped_at, start=start)
            last_status, last_detail = status, f"HTTP {status}"

        if attempt == 1:
            logger.warning("multpl CAPE transient failure (%s); retrying in %ss",
                           last_detail, _retry_wait_s)
            time.sleep(_retry_wait_s)

    log_event(
        "macro_fetch_error",
        indicator="cape_shiller",
        error="multpl_scrape_failed",
        http_status=last_status,
        detail=last_detail,
    )
    raise _AlreadyLogged(f"multpl_scrape_failed: {last_detail}")


def _http_get_json(base_url: str, params: dict) -> tuple[int, dict | None]:
    """GET ``base_url`` with ``params`` and return ``(status, json | None)``.

    Isolated so tests inject a fake fetcher with the same shape. The
    response body is parsed only on 200; for any other status we return
    ``None`` so the caller treats it as transient/hard without touching
    response bodies that might leak request URLs.
    """
    import httpx
    resp = httpx.get(
        base_url, params=params, timeout=_HTTP_TIMEOUT,
        follow_redirects=True, headers={"User-Agent": _HTTP_UA},
    )
    if resp.status_code == 200:
        try:
            return 200, resp.json()
        except Exception:
            return 200, None
    return resp.status_code, None


def _parse_fred_observations(
    payload: dict | None,
    *,
    indicator: str,
    series_id: str,
    scraped_at: str,
    start: str | None = None,
    value_range: tuple[float, float] | None = None,
) -> tuple[list[dict], int]:
    """Parse a FRED ``/fred/series/observations`` response.

    Per the FRED contract, ``value`` arrives as a STRING and ``"."`` is the
    sentinel for missing observations (weekends, holidays, gaps). Those
    are filtered out and counted in ``dropped_source``. Rows come out
    ts-ASC, tagged with point-in-time metadata
    (``realtime_start``/``realtime_end``) which is the field that makes
    FRED-based backtests honest.

    Defensive (raises ``RuntimeError``, nothing inserted): payload missing
    ``observations``, no numeric rows after filtering, or the most-recent
    value outside ``value_range``.
    """
    if not isinstance(payload, dict) or "observations" not in payload:
        raise RuntimeError(
            f"FRED {series_id}: response missing 'observations' "
            "(API contract changed?)"
        )
    obs = payload.get("observations") or []
    if not isinstance(obs, list):
        raise RuntimeError(f"FRED {series_id}: 'observations' is not a list")

    lo, hi = value_range if value_range is not None else _VALUE_RANGES[indicator]

    rows: list[dict] = []
    dropped_source = 0
    for o in obs:
        raw_value = (o.get("value") or "").strip()
        if raw_value in (".", ""):     # FRED sentinel + empty -> drop
            dropped_source += 1
            continue
        try:
            value = float(raw_value)
        except ValueError:
            dropped_source += 1
            continue
        ts = (o.get("date") or "").strip()
        if not ts:
            dropped_source += 1
            continue
        if start and ts < start:
            continue
        rows.append({
            "ts": ts,
            "value": value,
            "metadata": {
                "source": "fred",
                "series_id": series_id,
                "scraped_at": scraped_at,
                "realtime_start": o.get("realtime_start"),
                "realtime_end": o.get("realtime_end"),
            },
        })

    if not rows:
        raise RuntimeError(
            f"FRED {series_id}: zero numeric observations after filter "
            f"(dropped_source={dropped_source})"
        )

    rows.sort(key=lambda r: r["ts"])  # ASC
    latest = rows[-1]
    if not (lo <= latest["value"] <= hi):
        raise RuntimeError(
            f"FRED {series_id}: latest value {latest['value']} ({latest['ts']}) "
            f"outside sane range [{lo}, {hi}]"
        )
    return rows, dropped_source


def fetch_fred_series(
    indicator: str,
    *,
    start: str | None = None,
    _fetch=None,
    _retry_wait_s: float = _RETRY_WAIT_S,
    _api_key: str | None = None,
) -> tuple[list[dict], int]:
    """Fetch a FRED daily series (vix, hy_oas, sp500_close, tnx_yield).

    Behaviour:
      * HTTP 200      -> parse + return (rows, dropped_source).
      * HTTP 401      -> NO retry (invalid api_key is deterministic);
                          emit ``macro_fetch_error`` + raise ``_AlreadyLogged``.
      * HTTP non-200 or network exception -> ONE retry after
        ``_retry_wait_s``; on second failure emit ``macro_fetch_error`` +
        raise ``_AlreadyLogged``.
      * Parse / validation failure -> raise ``RuntimeError`` (orchestrator emits).

    Security: ``api_key`` is read from ``$FRED_API_KEY`` (or ``_api_key``
    for tests) and NEVER appears in any emitted event — error ``detail``
    strings are routed through :func:`_redact`.

    SP500 caveat: see module docstring; FRED returns only ~10y of SP500.
    """
    cfg = mr.INDICATORS.get(indicator)
    if not cfg or cfg.get("source") != "fred":
        raise ValueError(f"{indicator!r} is not a FRED-sourced indicator")
    series_id = cfg["series_id"]
    api_key = _api_key if _api_key is not None else os.getenv("FRED_API_KEY", "")
    if not api_key:
        log_event(
            "macro_fetch_error",
            indicator=indicator,
            series_id=series_id,
            error="fred_api_key_missing",
        )
        raise _AlreadyLogged(f"fred_api_key_missing[{series_id}]")

    fetch = _fetch or _http_get_json
    params = {"series_id": series_id, "api_key": api_key, "file_type": "json"}
    if start:
        params["observation_start"] = start

    last_status: int | None = None
    last_detail = ""

    for attempt in (1, 2):
        try:
            status, payload = fetch(_FRED_BASE_URL, params)
        except Exception as e:
            last_status = None
            last_detail = _redact(f"{type(e).__name__}: {e}", api_key)
        else:
            if status == 200:
                scraped_at = datetime.now(timezone.utc).isoformat()
                return _parse_fred_observations(
                    payload, indicator=indicator, series_id=series_id,
                    scraped_at=scraped_at, start=start,
                )
            if status == 401:
                # Auth failure is deterministic — re-trying just wastes a request.
                log_event(
                    "macro_fetch_error",
                    indicator=indicator,
                    series_id=series_id,
                    error="fred_unauthorized",
                    http_status=401,
                )
                raise _AlreadyLogged(
                    f"fred_unauthorized[{series_id}]: HTTP 401"
                )
            last_status, last_detail = status, f"HTTP {status}"

        if attempt == 1:
            logger.warning(
                "FRED %s transient failure (%s); retrying in %ss",
                series_id, last_detail, _retry_wait_s,
            )
            time.sleep(_retry_wait_s)

    log_event(
        "macro_fetch_error",
        indicator=indicator,
        series_id=series_id,
        error="fred_fetch_failed",
        http_status=last_status,
        detail=_redact(last_detail, api_key),
    )
    raise _AlreadyLogged(f"fred_fetch_failed[{series_id}]: {last_detail}")


# ---------------------------------------------------------------------------
# Dispatch — keyed exactly to ``macro_repository.INDICATORS``. The
# orchestrator (step 3d) iterates this dict to drive the run.
# ---------------------------------------------------------------------------

_FETCHERS = {
    "cape_shiller": fetch_shiller_cape,
    "vix":         lambda **kw: fetch_fred_series("vix", **kw),
    "hy_oas":      lambda **kw: fetch_fred_series("hy_oas", **kw),
    "sp500_close": lambda **kw: fetch_fred_series("sp500_close", **kw),
    "tnx_yield":   lambda **kw: fetch_fred_series("tnx_yield", **kw),
}


# ---------------------------------------------------------------------------
# Orchestration -- populated in step 3d.
# ---------------------------------------------------------------------------

def run_all(*, start: str | None = None) -> dict:
    """Run every fetcher in :data:`_FETCHERS`, upsert results idempotently,
    emit the structured events agreed at PR #69 (P3 observability).

    Per-indicator on success::

        {"event": "macro_fetch", "indicator": ..., "rows_inserted": N,
         "rows_skipped": N}   # rows_skipped = upsert duplicates + source drops

    Per-indicator on failure: exactly one ``macro_fetch_error`` event — the
    fetcher emits it directly for HTTP/auth paths, or the orchestrator
    emits it here for parse/validation/unexpected exceptions.

    End of run::

        {"event": "macro_fetcher_run", "duration_ms": ...,
         "by_indicator": {...with breakdown per indicator...},
         "totals": {"inserted", "skipped", "dropped_source", "failed"}}

    Returns the same payload as a dict for callers that want it
    programmatically (e.g. backfill script for its tail report).
    """
    t0 = time.perf_counter()
    by_indicator: dict[str, dict] = {}
    totals = {"inserted": 0, "skipped": 0, "dropped_source": 0, "failed": 0}

    for indicator, fetcher in _FETCHERS.items():
        try:
            rows, dropped = fetcher(start=start)
            inserted, dup_skipped = mr.upsert_observations(indicator, rows)
            rows_skipped = dup_skipped + dropped
            log_event(
                "macro_fetch",
                indicator=indicator,
                rows_inserted=inserted,
                rows_skipped=rows_skipped,
            )
            by_indicator[indicator] = {
                "fetched": len(rows),
                "inserted": inserted,
                "skipped_dup": dup_skipped,
                "dropped_source": dropped,
            }
            totals["inserted"] += inserted
            totals["skipped"] += dup_skipped
            totals["dropped_source"] += dropped
        except _AlreadyLogged as e:
            # Fetcher already emitted macro_fetch_error; just tally.
            by_indicator[indicator] = {"error": str(e)}
            totals["failed"] += 1
            logger.warning("%s fetcher failed (logged): %s", indicator, e)
        except Exception as e:
            # Parse / validation / unexpected — orchestrator emits.
            log_event(
                "macro_fetch_error",
                indicator=indicator,
                error=type(e).__name__,
                detail=str(e),
            )
            by_indicator[indicator] = {"error": str(e)}
            totals["failed"] += 1
            logger.warning("%s fetcher failed: %s", indicator, e)

    duration_ms = int((time.perf_counter() - t0) * 1000)
    log_event(
        "macro_fetcher_run",
        duration_ms=duration_ms,
        by_indicator=by_indicator,
        totals=totals,
    )
    return {
        "duration_ms": duration_ms,
        "by_indicator": by_indicator,
        "totals": totals,
    }


if __name__ == "__main__":
    run_all()
