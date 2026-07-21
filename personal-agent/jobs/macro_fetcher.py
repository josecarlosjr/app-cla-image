"""Macro indicators daily fetcher (Onda 12 Sprint 1, Camada B).

Daily cron entry point. For each of the 5 indicators in
``SUPPORTED_INDICATORS`` (the FRED + Shiller subset of the wider
``macro_repository.INDICATORS`` catalog — BIS credit-to-GDP entries are
handled by ``jobs/bis_fetcher.py``), hits the upstream source (FRED for
4, multpl.com scrape for CAPE), upserts via ``macro_repository``
(idempotent INSERT OR IGNORE / update_on_change), and emits structured
``log_event`` records.

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
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

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
# Fetcher return shape — two distinct drop counters so source-quality drift
# (bad upstream data) doesn't get conflated with policy filtering (data we
# intentionally don't insert):
#
#   dropped_source : upstream row was malformed / missing / sentinel
#                    (FRED "." / empty / non-numeric / no date; CAPE
#                    non-numeric value in a parseable date row)
#   dropped_policy : upstream row was well-formed, but our policy filters
#                    it out (CAPE: live intra-month row whose ts == today,
#                    dropped so PRIMARY KEY (indicator, ts) stays idempotent
#                    across daily runs)
# ---------------------------------------------------------------------------

class FetchResult(NamedTuple):
    rows: list[dict]
    dropped_source: int = 0
    dropped_policy: int = 0


# ---------------------------------------------------------------------------
# Shared HTTP config + per-indicator defensive value ranges. Ranges live
# here (not in ``macro_repository``) because they are an internal validation
# concern, not part of the public ``GET /api/macro/indicators`` shape.
# ---------------------------------------------------------------------------

_HTTP_UA = "PIA-bot/1.0 (personal-research)"
_HTTP_TIMEOUT = 20.0
_RETRY_WAIT_S = 30.0

_VALUE_RANGES: dict[str, tuple[float, float]] = {
    "cape_shiller": (4.0, 60.0),
    "vix":          (5.0, 150.0),
    "hy_oas":       (1.0, 25.0),
    "sp500_close":  (100.0, 20000.0),
    "tnx_yield":    (0.0, 20.0),
}

# Run modes — see :func:`run_all`.
MODE_DAILY = "daily"
MODE_BACKFILL = "backfill"
_DEFAULT_LOOKBACK_DAYS = 7   # >= 5 per the spec; covers weekends + 1-day buffer

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
# ⚠️ History caps (FRED-side, NOT bugs in our code — see macro_repository
#    catalog comments for the exact phrasing on each entry):
#
#    SP500 (S&P / Dow Jones licensing) — capped at ~10 years of daily
#       history. Long-history alternatives: ^GSPC via yfinance, or
#       Shiller's SP500 price column on multpl.
#
#    HY_OAS / any ICE BofA series — a FRED licensing change around
#       April 2026 capped the entire ICE BofA family to a rolling ~3-year
#       window. HY_OAS is currently the only ICE BofA series we use; the
#       underlying series starts 1996-12-31 but FRED returns only the
#       trailing ~3y. Long-history alternatives: ICE direct, Bloomberg.
#
#    VIX (CBOE → FRED) and TNX/DGS10 (Treasury → FRED) are unaffected;
#    both return their full series (1990->, 1962-> respectively).
#
#    No auto-fallback for either cap — alternatives are operator decisions
#    at PR review (not silent vendor swaps).
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
    fatal_on_empty: bool = True,
    min_rows: int = _CAPE_MIN_ROWS,
    value_range: tuple[float, float] | None = None,
    require_year: str | None = _CAPE_REQUIRE_YEAR,
) -> FetchResult:
    """Parse the multpl.com Shiller-PE monthly table into a :class:`FetchResult`.

    Drop-counter discipline:
      * ``dropped_policy`` += 1 for the intra-month live row (``day != 1``)
        — well-formed but intentionally not persisted, so PRIMARY KEY
        ``(indicator, ts)`` stays idempotent across daily runs.
      * ``dropped_source`` += 1 for a parseable date row whose value is
        not a float (upstream data integrity).

    Fatality discipline:
      * Always raises ``RuntimeError`` on hard layout issues (no table,
        too few data rows, missing current year, latest value out of
        range). These are NOT empty-data — they're real problems.
      * "No monthly rows survived after parse + start filter" is treated
        as **empty** rather than fatal when ``fatal_on_empty=False``,
        which is what the daily mode wants (an empty short window is
        normal, not a failure).
    """
    from bs4 import BeautifulSoup

    lo, hi = value_range if value_range is not None else _VALUE_RANGES["cape_shiller"]
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        raise RuntimeError("multpl CAPE: no <table> found in HTML (layout changed?)")
    table = max(tables, key=lambda t: len(t.find_all("tr")))

    parsed: list[tuple[str, float, str]] = []
    data_row_count = 0
    dropped_source = 0
    dropped_policy = 0
    for tr in table.find_all("tr"):
        cells = [c.get_text(strip=True) for c in tr.find_all(["td", "th"])]
        if len(cells) < 2:
            continue
        raw_date, raw_value = cells[0], cells[1]
        try:
            dt = datetime.strptime(raw_date, "%b %d, %Y")
        except ValueError:
            continue  # header / non-date row — not a data row
        data_row_count += 1
        if dt.day != 1:
            dropped_policy += 1   # the live intra-month row
            continue
        try:
            value = float(raw_value)
        except ValueError:
            dropped_source += 1   # data row with non-numeric value
            continue
        parsed.append((dt.strftime("%Y-%m-%d"), value, raw_date))

    if data_row_count < min_rows:
        raise RuntimeError(
            f"multpl CAPE: only {data_row_count} data rows (< {min_rows}); "
            "layout likely changed"
        )
    if not parsed:
        # No clean monthly rows at all — that IS a layout/source issue
        # regardless of mode, since we know the table has >=1800 data rows.
        raise RuntimeError("multpl CAPE: no monthly (day==1) rows after parse")

    latest_ts, latest_value, _ = parsed[0]   # descending table
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
    rows.sort(key=lambda r: r["ts"])  # ASC

    if not rows and fatal_on_empty:
        raise RuntimeError(
            f"multpl CAPE: zero rows in requested window "
            f"(start={start!r}, dropped_policy={dropped_policy})"
        )

    return FetchResult(rows, dropped_source, dropped_policy)


def fetch_shiller_cape(
    *,
    start: str | None = None,
    fatal_on_empty: bool = True,
    _fetch=None,
    _retry_wait_s: float = _RETRY_WAIT_S,
) -> FetchResult:
    """Scrape the Shiller CAPE monthly series from multpl.com.

    Transient failures (HTTP non-200 incl. 429, or a network/timeout
    exception) get **one** retry after ``_retry_wait_s``; on exhaustion
    we emit ``macro_fetch_error`` and raise ``_AlreadyLogged``.
    Parse/validation failures from :func:`_parse_multpl_cape` are
    deterministic and propagate as ``RuntimeError``. ``fatal_on_empty``
    is forwarded to the parser so daily-mode empty windows aren't fatal.
    """
    fetch = _fetch or _http_get_text
    last_status: int | None = None
    last_detail = ""

    for attempt in (1, 2):
        try:
            status, text = fetch(MULTPL_CAPE_URL)
        except Exception as e:
            last_status, last_detail = None, f"{type(e).__name__}: {e}"
        else:
            if status == 200:
                scraped_at = datetime.now(timezone.utc).isoformat()
                return _parse_multpl_cape(
                    text, scraped_at, start=start, fatal_on_empty=fatal_on_empty,
                )
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
    fatal_on_empty: bool = True,
    value_range: tuple[float, float] | None = None,
) -> FetchResult:
    """Parse a FRED ``/fred/series/observations`` response.

    Drop-counter discipline:
      * ``dropped_source`` += 1 for FRED's missing-observation sentinel
        ``"."``, empty value, non-numeric value, or empty date.
      * ``dropped_policy`` = 0 (FRED has no policy filtering — every
        well-formed numeric row is persisted as-is).

    Fatality discipline:
      * Always raises ``RuntimeError`` for hard layout / contract issues
        (missing ``observations`` key, not-a-list, latest value out of
        range). These signal upstream regression, not empty data.
      * "No numeric rows after filter" raises only when
        ``fatal_on_empty=True``; daily mode passes ``False`` so a
        weekend/holiday window simply yields an empty result.
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
        if raw_value in (".", ""):
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
        if fatal_on_empty:
            raise RuntimeError(
                f"FRED {series_id}: zero numeric observations after filter "
                f"(dropped_source={dropped_source})"
            )
        return FetchResult([], dropped_source, 0)

    rows.sort(key=lambda r: r["ts"])  # ASC
    latest = rows[-1]
    if not (lo <= latest["value"] <= hi):
        raise RuntimeError(
            f"FRED {series_id}: latest value {latest['value']} ({latest['ts']}) "
            f"outside sane range [{lo}, {hi}]"
        )
    return FetchResult(rows, dropped_source, 0)


def fetch_fred_series(
    indicator: str,
    *,
    start: str | None = None,
    fatal_on_empty: bool = True,
    _fetch=None,
    _retry_wait_s: float = _RETRY_WAIT_S,
    _api_key: str | None = None,
) -> FetchResult:
    """Fetch a FRED daily series (vix, hy_oas, sp500_close, tnx_yield).

    Behaviour:
      * HTTP 200      -> parse + return ``FetchResult``.
      * HTTP 401      -> NO retry (auth is deterministic); 1
                          ``macro_fetch_error`` + raise ``_AlreadyLogged``.
      * HTTP non-200 / network exception -> ONE retry after
        ``_retry_wait_s``; on exhaustion 1 ``macro_fetch_error`` + raise
        ``_AlreadyLogged``.
      * Parse / validation failure -> raise ``RuntimeError`` (orchestrator
        emits ``macro_fetch_error``).

    Security: ``api_key`` is read from ``$FRED_API_KEY`` (or ``_api_key``
    for tests) and NEVER appears in any emitted event — error ``detail``
    strings are routed through :func:`_redact`.

    History caps: see module docstring. FRED returns only ~10y of SP500
    (S&P licensing) and only ~3y of any ICE BofA series including HY_OAS
    (April 2026 licensing change). VIX / DGS10 are unaffected.
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
                    fatal_on_empty=fatal_on_empty,
                )
            if status == 401:
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

# Public alias — the indicator ids that THIS fetcher handles. Callers
# outside this module (macro_backfill; future observability probes)
# should iterate this set, NOT ``mr.INDICATORS`` directly. Sprint C1
# adds BIS credit-to-GDP entries to ``mr.INDICATORS`` that live behind
# a DIFFERENT fetcher (``jobs/bis_fetcher.py``); iterating the whole
# catalog would report those under macro-fetcher accounting and shift
# the backfill exit-code threshold. Immutable snapshot at import time.
SUPPORTED_INDICATORS: tuple[str, ...] = tuple(_FETCHERS)


# ---------------------------------------------------------------------------
# Orchestration -- populated in step 3d.
# ---------------------------------------------------------------------------

def run_all(
    *,
    mode: str = MODE_DAILY,
    start: str | None = None,
    lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
) -> dict:
    """Run every fetcher in :data:`_FETCHERS`, upsert idempotently, emit
    the structured events agreed at PR #69.

    Modes
    -----
    ``mode="daily"`` (default, used by the CronJob):
        * ``fatal_on_empty=False`` — an empty window is a warning, not a
          failure (e.g. weekend FRED days, monthly CAPE between releases).
        * When ``start`` is not given, defaults to ``today - lookback_days``.
        * Exit code 0 unless **every** indicator errored.
    ``mode="backfill"`` (used by ``jobs/macro_backfill.py``):
        * ``fatal_on_empty=True`` — empty result is a real failure since
          full history was requested.
        * ``start`` is forwarded as-is (``None`` -> full history).

    Per-indicator events
    --------------------
    On success::

        {"event": "macro_fetch", "indicator": ..., "rows_inserted": N,
         "rows_skipped": N}      # = upsert duplicates + dropped_source + dropped_policy

    On failure: exactly one ``macro_fetch_error`` event — the fetcher
    emits it directly for HTTP/auth paths, or the orchestrator emits it
    here for parse/validation/unexpected exceptions (gated by
    ``_AlreadyLogged`` so we never double-log).

    Run summary
    -----------
    Final event::

        {"event": "macro_fetcher_run", "mode": ..., "window_start": ...,
         "duration_ms": ...,
         "by_indicator": {ind: {fetched, inserted, skipped_dup,
                                 dropped_source, dropped_policy} | {error}},
         "totals": {inserted, skipped, dropped_source, dropped_policy, failed}}
    """
    if mode not in (MODE_DAILY, MODE_BACKFILL):
        raise ValueError(f"unknown mode {mode!r}; use 'daily' or 'backfill'")
    fatal_on_empty = (mode == MODE_BACKFILL)
    if mode == MODE_DAILY and start is None:
        lb = max(5, int(lookback_days))
        start = (datetime.now(timezone.utc) - timedelta(days=lb)).strftime("%Y-%m-%d")

    t0 = time.perf_counter()
    by_indicator: dict[str, dict] = {}
    totals = {
        "inserted": 0, "updated": 0, "skipped": 0,
        "dropped_source": 0, "dropped_policy": 0, "failed": 0,
    }

    for indicator, fetcher in _FETCHERS.items():
        try:
            result = fetcher(start=start, fatal_on_empty=fatal_on_empty)
            rows = result.rows
            # Per-indicator write semantics are decided by the catalog
            # entry (cape_shiller -> update_on_change; FRED -> ignore).
            ups = mr.upsert_observations(indicator, rows)
            inserted = ups["inserted"]
            updated = ups["updated"]
            dup_skipped = ups["skipped_dup"]
            rows_skipped = dup_skipped + result.dropped_source + result.dropped_policy
            log_event(
                "macro_fetch",
                indicator=indicator,
                rows_inserted=inserted,
                rows_updated=updated,
                rows_skipped=rows_skipped,
            )
            by_indicator[indicator] = {
                "fetched": len(rows),
                "inserted": inserted,
                "updated": updated,
                "skipped_dup": dup_skipped,
                "dropped_source": result.dropped_source,
                "dropped_policy": result.dropped_policy,
            }
            totals["inserted"] += inserted
            totals["updated"] += updated
            totals["skipped"] += dup_skipped
            totals["dropped_source"] += result.dropped_source
            totals["dropped_policy"] += result.dropped_policy
        except _AlreadyLogged as e:
            by_indicator[indicator] = {"error": str(e)}
            totals["failed"] += 1
            logger.warning("%s fetcher failed (logged): %s", indicator, e)
        except Exception as e:
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
        mode=mode,
        window_start=start,
        duration_ms=duration_ms,
        by_indicator=by_indicator,
        totals=totals,
    )
    return {
        "mode": mode,
        "window_start": start,
        "duration_ms": duration_ms,
        "by_indicator": by_indicator,
        "totals": totals,
    }


if __name__ == "__main__":
    # Daily mode is the default CronJob entry. Exit code:
    #   0 -> at least one indicator succeeded (partial failure tolerated)
    #   1 -> every indicator failed (the run is useless to the operator)
    _summary = run_all(mode=MODE_DAILY)
    _n_total = len(_FETCHERS)
    _n_failed = _summary["totals"]["failed"]
    sys.exit(0 if _n_failed < _n_total else 1)
