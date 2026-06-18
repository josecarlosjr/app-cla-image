"""Macro indicators daily fetcher (Onda 12 Sprint 1, Camada B).

Daily cron entry point. For each of the 5 indicators in
``macro_repository.INDICATORS``, hits the upstream source (FRED for 4,
Shiller Yale XLSX for CAPE), upserts via ``macro_repository`` (idempotent
INSERT OR IGNORE), and emits structured ``log_event`` records.

Invocation:
    python jobs/macro_fetcher.py
(CronJob WORKDIR is ``/app/personal-agent``; the bootstrap below ensures
relative imports work regardless of how the script is launched.)

This file is the **3a skeleton** — function signatures + dispatch +
entry point in place; the actual fetch logic lands in 3b (Shiller),
3c (FRED) and 3d (orchestration).
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
# Shiller CAPE — scraped from multpl.com (the Yale XLSX is updated manually
# and lagged >2 years; multpl carries the full monthly series 1871->present).
# ---------------------------------------------------------------------------

MULTPL_CAPE_URL = "https://www.multpl.com/shiller-pe/table/by-month"
_HTTP_UA = "PIA-bot/1.0 (personal-research)"
_HTTP_TIMEOUT = 20.0
_RETRY_WAIT_S = 30.0

# Defensive production thresholds (relaxed in tests via the private params).
_CAPE_MIN_ROWS = 1800              # ~155y monthly; if layout broke we'd get few
_CAPE_VALUE_RANGE = (4.0, 60.0)    # historical real range ~4.78..44.2
_CAPE_REQUIRE_YEAR = "2026"        # at least one current-year row must survive


# ---------------------------------------------------------------------------
# Per-source fetchers — each returns ``list[dict]`` ready for
# ``mr.upsert_observations(indicator, rows)``. Row contract:
#     {"ts": "YYYY-MM-DD", "value": float, "metadata": dict | None}
# Fetchers raise on hard failure; the orchestrator catches and logs a
# ``macro_fetch_error`` event so a single bad source doesn't kill the run.
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
    value_range: tuple[float, float] = _CAPE_VALUE_RANGE,
    require_year: str | None = _CAPE_REQUIRE_YEAR,
) -> list[dict]:
    """Parse the multpl.com Shiller-PE monthly table into observation rows.

    Keeps only clean monthly observations (``day == 1``); the table's first
    row is an intra-month *live* value dated today, which would otherwise
    create a fresh row each daily run and break ``PRIMARY KEY (indicator,
    ts)`` idempotency. Rows come out ts-ASC.

    Defensive (raises ``RuntimeError``, nothing inserted): no table present,
    fewer than ``min_rows`` data rows, no row for ``require_year``, or the
    most-recent value outside ``value_range``.
    """
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table")
    if not tables:
        raise RuntimeError("multpl CAPE: no <table> found in HTML (layout changed?)")
    # The data table is by far the largest; auxiliary tables are tiny.
    table = max(tables, key=lambda t: len(t.find_all("tr")))

    parsed: list[tuple[str, float, str]] = []  # (iso_ts, value, raw_date)
    data_row_count = 0
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
            continue  # drop the intra-month live row
        try:
            value = float(raw_value)
        except ValueError:
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
    lo, hi = value_range
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
    return rows


def fetch_shiller_cape(
    *,
    start: str | None = None,
    _fetch=None,
    _retry_wait_s: float = _RETRY_WAIT_S,
) -> list[dict]:
    """Scrape the Shiller CAPE monthly series from multpl.com.

    Transient failures (HTTP non-200 incl. 429, or a network/timeout
    exception) get **one** retry after ``_retry_wait_s``; if the second
    attempt also fails we emit a ``macro_fetch_error`` event and raise
    ``RuntimeError``. Parse/validation failures (see
    :func:`_parse_multpl_cape`) are deterministic — they propagate
    immediately, no retry. ``_fetch`` is a test seam: a callable
    ``url -> (status_code, text)``.
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
    raise RuntimeError(f"multpl_scrape_failed: {last_detail}")


def fetch_fred_series(indicator: str, *, start: str | None = None) -> list[dict]:
    """Fetch a FRED daily series (one of vix, hy_oas, sp500_close,
    tnx_yield). Returns rows tagged with metadata
    ``{series_id, realtime_start, realtime_end}`` from FRED's per-row
    revisions. Raises ``RuntimeError`` on FRED error/timeout.
    **Implemented in step 3c.**"""
    raise NotImplementedError("step 3c -- FRED fetcher")


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
    """Run every fetcher, upsert results, emit per-indicator
    ``macro_fetch`` events, a final ``macro_fetcher_run`` summary, and
    a ``macro_fetch_error`` per failing source. Returns
    ``{by_indicator: {...}, totals: {inserted, skipped, failed},
    duration_ms: int}``. **Implemented in step 3d.**"""
    raise NotImplementedError("step 3d -- orchestrator")


if __name__ == "__main__":
    run_all()
