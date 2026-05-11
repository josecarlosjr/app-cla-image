"""FRED macro indicator ingestion.

Pulls a small, curated set of Federal Reserve Economic Data series into
`quant_indicators` (TimescaleDB hypertable). The series chosen are the
ones a bubble/recession detector actually uses:

  Yield curve   T10Y3M, T10Y2Y       — inversion is the cleanest
                                       recession indicator (NY Fed model)
  Credit        BAMLH0A0HYM2         — HY OAS, flight-to-quality signal
                BAMLC0A4CBBB         — BBB IG OAS
  Liquidity     M2SL, DFF            — money supply, fed funds rate
  Real          UNRATE, CPIAUCSL,    — unemployment, inflation, IP
                INDPRO
  Volatility    VIXCLS               — VIX close
  Equity        WILL5000IND          — Wilshire 5000 (Buffett indicator
                                       numerator vs. GDP)
  GDP           GDP, PCE, DGORDER    — quarterly real economy data

Runs as a CronJob every 6h. FRED data updates slowly (most series are
daily/monthly/quarterly), so re-running is mostly cheap re-confirms.
Anonymous FRED is limited to 120 req/min; with a free key (registered
at fredaccount.stlouisfed.org/apikey) it's 6000/hr — plenty.

Env vars:
  FRED_API_KEY  — required; the cron fails fast without it.
  DATABASE_URL  — postgres connection, from postgres-secrets.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import httpx

from pg_database import upsert_indicators
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

FRED_API_KEY = os.getenv("FRED_API_KEY")
FRED_BASE = "https://api.stlouisfed.org/fred/series/observations"

# Curated to ~15 series; enough to build the recession/bubble detectors
# without flooding the table with macro data we don't yet use.
SERIES = [
    "T10Y3M",        # 10Y - 3M Treasury yield spread
    "T10Y2Y",        # 10Y - 2Y Treasury yield spread
    "BAMLH0A0HYM2",  # High-yield option-adjusted spread
    "BAMLC0A4CBBB",  # BBB Investment Grade OAS
    "M2SL",          # M2 money supply (monthly)
    "DFF",           # Federal funds rate (daily)
    "FEDFUNDS",      # Federal funds rate (monthly avg)
    "UNRATE",        # Unemployment rate
    "CPIAUCSL",      # CPI all urban consumers
    "INDPRO",        # Industrial production index
    "VIXCLS",        # VIX close
    "WILL5000IND",   # Wilshire 5000 total market index
    "GDP",           # Nominal GDP (quarterly)
    "PCE",           # Personal Consumption Expenditures
    "DGORDER",       # Durable goods orders
]

# Look-back window per run. FRED publishes revisions, so re-fetching the
# last 90 days lets late revisions overwrite earlier values via the
# UPSERT. First run still picks up all recent data; the full historical
# backfill should be done separately (one-off, not from this cron).
LOOKBACK_DAYS = 90


async def fetch_series(
    client: httpx.AsyncClient,
    series_id: str,
    start_iso: str,
) -> list[tuple[str, str, float]]:
    """Return [(series_id, ts ISO, value), ...] for one series."""
    params = {
        "series_id": series_id,
        "api_key": FRED_API_KEY,
        "file_type": "json",
        "observation_start": start_iso,
    }
    try:
        resp = await client.get(FRED_BASE, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.error("FRED %s fetch failed: %s", series_id, e)
        return []

    rows: list[tuple[str, str, float]] = []
    for obs in data.get("observations", []):
        # FRED encodes missing values as a literal "."
        if obs.get("value") in (".", "", None):
            continue
        try:
            value = float(obs["value"])
        except (ValueError, TypeError):
            continue
        # FRED dates are YYYY-MM-DD with no TZ; treat as UTC midnight.
        ts = f"{obs['date']}T00:00:00+00:00"
        rows.append((series_id, ts, value))
    logger.info("FRED %s: %d observations", series_id, len(rows))
    return rows


async def main() -> None:
    if not FRED_API_KEY:
        logger.error(
            "FRED_API_KEY missing — register a free key at "
            "fredaccount.stlouisfed.org/apikey and add it to agent-secrets",
        )
        return

    start = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime(
        "%Y-%m-%d",
    )
    logger.info(
        "FRED ingestion: %d series, lookback from %s", len(SERIES), start,
    )

    async with httpx.AsyncClient() as client:
        # Parallel fetch — FRED's rate limit (6000/hr with key) is far
        # above our load (15 requests / 6h = 60/day).
        results = await asyncio.gather(
            *[fetch_series(client, s, start) for s in SERIES],
            return_exceptions=False,
        )

    all_rows = [row for rows in results for row in rows]
    n = upsert_indicators(all_rows)
    logger.info(
        "FRED ingestion done: %d total observations upserted across %d series",
        n, len(SERIES),
    )


if __name__ == "__main__":
    asyncio.run(main())
