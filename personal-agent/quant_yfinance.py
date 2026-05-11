"""Yahoo Finance ingestion — OHLCV bars + valuation snapshots.

Pulls daily OHLCV bars for the watchlist into `quant_bars`, plus a
per-run valuation snapshot (P/E, P/B, P/S, market cap) into
`quant_valuations`. Both are TimescaleDB hypertables.

yfinance scrapes Yahoo's web endpoints — no auth, but rate-limited
aggressively. Be conservative with frequency (once a day after US close
is enough) and add a small sleep between tickers.

Incremental strategy:
  - First run for a ticker → backfills `INITIAL_HISTORY_YEARS` of history.
  - Subsequent runs → only fetches from `last_bar_ts + 1 day` onwards.
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone

import pandas as pd
import yfinance as yf

from pg_database import last_bar_ts, upsert_bars, upsert_valuations
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


# Watchlist — broad indexes, sector ETFs, crypto, bonds, credit, gold.
# Mix chosen so the cross-asset correlation breakdown that often
# precedes crises is visible (e.g. SPY-TLT correlation flipping
# positive = textbook regime change).
WATCHLIST = [
    "SPY",      # S&P 500 ETF (broad equity)
    "QQQ",      # Nasdaq 100 ETF (tech-heavy)
    "IWM",      # Russell 2000 ETF (small caps)
    "BTC-USD",  # Bitcoin
    "ETH-USD",  # Ethereum
    "XLK",      # Technology sector SPDR
    "XLE",      # Energy sector SPDR
    "XLF",      # Financial sector SPDR
    "GLD",      # Gold (safe haven)
    "TLT",      # 20+ Year Treasury (duration / safe haven)
    "HYG",      # High-yield corporate credit
]

INITIAL_HISTORY_YEARS = 10
SLEEP_BETWEEN_TICKERS = 1.0  # seconds — be polite to Yahoo


def _ingest_bars(ticker: str) -> int:
    last_ts = last_bar_ts(ticker)
    now = datetime.now(timezone.utc)

    if last_ts:
        # Incremental — from day after the last stored bar.
        last_dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
        start = (last_dt + timedelta(days=1)).strftime("%Y-%m-%d")
    else:
        # Initial — back-fill INITIAL_HISTORY_YEARS years.
        start = (now - timedelta(days=365 * INITIAL_HISTORY_YEARS)).strftime("%Y-%m-%d")

    end = now.strftime("%Y-%m-%d")
    if start >= end:
        logger.info("%s: up to date (last bar %s)", ticker, last_ts)
        return 0

    try:
        df = yf.download(
            ticker,
            start=start,
            end=end,
            progress=False,
            auto_adjust=False,
            threads=False,  # one-by-one ticker
        )
    except Exception as e:
        logger.error("%s: yfinance download failed: %s", ticker, e)
        return 0

    if df is None or df.empty:
        logger.warning("%s: no data returned for [%s, %s)", ticker, start, end)
        return 0

    # yfinance returns a multi-level column index when downloading
    # multiple tickers; with a single ticker it's flat. Normalise:
    if isinstance(df.columns, pd.MultiIndex):
        df.columns = df.columns.get_level_values(0)

    rows: list[tuple] = []
    for idx, r in df.iterrows():
        ts_dt = idx.to_pydatetime()
        if ts_dt.tzinfo is None:
            ts_dt = ts_dt.replace(tzinfo=timezone.utc)
        ts_iso = ts_dt.isoformat()
        close = r.get("Close")
        if pd.isna(close):
            continue
        rows.append((
            ticker,
            ts_iso,
            float(r["Open"]) if pd.notna(r.get("Open")) else None,
            float(r["High"]) if pd.notna(r.get("High")) else None,
            float(r["Low"]) if pd.notna(r.get("Low")) else None,
            float(close),
            int(r["Volume"]) if pd.notna(r.get("Volume")) else None,
        ))

    n = upsert_bars(rows)
    logger.info("%s: ingested %d bars [%s..%s)", ticker, n, start, end)
    return n


def _ingest_valuations(ticker: str) -> int:
    """One snapshot per run of the fundamentals from yfinance's info dict.

    Not every ticker has every field — crypto pairs only have market_cap
    via the spot price * supply; sector ETFs have ratios but not all.
    yfinance returns None for missing fields; we pass that through.
    """
    try:
        info = yf.Ticker(ticker).info
    except Exception as e:
        logger.warning("%s: info fetch failed: %s", ticker, e)
        return 0

    ts = datetime.now(timezone.utc).isoformat()
    row = (
        ticker,
        ts,
        info.get("trailingPE"),
        info.get("priceToBook"),
        info.get("priceToSalesTrailing12Months"),
        # CAPE Shiller — not in yfinance, computed separately later
        # from real-earnings data. Placeholder for now.
        None,
        info.get("marketCap"),
    )
    return upsert_valuations([row])


def main() -> None:
    logger.info(
        "Yahoo Finance ingestion: %d tickers, initial backfill %dy",
        len(WATCHLIST),
        INITIAL_HISTORY_YEARS,
    )

    bars_total = 0
    val_total = 0
    for i, ticker in enumerate(WATCHLIST):
        bars_total += _ingest_bars(ticker)
        val_total += _ingest_valuations(ticker)
        # Don't sleep after the last one.
        if i < len(WATCHLIST) - 1:
            time.sleep(SLEEP_BETWEEN_TICKERS)

    logger.info(
        "Yahoo Finance ingestion done: %d bars, %d valuation snapshots",
        bars_total, val_total,
    )


if __name__ == "__main__":
    main()
