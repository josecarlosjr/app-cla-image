"""Postgres / TimescaleDB connection helper for the quant ingestion path.

Mirrors `database.py` (which talks to SQLite) but for the new postgres
instance that holds time-series data — articles/patterns/graph stay in
SQLite, quant_* lives in postgres. The hybrid is deliberate: SQLite is
read-heavy and stays where it is; postgres absorbs the high-frequency
writes that bubble detection will need.

Connection string resolution order:

  1. `DATABASE_URL` env var (preferred — it's what the postgres-secrets
     Secret exposes as a single line, no parsing needed).
  2. Composed from individual parts (`PIA_DB_USER`, `PIA_DB_PASSWORD`,
     `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`). Useful when
     overriding a single component for testing.
  3. Fail with a clear error — never silently fall back to a default
     that could connect somewhere unintended.
"""

import logging
import os
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

logger = logging.getLogger(__name__)


def _build_dsn() -> str:
    dsn = os.getenv("DATABASE_URL")
    if dsn:
        return dsn

    user = os.getenv("PIA_DB_USER")
    pwd = os.getenv("PIA_DB_PASSWORD")
    host = os.getenv("POSTGRES_HOST", "postgres")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "agent")

    if not (user and pwd):
        raise RuntimeError(
            "Postgres credentials missing: set DATABASE_URL, or both "
            "PIA_DB_USER and PIA_DB_PASSWORD."
        )
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


DSN = _build_dsn()


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
    """Open a short-lived connection. Caller owns the transaction.

    Use as:

        with pg.connect() as conn, conn.cursor() as cur:
            cur.execute("...")
            conn.commit()
    """
    conn = psycopg.connect(DSN, row_factory=dict_row)
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# quant_indicators (FRED scalar series)
# ---------------------------------------------------------------------------

def upsert_indicators(rows: list[tuple[str, str, float]]) -> int:
    """Bulk upsert of (series_id, ts ISO, value) into quant_indicators."""
    if not rows:
        return 0
    with connect() as conn, conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO quant_indicators (series_id, ts, value)
               VALUES (%s, %s, %s)
               ON CONFLICT (series_id, ts)
               DO UPDATE SET value = EXCLUDED.value""",
            rows,
        )
        conn.commit()
        return len(rows)


# ---------------------------------------------------------------------------
# quant_bars (OHLCV per ticker)
# ---------------------------------------------------------------------------

def upsert_bars(rows: list[tuple]) -> int:
    """Bulk upsert (ticker, ts, open, high, low, close, volume)."""
    if not rows:
        return 0
    with connect() as conn, conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO quant_bars (ticker, ts, open, high, low, close, volume)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (ticker, ts) DO UPDATE SET
                   open   = EXCLUDED.open,
                   high   = EXCLUDED.high,
                   low    = EXCLUDED.low,
                   close  = EXCLUDED.close,
                   volume = EXCLUDED.volume""",
            rows,
        )
        conn.commit()
        return len(rows)


def last_bar_ts(ticker: str) -> str | None:
    """Most recent ts for a ticker, ISO format. None if never seen.

    Used by the yfinance cronjob to do an incremental pull — first run
    backfills 10 years, subsequent runs pull only from last_ts+1.
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT MAX(ts) AS ts FROM quant_bars WHERE ticker = %s",
            (ticker,),
        )
        row = cur.fetchone()
        return row["ts"].isoformat() if row and row["ts"] else None


# ---------------------------------------------------------------------------
# quant_valuations (per-ticker P/E, P/B, P/S, market cap snapshots)
# ---------------------------------------------------------------------------

def upsert_valuations(rows: list[tuple]) -> int:
    if not rows:
        return 0
    with connect() as conn, conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO quant_valuations
                   (ticker, ts, pe, pb, ps, cape, market_cap)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (ticker, ts) DO UPDATE SET
                   pe         = EXCLUDED.pe,
                   pb         = EXCLUDED.pb,
                   ps         = EXCLUDED.ps,
                   cape       = EXCLUDED.cape,
                   market_cap = EXCLUDED.market_cap""",
            rows,
        )
        conn.commit()
        return len(rows)


# ---------------------------------------------------------------------------
# quant_features (detector output: LPPL, GSADF, recession score, ...)
# ---------------------------------------------------------------------------

def upsert_feature(
    feature_id: str,
    target: str,
    ts: str,
    value: float,
    meta: dict | None = None,
) -> None:
    """Upsert a single derived feature value."""
    import json
    meta_json = json.dumps(meta) if meta else None
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO quant_features (feature_id, target, ts, value, meta)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (feature_id, target, ts) DO UPDATE SET
                   value = EXCLUDED.value,
                   meta  = EXCLUDED.meta""",
            (feature_id, target, ts, value, meta_json),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def healthcheck() -> dict:
    """Quick liveness probe: connect, count rows in each hypertable."""
    out = {}
    with connect() as conn, conn.cursor() as cur:
        for table in ("quant_indicators", "quant_bars",
                      "quant_valuations", "quant_features"):
            cur.execute(f"SELECT COUNT(*) AS n FROM {table}")
            row = cur.fetchone()
            out[table] = row["n"] if row else 0
    return out
