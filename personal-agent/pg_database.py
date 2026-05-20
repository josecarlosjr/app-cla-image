"""Postgres / TimescaleDB connection helper for the quant layer.

Mirrors `database.py` (which talks to SQLite) but for the new postgres
instance that holds time-series data — articles/patterns/graph stay in
SQLite, quant_* lives in postgres. The hybrid is deliberate: SQLite is
read-heavy and stays where it is; postgres absorbs the high-frequency
writes that bubble detection needs.

Connection string resolution order:

  1. `DATABASE_URL` env var (preferred — it's what the postgres-secrets
     Secret exposes as a single line, no parsing needed).
  2. Composed from individual parts (`PIA_DB_USER`, `PIA_DB_PASSWORD`,
     `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`).
  3. Raise on connect — never silently fall back to a default that
     could connect somewhere unintended.

The DSN is resolved lazily (first connect, not at import) so the
FastAPI app can import this module even when postgres isn't reachable
or configured yet. Failures surface only at the actual DB call.
"""

import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

logger = logging.getLogger(__name__)


_DSN: str | None = None

# Macro-risk panel keeps ~7 years of quarterly history per series so
# the sparkline captures the pre/post-COVID regime and the 2022 rate
# cycle. ~28 points/series, payload still small.
_MACRO_SERIES_DAYS = 365 * 7


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


def _get_dsn() -> str:
    global _DSN
    if _DSN is None:
        _DSN = _build_dsn()
    return _DSN


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
    """Open a short-lived connection. Caller owns the transaction.

    Use as:

        with pg.connect() as conn, conn.cursor() as cur:
            cur.execute("...")
            conn.commit()
    """
    conn = psycopg.connect(_get_dsn(), row_factory=dict_row)
    try:
        yield conn
    finally:
        conn.close()


# ===========================================================================
# WRITERS — used by the ingestion cronjobs
# ===========================================================================

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


def upsert_feature(
    feature_id: str,
    target: str,
    ts: str,
    value: float,
    meta: dict | None = None,
) -> None:
    """Upsert a single derived feature value."""
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


# ===========================================================================
# READERS — used by the FastAPI /api/quant/* endpoints
# ===========================================================================

def get_indicator_series(series_id: str, days: int = 365) -> list[dict]:
    """Return [{ts ISO, value}, ...] for a FRED series, most-recent-last."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT ts, value FROM quant_indicators
               WHERE series_id = %s AND ts >= %s
               ORDER BY ts""",
            (series_id, cutoff),
        )
        return [
            {"ts": r["ts"].isoformat(), "value": float(r["value"])}
            for r in cur.fetchall()
        ]


def get_indicators_series_batch(
    series_ids: list[str], days: int = 365,
) -> dict[str, list[dict]]:
    """Time series for many series_ids in a single round trip.

    Returns {series_id: [{ts, value}, ...], ...}. Every requested id
    is present in the result (empty list when there's no data within
    the window). One SELECT with `WHERE series_id = ANY(%s)`, grouped
    client-side — replaces N separate connect() calls for the
    macro-risk dashboard panel which needs ~22 series at once.
    """
    if not series_ids:
        return {}
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out: dict[str, list[dict]] = {sid: [] for sid in series_ids}
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT series_id, ts, value
               FROM quant_indicators
               WHERE series_id = ANY(%s) AND ts >= %s
               ORDER BY series_id, ts""",
            (series_ids, cutoff),
        )
        for r in cur.fetchall():
            out[r["series_id"]].append({
                "ts": r["ts"].isoformat(),
                "value": float(r["value"]),
            })
    return out


def get_latest_by_prefix(prefix: str) -> dict[str, dict]:
    """Latest (ts, value) per series whose id starts with `prefix`.

    Used by the macro-risk panel / alert context to pick up the
    BIS_CREDIT_GAP_*, EUROSTAT_HPI_*, BPSTAT_* indicators without
    hardcoding the country list — anything an ingester writes shows
    up automatically. Sub-millisecond on the (series_id, ts DESC)
    hypertable index thanks to DISTINCT ON.
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT DISTINCT ON (series_id)
                   series_id, ts, value
               FROM quant_indicators
               WHERE series_id LIKE %s
               ORDER BY series_id, ts DESC""",
            (prefix + "%",),
        )
        return {
            r["series_id"]: {
                "ts": r["ts"].isoformat(),
                "value": float(r["value"]),
            }
            for r in cur.fetchall()
        }


def get_yoy_change(series_id: str) -> float | None:
    """% change between the latest observation and the closest one ~12
    months earlier. None when either value is missing or the past
    value is zero.

    One round-trip — a CTE picks the latest row, the outer SELECT
    pulls both the latest value and the past value via scalar
    subqueries against the same indexed hypertable.
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """WITH latest AS (
                 SELECT ts, value FROM quant_indicators
                 WHERE series_id = %s
                 ORDER BY ts DESC LIMIT 1
               )
               SELECT
                 (SELECT value FROM latest) AS now,
                 (SELECT value FROM quant_indicators i
                  WHERE i.series_id = %s
                    AND i.ts <= (SELECT ts FROM latest) - INTERVAL '12 months'
                  ORDER BY i.ts DESC LIMIT 1) AS past""",
            (series_id, series_id),
        )
        r = cur.fetchone()
    if not r or r["now"] is None or r["past"] is None:
        return None
    past = float(r["past"])
    if past == 0:
        return None
    return (float(r["now"]) - past) / past * 100.0


def get_latest_features_by_target() -> dict[str, dict]:
    """Latest LPPL + GSADF feature value per ticker.

    Returns:
        {
          "SPY":  {"lppl_bubble_prob": 0.34,
                   "gsadf_bsadf": 1.21, "gsadf_explosive": False},
          ...
        }

    Tickers with no features yet (detector hasn't run) are absent
    from the dict — callers should treat missing values as None.
    """
    out: dict[str, dict] = {}
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT ON (feature_id, target)
                feature_id, target, value, meta
            FROM quant_features
            WHERE feature_id IN ('lppl_bubble_prob', 'gsadf_stat')
            ORDER BY feature_id, target, ts DESC
        """)
        for r in cur.fetchall():
            ticker = r["target"]
            bucket = out.setdefault(ticker, {})
            if r["feature_id"] == "lppl_bubble_prob":
                bucket["lppl_bubble_prob"] = float(r["value"])
            elif r["feature_id"] == "gsadf_stat":
                bucket["gsadf_bsadf"] = float(r["value"])
                meta = r["meta"] or {}
                bucket["gsadf_explosive"] = bool(meta.get("explosive", False))
    return out


def _hy_status(value: float | None) -> str:
    """Map HY OAS % to a qualitative status label."""
    if value is None:
        return "unknown"
    if value < 3.0:
        return "tight"      # frothy — credit very cheap
    if value < 5.0:
        return "normal"
    if value < 7.0:
        return "elevated"
    return "stress"         # flight-to-quality in progress


def _vix_status(value: float | None) -> str:
    if value is None:
        return "unknown"
    if value < 15:
        return "calm"
    if value < 25:
        return "nervous"
    if value < 40:
        return "fear"
    return "panic"


def get_watchlist() -> list[dict]:
    """Latest close + 1d / 30d change + latest valuation per ticker.

    Uses a four-CTE query so the whole result comes back in one round
    trip. Each CTE uses DISTINCT ON to fetch the closest matching row
    per ticker — sub-millisecond on the (ticker, ts DESC) hypertable
    index.
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""
            WITH latest_bar AS (
                SELECT DISTINCT ON (ticker)
                    ticker, ts, close
                FROM quant_bars
                ORDER BY ticker, ts DESC
            ),
            prev_bar AS (
                SELECT DISTINCT ON (b.ticker)
                    b.ticker, b.close AS prev_close
                FROM quant_bars b
                JOIN latest_bar l ON b.ticker = l.ticker
                WHERE b.ts < l.ts
                ORDER BY b.ticker, b.ts DESC
            ),
            bar_30d_ago AS (
                SELECT DISTINCT ON (b.ticker)
                    b.ticker, b.close AS close_30d
                FROM quant_bars b
                JOIN latest_bar l ON b.ticker = l.ticker
                WHERE b.ts <= l.ts - INTERVAL '30 days'
                ORDER BY b.ticker, b.ts DESC
            ),
            latest_val AS (
                SELECT DISTINCT ON (ticker)
                    ticker, pe, market_cap
                FROM quant_valuations
                ORDER BY ticker, ts DESC
            )
            SELECT
                l.ticker, l.ts, l.close,
                p.prev_close,
                d30.close_30d,
                v.pe, v.market_cap
            FROM latest_bar l
            LEFT JOIN prev_bar p ON l.ticker = p.ticker
            LEFT JOIN bar_30d_ago d30 ON l.ticker = d30.ticker
            LEFT JOIN latest_val v ON l.ticker = v.ticker
            ORDER BY l.ticker
        """)
        rows = cur.fetchall()

    # Enrich with the latest detector output. One extra round trip but
    # the query is sub-millisecond (small table, indexed).
    features = get_latest_features_by_target()

    out = []
    for r in rows:
        close = float(r["close"])
        prev = float(r["prev_close"]) if r["prev_close"] is not None else None
        c30 = float(r["close_30d"]) if r["close_30d"] is not None else None
        f = features.get(r["ticker"], {})
        out.append({
            "ticker": r["ticker"],
            "ts": r["ts"].isoformat(),
            "close": close,
            "change_pct_1d": ((close - prev) / prev * 100) if prev else None,
            "change_pct_30d": ((close - c30) / c30 * 100) if c30 else None,
            "pe": float(r["pe"]) if r["pe"] is not None else None,
            "market_cap": float(r["market_cap"]) if r["market_cap"] is not None else None,
            "lppl_bubble_prob": f.get("lppl_bubble_prob"),
            "gsadf_bsadf": f.get("gsadf_bsadf"),
            "gsadf_explosive": f.get("gsadf_explosive", False),
        })
    return out


def _build_macro_risk() -> dict:
    """Latest + ~7y series for credit gap (BIS), HPI (Eurostat),
    BPstat. All three sources write into quant_indicators with
    distinct id prefixes, so the country/series set is whatever the
    ingesters produced.

    Each entry carries the latest point AND the recent time series
    (for sparklines), plus a y-o-y % for the HPI/BPstat momentum
    gauge. Series come back from a single batch query per source so
    the dashboard payload is built in O(3) round trips instead of
    O(series_count).
    """
    credit_raw = get_latest_by_prefix("BIS_CREDIT_GAP_")
    hpi_raw = get_latest_by_prefix("EUROSTAT_HPI_")
    bpstat_raw = get_latest_by_prefix("BPSTAT_")

    credit_series = get_indicators_series_batch(
        list(credit_raw.keys()), _MACRO_SERIES_DAYS,
    )
    hpi_series = get_indicators_series_batch(
        list(hpi_raw.keys()), _MACRO_SERIES_DAYS,
    )
    bpstat_series = get_indicators_series_batch(
        list(bpstat_raw.keys()), _MACRO_SERIES_DAYS,
    )

    credit_gap = {
        sid.replace("BIS_CREDIT_GAP_", ""): {
            **rec,
            "series": credit_series.get(sid, []),
        }
        for sid, rec in credit_raw.items()
    }
    hpi = {
        sid.replace("EUROSTAT_HPI_", ""): {
            **rec,
            "yoy_pct": get_yoy_change(sid),
            "series": hpi_series.get(sid, []),
        }
        for sid, rec in hpi_raw.items()
    }
    bpstat = {
        sid.replace("BPSTAT_", ""): {
            **rec,
            "yoy_pct": get_yoy_change(sid),
            "series": bpstat_series.get(sid, []),
        }
        for sid, rec in bpstat_raw.items()
    }
    return {"credit_gap": credit_gap, "hpi": hpi, "bpstat": bpstat}


def get_quant_dashboard() -> dict:
    """Bundled snapshot used by the /api/quant/dashboard endpoint.

    One round-trip from the frontend; multiple SQL queries here (each
    is sub-millisecond on the hypertables).
    """
    out: dict = {}

    # ---- Yield curve panel ----
    t10y3m = get_indicator_series("T10Y3M", 365)
    t10y2y = get_indicator_series("T10Y2Y", 365)
    latest_t10y3m = t10y3m[-1]["value"] if t10y3m else None
    out["yield_curve"] = {
        "T10Y3M": t10y3m,
        "T10Y2Y": t10y2y,
        # FRED publishes spreads in percentage points; convert to bps.
        "latest_t10y3m_bps": (latest_t10y3m * 100) if latest_t10y3m is not None else None,
        "inverted": latest_t10y3m is not None and latest_t10y3m < 0,
    }

    # ---- Credit spreads panel ----
    hy = get_indicator_series("BAMLH0A0HYM2", 365)
    bbb = get_indicator_series("BAMLC0A4CBBB", 365)
    latest_hy = hy[-1]["value"] if hy else None
    out["credit"] = {
        "HY": hy,
        "BBB": bbb,
        "latest_hy_pct": latest_hy,
        "hy_status": _hy_status(latest_hy),
    }

    # ---- VIX panel ----
    vix = get_indicator_series("VIXCLS", 365)
    latest_vix = vix[-1]["value"] if vix else None
    out["vix"] = {
        "series": vix,
        "latest": latest_vix,
        "status": _vix_status(latest_vix),
    }

    # ---- Macro risk: credit gap (BIS) + house prices (Eurostat, BPstat) ----
    out["macro_risk"] = _build_macro_risk()

    # ---- Watchlist (now includes LPPL + GSADF detector output) ----
    out["watchlist"] = get_watchlist()
    out["updated_at"] = datetime.now(timezone.utc).isoformat()
    return out


# ===========================================================================
# Health
# ===========================================================================

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
