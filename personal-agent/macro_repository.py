"""Macro-indicators repository (Onda 12 Sprint 1, Camada B).

All SQL that touches the ``macro_indicators`` table is concentrated in this
module so the rest of the codebase stays agnostic of the schema. A future
migration to Postgres/TimescaleDB (when row counts justify it) becomes a
single-module diff.

Reuses ``database._db()`` to honour the ``DB_PATH`` env var (PR #66) and
the auto-migration via ``_LATE_ADDED_TABLES`` (so the table is created on
first call against a pre-Onda-12 production DB without manual migration).
"""

import json
from datetime import datetime, timezone

from database import _db


# ---------------------------------------------------------------------------
# Catalog — the 5 indicators this sprint ships with. Keep this dict the
# single source of truth: ``GET /api/macro/indicators``, the fetcher and
# the backfill all derive from it.
# ---------------------------------------------------------------------------

INDICATORS: dict[str, dict] = {
    "cape_shiller": {
        "id": "cape_shiller",
        "source": "shiller_yale",
        "frequency": "monthly",
        "xlsx_urls": (
            "http://www.econ.yale.edu/~shiller/data/ie_data.xls",
            "https://shillerdata.com/data/ie_data.xls",
        ),
        "column": "CAPE",
    },
    "vix": {
        "id": "vix",
        "source": "fred",
        "frequency": "daily",
        "series_id": "VIXCLS",
    },
    "hy_oas": {
        "id": "hy_oas",
        "source": "fred",
        "frequency": "daily",
        "series_id": "BAMLH0A0HYM2",
    },
    "sp500_close": {
        "id": "sp500_close",
        "source": "fred",
        "frequency": "daily",
        "series_id": "SP500",
    },
    "tnx_yield": {
        "id": "tnx_yield",
        "source": "fred",
        "frequency": "daily",
        "series_id": "DGS10",
    },
}


def list_indicators() -> list[dict]:
    """Public-facing catalog (no URLs, no series_ids) for the
    ``GET /api/macro/indicators`` endpoint. Returns a list of
    ``{id, source, frequency}`` dicts ordered by insertion order."""
    return [
        {"id": v["id"], "source": v["source"], "frequency": v["frequency"]}
        for v in INDICATORS.values()
    ]


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------

def upsert_observations(
    indicator: str,
    rows: list[dict],
    *,
    source: str | None = None,
    fetched_at: str | None = None,
) -> tuple[int, int]:
    """Insert observations idempotently via INSERT OR IGNORE.

    ``rows`` is a list of ``{"ts": "...", "value": float, "metadata": {...}|None}``.
    ``ts`` is the observation date (ISO ``YYYY-MM-DD`` or full ISO). ``source``
    defaults to the catalog entry. ``fetched_at`` defaults to ``now()`` and is
    shared by all rows of this call. Returns ``(inserted, skipped)``.
    """
    if indicator not in INDICATORS:
        raise ValueError(f"unknown indicator {indicator!r}")
    if source is None:
        source = INDICATORS[indicator]["source"]
    if fetched_at is None:
        fetched_at = datetime.now(timezone.utc).isoformat()
    if not rows:
        return (0, 0)

    inserted = 0
    skipped = 0
    conn = _db()
    with conn:
        for row in rows:
            ts = row["ts"]
            value = float(row["value"])
            md = row.get("metadata")
            md_json = (
                json.dumps(md, separators=(",", ":"), default=str)
                if md is not None else None
            )
            cur = conn.execute(
                "INSERT OR IGNORE INTO macro_indicators "
                "(indicator, ts, value, source, fetched_at, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (indicator, ts, value, source, fetched_at, md_json),
            )
            if cur.rowcount:
                inserted += 1
            else:
                skipped += 1
    return inserted, skipped


# ---------------------------------------------------------------------------
# Read path
# ---------------------------------------------------------------------------

def get_timeseries(
    indicator: str,
    *,
    start: str | None = None,
    end: str | None = None,
    limit: int = 1000,
) -> dict:
    """Return ``{indicator, points: [{ts, value}, ...], total}``.

    ``start``/``end`` are inclusive ISO bounds. Points are ordered by ts
    ASC. ``limit`` is clamped to [1, 10000]; ``total`` reflects the full
    matching set so the caller can detect when more pages exist.
    """
    if indicator not in INDICATORS:
        raise ValueError(f"unknown indicator {indicator!r}")
    limit = max(1, min(int(limit), 10000))

    clauses = ["indicator = ?"]
    params: list = [indicator]
    if start:
        clauses.append("ts >= ?")
        params.append(start)
    if end:
        clauses.append("ts <= ?")
        params.append(end)
    where = " AND ".join(clauses)

    conn = _db()
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM macro_indicators WHERE {where}",
        params,
    ).fetchone()["n"]
    rows = conn.execute(
        f"SELECT ts, value FROM macro_indicators WHERE {where} "
        f"ORDER BY ts ASC LIMIT ?",
        params + [limit],
    ).fetchall()
    points = [{"ts": r["ts"], "value": r["value"]} for r in rows]
    return {"indicator": indicator, "points": points, "total": total}


def get_latest(indicator: str) -> dict | None:
    """Most-recent observation for ``indicator``, or ``None`` if no rows.
    Returns ``{indicator, ts, value, fetched_at}``."""
    if indicator not in INDICATORS:
        raise ValueError(f"unknown indicator {indicator!r}")
    row = _db().execute(
        "SELECT ts, value, fetched_at FROM macro_indicators "
        "WHERE indicator = ? ORDER BY ts DESC LIMIT 1",
        (indicator,),
    ).fetchone()
    if row is None:
        return None
    return {
        "indicator": indicator,
        "ts": row["ts"],
        "value": row["value"],
        "fetched_at": row["fetched_at"],
    }


def get_latest_all() -> dict[str, dict]:
    """Most-recent observation per catalog indicator. Indicators without
    any rows are absent from the returned dict."""
    conn = _db()
    out: dict[str, dict] = {}
    for ind_id in INDICATORS:
        row = conn.execute(
            "SELECT ts, value, fetched_at FROM macro_indicators "
            "WHERE indicator = ? ORDER BY ts DESC LIMIT 1",
            (ind_id,),
        ).fetchone()
        if row is not None:
            out[ind_id] = {
                "ts": row["ts"],
                "value": row["value"],
                "fetched_at": row["fetched_at"],
            }
    return out


def count_by_indicator() -> dict[str, int]:
    """Diagnostic: ``{indicator: n_rows}``. Useful for the backfill
    pre-flight check and the run summary."""
    rows = _db().execute(
        "SELECT indicator, COUNT(*) AS n FROM macro_indicators "
        "GROUP BY indicator",
    ).fetchall()
    return {r["indicator"]: r["n"] for r in rows}


def get_ts_range(indicator: str) -> dict | None:
    """Return ``{first_ts, last_ts, count}`` for an indicator, or ``None``
    when there are no observations. Used by the backfill end-of-run
    report to show the actual series coverage."""
    if indicator not in INDICATORS:
        raise ValueError(f"unknown indicator {indicator!r}")
    row = _db().execute(
        "SELECT MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS n "
        "FROM macro_indicators WHERE indicator = ?",
        (indicator,),
    ).fetchone()
    if row is None or row["n"] == 0:
        return None
    return {
        "first_ts": row["first_ts"],
        "last_ts": row["last_ts"],
        "count": row["n"],
    }
