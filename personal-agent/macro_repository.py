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
        "cadence": "monthly",
        # multpl.com sometimes restates recent CAPE values when the
        # underlying earnings/CPI inputs are revised. Use update-on-change
        # so a restated month overwrites the prior write while unchanged
        # rows stay no-op (idempotency preserved).
        "on_conflict": "update_on_change",
        "xlsx_urls": (
            "http://www.econ.yale.edu/~shiller/data/ie_data.xls",
            "https://shillerdata.com/data/ie_data.xls",
        ),
        "column": "CAPE",
    },
    "vix": {
        "id": "vix",
        "source": "fred",
        "cadence": "daily",
        # FRED values are point-in-time (carry their own realtime_start/
        # realtime_end); revisions create new rows, never restate the
        # primary key. Keep the simple ignore-on-conflict path.
        "on_conflict": "ignore",
        "series_id": "VIXCLS",
    },
    "hy_oas": {
        "id": "hy_oas",
        "source": "fred",
        "cadence": "daily",
        "on_conflict": "ignore",
        "series_id": "BAMLH0A0HYM2",
    },
    "sp500_close": {
        "id": "sp500_close",
        "source": "fred",
        "cadence": "daily",
        "on_conflict": "ignore",
        "series_id": "SP500",
    },
    "tnx_yield": {
        "id": "tnx_yield",
        "source": "fred",
        "cadence": "daily",
        "on_conflict": "ignore",
        "series_id": "DGS10",
    },
}


# ---------------------------------------------------------------------------
# Staleness thresholds — tunable. ``daily`` indicators source from FRED,
# which publishes on US trading days; 6 business days covers a normal
# weekly cadence (prior-Friday-to-this-Friday is 5 business days) plus
# FRED's publication lag over a long weekend, without false positives.
# ``monthly`` thresholds tolerate a little slack around the multpl.com
# refresh cadence (~mid-month). Both values are tweakable here without
# touching callers. Holidays are deliberately out of scope — tune the
# threshold rather than maintaining a holiday calendar.
# ---------------------------------------------------------------------------

STALE_BUSINESS_DAYS_DAILY = 6
STALE_CALENDAR_DAYS_MONTHLY = 40


def get_indicators_catalog() -> list[dict]:
    """Catalog + DB coverage for ``GET /api/macro/indicators``.

    Returns a list of ``{id, source, cadence, count, first_ts, last_ts}``,
    one per catalog entry. Indicators with no rows yet report ``count=0``
    and ``first_ts/last_ts = None``. Internal-only catalog keys
    (``xlsx_urls``, ``series_id``, ``on_conflict``, ``column``) are NOT
    exposed.
    """
    out: list[dict] = []
    for ind_id, cfg in INDICATORS.items():
        rng = get_ts_range(ind_id)
        out.append({
            "id": ind_id,
            "source": cfg["source"],
            "cadence": cfg["cadence"],
            "count": rng["count"] if rng else 0,
            "first_ts": rng["first_ts"] if rng else None,
            "last_ts": rng["last_ts"] if rng else None,
        })
    return out


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------

_ON_CONFLICT_MODES = ("ignore", "update_on_change")


def upsert_observations(
    indicator: str,
    rows: list[dict],
    *,
    source: str | None = None,
    fetched_at: str | None = None,
    on_conflict: str | None = None,
) -> dict:
    """Upsert observations and return ``{inserted, updated, skipped_dup}``.

    ``rows`` is a list of ``{"ts": "...", "value": float, "metadata": {...}|None}``.
    ``ts`` is the observation date (ISO ``YYYY-MM-DD`` or full ISO).
    ``source`` defaults to the catalog entry. ``fetched_at`` defaults to
    ``now()`` and is shared by all rows of this call.

    ``on_conflict`` selects the write semantics; defaults to whatever the
    catalog entry says (``INDICATORS[indicator]["on_conflict"]``), so
    callers normally don't have to think about it:

      * ``"ignore"`` (FRED) — pure ``INSERT OR IGNORE``. New ts → insert;
        existing ts → ``skipped_dup``, never re-written. Returned
        ``updated`` is always ``0``.
      * ``"update_on_change"`` (CAPE) — ``INSERT OR IGNORE``; if that
        was a no-op, retry as ``UPDATE ... WHERE value != excluded.value``
        so a restated month overwrites the prior write but unchanged
        rows stay no-op. Metadata only moves when the value moves —
        rows whose value is unchanged keep their original ``metadata``
        (and therefore the original ``scraped_at`` / ``fetched_at``),
        which makes the "ran twice → 0 writes" idempotency proof hold.
    """
    if indicator not in INDICATORS:
        raise ValueError(f"unknown indicator {indicator!r}")
    if on_conflict is None:
        on_conflict = INDICATORS[indicator].get("on_conflict", "ignore")
    if on_conflict not in _ON_CONFLICT_MODES:
        raise ValueError(f"unknown on_conflict mode {on_conflict!r}")
    if source is None:
        source = INDICATORS[indicator]["source"]
    if fetched_at is None:
        fetched_at = datetime.now(timezone.utc).isoformat()
    if not rows:
        return {"inserted": 0, "updated": 0, "skipped_dup": 0}

    inserted = 0
    updated = 0
    skipped_dup = 0
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
                continue
            # Row exists. In ignore mode, that's the end of it. In
            # update_on_change mode, the UPDATE is gated on
            # ``value != ?`` so unchanged rows return rowcount=0
            # (no churn, no metadata rewrite) and changed rows
            # return rowcount=1 (counted as 'updated').
            if on_conflict == "update_on_change":
                cur2 = conn.execute(
                    "UPDATE macro_indicators "
                    "SET value = ?, metadata = ? "
                    "WHERE indicator = ? AND ts = ? AND value != ?",
                    (value, md_json, indicator, ts, value),
                )
                if cur2.rowcount:
                    updated += 1
                    continue
            skipped_dup += 1
    return {"inserted": inserted, "updated": updated, "skipped_dup": skipped_dup}


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


# ---------------------------------------------------------------------------
# Freshness — request-time only (never persisted). Used by /api/macro/latest
# ---------------------------------------------------------------------------

def _business_days_between(d1, d2) -> int:
    """Number of business days (Mon-Fri) strictly after ``d1`` up to and
    including ``d2``. Returns 0 when ``d2 <= d1``.

    Calendar-day accounting is too noisy for FRED's publication cadence
    (US trading days only), so the daily-cadence staleness threshold
    runs through this helper. We don't subtract individual holidays —
    too brittle, the operator tunes the threshold instead.
    """
    if d2 <= d1:
        return 0
    from datetime import timedelta
    count = 0
    cur = d1 + timedelta(days=1)
    while cur <= d2:
        if cur.weekday() < 5:    # Mon-Fri
            count += 1
        cur += timedelta(days=1)
    return count


def get_freshness(*, now_utc=None) -> list[dict]:
    """Per-indicator freshness report. Powers ``GET /api/macro/latest``.

    For each catalog entry, returns::

        {
          "indicator":      "<id>",
          "cadence":        "daily" | "monthly",
          "latest_ts":      "YYYY-MM-DD" | None,
          "value":          float | None,
          "no_data":        True iff there is no row at all,
          "age_days":       business days for daily / calendar days for monthly,
          "threshold_days": STALE_THRESHOLD_*  (the comparison threshold),
          "is_stale":       True iff age_days > threshold_days OR no_data,
        }

    ``now_utc`` is a test seam — production callers leave it ``None`` and
    we read ``datetime.now(timezone.utc)`` at request time. Staleness is
    computed here, never persisted.
    """
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    today = now_utc.date()

    latest_all = get_latest_all()
    out: list[dict] = []
    for ind_id, cfg in INDICATORS.items():
        cadence = cfg["cadence"]
        threshold = (
            STALE_BUSINESS_DAYS_DAILY if cadence == "daily"
            else STALE_CALENDAR_DAYS_MONTHLY
        )
        latest = latest_all.get(ind_id)
        if latest is None:
            out.append({
                "indicator": ind_id,
                "cadence": cadence,
                "latest_ts": None,
                "value": None,
                "no_data": True,
                "age_days": None,
                "threshold_days": threshold,
                "is_stale": True,
            })
            continue
        # Observations are stored as YYYY-MM-DD strings; slice to be safe
        # against any caller that ever stored a fuller ISO datetime.
        latest_date = datetime.fromisoformat(latest["ts"][:10]).date()
        if cadence == "daily":
            age = _business_days_between(latest_date, today)
        else:
            age = (today - latest_date).days
        out.append({
            "indicator": ind_id,
            "cadence": cadence,
            "latest_ts": latest["ts"],
            "value": latest["value"],
            "no_data": False,
            "age_days": age,
            "threshold_days": threshold,
            "is_stale": age > threshold,
        })
    return out
