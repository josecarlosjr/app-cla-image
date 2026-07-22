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
# Catalog — 33 indicators total (5 core macro + 28 BIS credit-to-GDP).
# ``INDICATORS`` is the single source of truth: ``GET /api/macro/indicators``,
# the fetchers and the backfills all derive from it.
#
# Core macro (5) — daily FRED + monthly Shiller CAPE — is the original
# Sprint 1 catalog. BIS credit-to-GDP (28) — 14 countries × {gap, ratio}
# — is Sprint C1. Cadence and on_conflict semantics propagate through
# ``upsert_observations`` and ``get_freshness`` from the entry itself; no
# hardcoded switch statements on indicator id anywhere in this module.
# ---------------------------------------------------------------------------

# BIS credit-to-GDP: 14 countries. ISO 3166-1 alpha-2 lowercase (internal
# convention); the BIS API expects uppercase, translated at the fetcher
# boundary. ``gb`` is the UK (BIS/ISO), not ``uk``. Order here doesn't
# matter for correctness; kept roughly by geography for eyeballing.
_BIS_COUNTRIES: tuple[str, ...] = (
    "us", "gb", "de", "fr", "it", "es", "pt",       # Americas + Western Europe
    "jp", "kr", "au",                                # Asia-Pacific advanced
    "ca",                                            # North America (other)
    "cn", "in", "br",                                # EMEs
)


def _bis_indicator_entry(country: str, series_type: str) -> dict:
    """Emit one BIS credit-to-GDP catalog entry.

    ``series_type`` is ``'gap'`` (narrow, Basel III) or ``'ratio'``
    (level). The narrow identity is baked in by hardcoding
    ``TC_BORROWERS='P'`` (private non-financial) and ``TC_LENDERS='A'``
    (all sectors = total credit). The bank-only variant ``TC_LENDERS='B'``
    is deliberately unreachable through this helper — a mistyped BIS
    dataflow key would still work, but a mistyped ``series_type`` won't.
    See ``test_catalog_bis_series_keys_are_narrow_gap_or_ratio`` for the
    regex guard.

    ``on_conflict='update_on_change'`` because BIS's HP filter is
    one-sided: every new observation shifts the trend, and therefore the
    entire historical gap series is republished with revised values. Same
    reasoning as CAPE Shiller. Idempotency "2× in the same publication
    cycle → 0 writes" still holds; "2× across publications → N updates"
    is expected, not a bug.
    """
    if series_type not in ("gap", "ratio"):
        raise ValueError(f"series_type must be 'gap' or 'ratio', got {series_type!r}")
    dim_dtype = "C" if series_type == "gap" else "A"
    return {
        "id": f"bis_credit_{series_type}_{country}",
        "source": "bis",
        "cadence": "quarterly",
        "on_conflict": "update_on_change",
        "dataflow": "BIS,WS_CREDIT_GAP,1.0",
        "series_key": f"Q.{country.upper()}.P.A.{dim_dtype}",
        "country": country.upper(),
        "series_type": series_type,
    }


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
        # History cap: a FRED licensing change around April 2026 capped
        # the entire ICE BofA family on FRED to a rolling ~3-year window.
        # HY_OAS is currently the only ICE BofA series in our catalog;
        # full history (the underlying series starts 1996-12-31) is NOT
        # retrievable through this endpoint. No auto-fallback — a longer
        # series requires a different vendor (ICE direct, Bloomberg) and
        # is an explicit operator decision.
    },
    "sp500_close": {
        "id": "sp500_close",
        "source": "fred",
        "cadence": "daily",
        "on_conflict": "ignore",
        "series_id": "SP500",
        # History cap: S&P / Dow Jones licensing caps FRED's SP500
        # series at ~10 years of daily history. Long-history alternatives
        # (^GSPC via yfinance, or Shiller's own SP500 price column on
        # multpl) are operator decisions — no auto-fallback.
    },
    "tnx_yield": {
        "id": "tnx_yield",
        "source": "fred",
        "cadence": "daily",
        "on_conflict": "ignore",
        "series_id": "DGS10",
    },
    # ---- BIS credit-to-GDP: 14 countries × {gap, ratio} = 28 entries ----
    **{f"bis_credit_gap_{c}":   _bis_indicator_entry(c, "gap")
       for c in _BIS_COUNTRIES},
    **{f"bis_credit_ratio_{c}": _bis_indicator_entry(c, "ratio")
       for c in _BIS_COUNTRIES},
}


# ---------------------------------------------------------------------------
# Staleness thresholds — tunable. ``daily`` indicators source from FRED,
# which publishes on US trading days; 6 business days covers a normal
# weekly cadence (prior-Friday-to-this-Friday is 5 business days) plus
# FRED's publication lag over a long weekend, without false positives.
# ``monthly`` thresholds tolerate a little slack around the multpl.com
# refresh cadence (~mid-month). All three values are tweakable here
# without touching callers. Holidays are deliberately out of scope —
# tune the threshold rather than maintaining a holiday calendar.
#
# ``quarterly`` is BIS credit-to-GDP: BIS publishes ~T+90 (three-month
# lag). 150 calendar days is 90 lag + ~60 slack — comfortable margin
# without hiding a real BIS outage. Wide by design because the
# underlying data doesn't move fast; a quarter that's 5 months late
# still reflects reality closely enough for regime detection. If BIS's
# publication cadence ever tightens (or slips), tune here.
# ---------------------------------------------------------------------------

STALE_BUSINESS_DAYS_DAILY = 6
STALE_CALENDAR_DAYS_MONTHLY = 40
STALE_CALENDAR_DAYS_QUARTERLY = 150

# Cadence → threshold lookup. Extend this map (and add the constant
# above) when a new cadence family is introduced. Direct indexing —
# a cadence missing from the map is a bug (not a silent fallback).
_STALE_THRESHOLDS: dict[str, int] = {
    "daily":     STALE_BUSINESS_DAYS_DAILY,
    "monthly":   STALE_CALENDAR_DAYS_MONTHLY,
    "quarterly": STALE_CALENDAR_DAYS_QUARTERLY,
}


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


def get_recent(indicator: str, n: int = 2) -> list[dict]:
    """The ``n`` most recent observations for ``indicator``, newest first.

    Each row is ``{"ts", "value"}``; returns ``[]`` when the indicator
    has no data. The Telegram macro digest uses this with ``n=2`` to
    compute "value (+/-diff vs prior_ts)" — it needs both the latest
    AND the immediately preceding observation, regardless of the
    calendar gap between them (weekends, holidays, FRED publication
    lag). "vs prior_ts" is honest about *which* prior point we compared
    against, in a way "vs yesterday" would not be.
    """
    if indicator not in INDICATORS:
        raise ValueError(f"unknown indicator {indicator!r}")
    n = max(1, int(n))
    rows = _db().execute(
        "SELECT ts, value FROM macro_indicators "
        "WHERE indicator = ? ORDER BY ts DESC LIMIT ?",
        (indicator, n),
    ).fetchall()
    return [{"ts": r["ts"], "value": r["value"]} for r in rows]


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
          "cadence":        "daily" | "monthly" | "quarterly",
          "latest_ts":      "YYYY-MM-DD" | None,
          "value":          float | None,
          "no_data":        True iff there is no row at all,
          "age_days":       business days for daily / calendar days for
                              monthly and quarterly,
          "threshold_days": ``_STALE_THRESHOLDS[cadence]``,
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
        threshold = _STALE_THRESHOLDS[cadence]
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
