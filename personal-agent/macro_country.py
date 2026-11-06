"""Per-country macro detail (Onda 13 multi-pais, Camada B).

On-demand assembly behind ``GET /api/macro/country/{code}``: the FULL
history of the BIS credit-to-GDP **gap** and **ratio** for one country,
plus the housing-price series that exist for it.

Why a separate module (and not ``pg_database``):

  * the primary payload — the two BIS series — comes from the SQLite
    macro catalog (``macro_repository``), which has no psycopg
    dependency. Putting this in ``pg_database`` would mean an
    ``ImportError`` on an image without the Postgres driver 503s the
    whole endpoint, including the part that would have worked. Here the
    Postgres enrichment is a lazy import inside a ``try`` and degrades
    to "no HPI / BPstat section" instead;
  * it is cross-source orchestration, the same role
    ``bubble_orchestrator`` plays for the bubble engine.

Why on demand: the Quant dashboard just came out of a performance
crisis (a hypertable query touching 5145 chunks -> OOM). The full
1980-> series are ~184 points x 2 per country x 14 countries; folding
them into ``/api/quant/dashboard`` would multiply that payload for data
nobody looks at until they open one country. So the dashboard keeps its
~7-year sparklines and this endpoint is only hit when a country detail
is opened.

Sources, and what each one legitimately says:

  BIS gap / ratio   SQLite ``macro_indicators``, quarterly, 1980-> ,
                    14 countries. Canonical (Onda 12 C1).
  Eurostat HPI      Postgres ``quant_indicators``, ``EUROSTAT_HPI_{code}``.
                    Only exists for the EU members among the 14.
  BPstat            Postgres, ``BPSTAT_{series_id}``. PT only, and only
                    the two series whose identity is CONFIRMED — see
                    ``_BPSTAT_PT`` below.
"""

import logging

logger = logging.getLogger(__name__)

# BIS is quarterly from 1980; Eurostat HPI and BPstat both start in the
# 2000s. 50 years is "everything either source could hold" while still
# being a finite lower bound on the hypertable query, so the planner
# keeps the same shape of plan ``get_indicator_series`` is already
# tuned for. Safe on quant_indicators specifically: the dashboard
# already runs two UNBOUNDED ``get_latest_by_prefix`` DISTINCT ON scans
# over this same table on every load, so a single-series range scan
# here is strictly less work than what production does today. (The
# 5145-chunk OOM was ``quant_bars``, a far bigger hypertable.)
_FULL_HISTORY_DAYS = 365 * 50

_GAP_PREFIX = "bis_credit_gap_"
_RATIO_PREFIX = "bis_credit_ratio_"

# Banco de Portugal housing series, PT only. ONLY the two whose
# identity is confirmed: ``quant_bpstat.py`` states in its own module
# docstring that "12559645 + 5739035 are confirmed; 12559646/47 are the
# new/existing siblings that appear alongside 12559645" — i.e. nobody
# has verified what 12559646/47 actually measure. An unlabelled series
# in a detail view would be read as meaning something, so they are left
# out rather than shown with a guessed label.
_BPSTAT_PT: tuple[tuple[str, str], ...] = (
    ("12559645", "Índice de preços da habitação — Total (nível)"),
    ("5739035", "Índice de preços da habitação — Total (variação homóloga %)"),
)


def bis_countries() -> list[str]:
    """The uppercase ISO2 codes the BIS catalog covers, sorted.

    Derived from the catalog itself rather than hardcoded, so the
    endpoint follows ``macro_repository._BIS_COUNTRIES`` automatically
    if the country set ever grows.
    """
    import macro_repository as mr

    return sorted(
        ind[len(_GAP_PREFIX):].upper()
        for ind in mr.INDICATORS
        if ind.startswith(_GAP_PREFIX)
    )


def _bis_block(indicator: str) -> dict | None:
    """Full history of one BIS indicator as ``{ts, value, series}``.

    ``ts``/``value`` are the LAST point of the series — no second query,
    and the headline number is guaranteed to be the one the chart ends
    on. ``None`` when the catalog entry exists but holds no rows.
    """
    import macro_repository as mr

    points = mr.get_timeseries(indicator, limit=10000)["points"]
    if not points:
        return None
    last = points[-1]
    return {"ts": last["ts"], "value": last["value"], "series": points}


def _housing_blocks(code: str) -> dict:
    """Eurostat HPI + (PT only) BPstat, from the quant Postgres.

    Never raises: on any failure — driver missing, Postgres down, a
    series absent — the country detail still renders with its BIS
    charts, which are the point of the view. Returns the keys it could
    fill: ``{"hpi": {...}|None, "bpstat": [...]}``.
    """
    out: dict = {"hpi": None, "bpstat": []}
    try:
        from pg_database import (
            get_indicator_series,
            get_indicators_series_batch,
            get_yoy_change,
        )

        hpi_sid = f"EUROSTAT_HPI_{code}"
        hpi_series = get_indicator_series(hpi_sid, _FULL_HISTORY_DAYS)
        if hpi_series:
            last = hpi_series[-1]
            out["hpi"] = {
                "ts": last["ts"],
                "value": last["value"],
                # Same helper the dashboard table uses, so the number in
                # the drawer and the number in the panel agree.
                "yoy_pct": get_yoy_change(hpi_sid),
                "series": hpi_series,
            }

        if code == "PT":
            sids = [f"BPSTAT_{sid}" for sid, _ in _BPSTAT_PT]
            batch = get_indicators_series_batch(sids, _FULL_HISTORY_DAYS)
            for sid, label in _BPSTAT_PT:
                series = batch.get(f"BPSTAT_{sid}", [])
                if not series:
                    continue
                last = series[-1]
                out["bpstat"].append({
                    "series_id": sid,
                    "label": label,
                    "ts": last["ts"],
                    "value": last["value"],
                    "yoy_pct": get_yoy_change(f"BPSTAT_{sid}"),
                    "series": series,
                })
    except ImportError as e:
        logger.warning(
            "country detail %s: no Postgres driver (%s); BIS-only", code, e,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "country detail %s: housing series unavailable (%s); BIS-only",
            code, e,
        )
    return out


def get_country_detail(code: str) -> dict | None:
    """Full macro detail for one BIS country, or ``None`` if unknown.

    ``code`` is case-insensitive ISO2; ``None`` (-> 404 at the route)
    means it is not one of the countries the BIS catalog covers.

    Shape::

        {"country": "PT",
         "credit_gap":   {ts, value, series: [{ts, value}, ...]} | null,
         "credit_ratio": {ts, value, series: [...]}              | null,
         "hpi":          {ts, value, yoy_pct, series: [...]}     | null,
         "bpstat":       [{series_id, label, ts, value, yoy_pct,
                           series: [...]}, ...]}

    ``series`` (not ``points``) so the shape matches the
    ``QuantSeriesPoint[]`` the frontend charts already consume.

    A valid country with no rows for a series gets an explicit ``null``
    rather than a missing key: the country IS in the catalog, so the
    drawer should say "no data" for that chart instead of silently
    rendering an empty box. ``bpstat`` is ``[]`` for the other 13.
    """
    norm = (code or "").strip().upper()
    if norm not in bis_countries():
        return None

    lower = norm.lower()
    out: dict = {
        "country": norm,
        "credit_gap": _bis_block(f"{_GAP_PREFIX}{lower}"),
        "credit_ratio": _bis_block(f"{_RATIO_PREFIX}{lower}"),
    }
    out.update(_housing_blocks(norm))
    return out
