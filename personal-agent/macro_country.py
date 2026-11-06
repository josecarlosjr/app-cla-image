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

# Lower bound for the housing series on quant_indicators. Eurostat HPI
# starts 2005 and BPstat ~2009, so 30 years covers both in full with
# years of margin. Narrowing it below ~2005 would clip real history.
#
# It is NOT a performance lever here, contrary to what the first cut of
# this file claimed. Measured in-pod: quant_indicators holds 146 chunks
# (quant_bars, the one that OOM'd in PR #78, had 5145), the query runs
# in ~10 ms, and 30y / 50y / 200y all take the same time with ZERO
# chunks excluded. The ~0.19 s that remains per country is connection
# overhead — ``connect()`` has no pool — which is a separate ticket, not
# something this window can touch.
_HOUSING_SERIES_DAYS = 365 * 30

_GAP_PREFIX = "bis_credit_gap_"
_RATIO_PREFIX = "bis_credit_ratio_"

# Banco de Portugal housing series, PT only. ONLY the two whose
# identity is confirmed: ``quant_bpstat.py`` states in its own module
# docstring that "12559645 + 5739035 are confirmed; 12559646/47 are the
# new/existing siblings that appear alongside 12559645" — i.e. nobody
# has verified what 12559646/47 actually measure. An unlabelled series
# in a detail view would be read as meaning something, so they are left
# out rather than shown with a guessed label.
#
# ``yoy``: whether a year-on-year makes sense for this series. 5739035
# IS already the year-on-year change (TVH), so running the y-o-y rule
# over it yields the change OF a change — a reading of +16.5% came back
# as -4.07%, which next to the HPI's +16.48% reads as "prices fell".
# Its ``value`` is the correct year-on-year figure; ``yoy_pct`` is
# reported as None rather than a number that means something else.
#
# ``unit``: carried in the payload because the same confusion bites the
# axis and the headline. 12559645 is an index (bare number); 5739035 is
# a rate, and rendering it as "0.97" instead of "0.97%" invites exactly
# the misreading above.
_BPSTAT_PT: tuple[dict, ...] = (
    {"id": "12559645",
     "label": "Índice de preços da habitação — Total (nível)",
     "yoy": True, "unit": ""},
    {"id": "5739035",
     "label": "Índice de preços da habitação — Total (variação homóloga %)",
     "yoy": False, "unit": "%"},
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

    ONE round trip for every series this country has.

    That matters more than it looks. ``pg_database.connect()`` opens a
    short-lived connection per call and there is no pool. The first cut
    of this function called ``get_indicator_series`` + ``get_yoy_change``
    per series and measured, in-pod: US (1 call) 0.257s, PT (5 calls)
    1.143s — ~0.22s of marginal cost per call, against 0.002s for the
    whole SQLite half of the payload.

    Almost all of that is the connection, not the query: the same
    measurement found quant_indicators at 146 chunks with the query
    itself at ~10 ms. So the fix is to stop making five of them — one
    batched query for every id at once, and the y-o-y computed from
    the series already in hand (``pg_database.yoy_from_series``, the
    in-Python twin of ``get_yoy_change`` — same rule, same number as
    the dashboard table) instead of a second round trip per series.

    Result in-pod: 1.07s -> 0.197s average across the 14, one
    connection per country. The ~0.19s floor that remains is one
    connection setup and belongs to the pooling ticket.

    Never raises: on any failure — driver missing, Postgres down, a
    series absent — the country detail still renders with its BIS
    charts, which are the point of the view. Returns the keys it could
    fill: ``{"hpi": {...}|None, "bpstat": [...]}``.
    """
    out: dict = {"hpi": None, "bpstat": []}
    try:
        from pg_database import get_indicators_series_batch, yoy_from_series

        hpi_sid = f"EUROSTAT_HPI_{code}"
        wanted = [hpi_sid]
        if code == "PT":
            wanted += [f"BPSTAT_{s['id']}" for s in _BPSTAT_PT]

        batch = get_indicators_series_batch(wanted, _HOUSING_SERIES_DAYS)

        hpi_series = batch.get(hpi_sid) or []
        if hpi_series:
            last = hpi_series[-1]
            out["hpi"] = {
                "ts": last["ts"],
                "value": last["value"],
                "yoy_pct": yoy_from_series(hpi_series),
                "series": hpi_series,
            }

        if code == "PT":
            for spec in _BPSTAT_PT:
                series = batch.get(f"BPSTAT_{spec['id']}") or []
                if not series:
                    continue
                last = series[-1]
                out["bpstat"].append({
                    "series_id": spec["id"],
                    "label": spec["label"],
                    "unit": spec["unit"],
                    "ts": last["ts"],
                    "value": last["value"],
                    # None where the series IS the y-o-y — see _BPSTAT_PT.
                    "yoy_pct": (
                        yoy_from_series(series) if spec["yoy"] else None
                    ),
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
         "bpstat":       [{series_id, label, unit, ts, value,
                           yoy_pct, series: [...]}, ...]}

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
