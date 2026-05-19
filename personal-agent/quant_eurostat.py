"""Eurostat house price index ingestion.

Pulls the Eurostat House Price Index (HPI, 2015=100, quarterly) into
`quant_indicators` — the same TimescaleDB hypertable as the FRED and
BIS series — so the quant layer has a real-estate-bubble signal next to
the credit and market signals. No schema change (the no-migration path
from the gap analysis).

Source: Eurostat dissemination "API Statistics", JSON-stat format.
Free, no key.

  https://ec.europa.eu/eurostat/api/dissemination/statistics/1.0/data/
      prc_hpi_q?format=JSON&lang=EN&unit=I15_Q&purchase=TOTAL
      &geo=PT&geo=ES&...&sinceTimePeriod=2000-Q1

Dataset prc_hpi_q dimensions used:
  unit     = I15_Q     index, 2015 = 100 (the level — lets a detector
                        do trend-deviation; RCH_A would be the y-o-y %)
  purchase = TOTAL      all dwellings (vs DW_NEW / DW_EXST)
  geo      = country / aggregate (PT, ES, DE, ..., EA20, EU27_2020)
  time     = quarterly periods, '2024-Q3'

JSON-stat returns one cube for all requested geos, so a single request
is enough (no per-country fan-out — Eurostat is a single reliable
source; if the call fails the whole HPI is unavailable anyway).

Eurostat HPI is quarterly, so a weekly cron is plenty (idempotent
upsert).

Env:
  EUROSTAT_API_BASE  override the dissemination base if Eurostat moves
                      it. default below.
  EUROSTAT_HPI_GEOS  comma list of geo codes.
                      default: PT,ES,IE,NL,DE,FR,IT,EA20,EU27_2020
  DATABASE_URL       postgres connection, from postgres-secrets
"""

import asyncio
import logging
import os
import re
from datetime import datetime, timezone

import httpx

from pg_database import upsert_indicators
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

EUROSTAT_API_BASE = os.getenv(
    "EUROSTAT_API_BASE",
    "https://ec.europa.eu/eurostat/api/dissemination/statistics/1.0",
).rstrip("/")
DATASET = "prc_hpi_q"

_DEFAULT_GEOS = "PT,ES,IE,NL,DE,FR,IT,EA20,EU27_2020"
GEOS = [
    g.strip().upper()
    for g in os.getenv("EUROSTAT_HPI_GEOS", _DEFAULT_GEOS).split(",")
    if g.strip()
]

# Index level (2015=100), all dwellings. Bounded history — the recent
# regime is what the bubble context cares about.
UNIT = "I15_Q"
PURCHASE = "TOTAL"
SINCE_PERIOD = "2000-Q1"

_QUARTER_END = {1: (3, 31), 2: (6, 30), 3: (9, 30), 4: (12, 31)}
_PERIOD_Q = re.compile(r"^(\d{4})-?Q([1-4])$", re.IGNORECASE)


def _period_to_iso(period: str) -> str | None:
    """Eurostat quarterly period -> ISO timestamp at quarter end (UTC).

    '2024-Q3' -> 2024-09-30T00:00:00+00:00. Anything else -> None
    (skipped by the caller).
    """
    m = _PERIOD_Q.match((period or "").strip())
    if not m:
        return None
    year, q = int(m.group(1)), int(m.group(2))
    month, day = _QUARTER_END[q]
    return f"{year:04d}-{month:02d}-{day:02d}T00:00:00+00:00"


def _inv_index(dimension: dict, name: str) -> dict[int, str]:
    """position -> code map for one JSON-stat dimension.

    Eurostat usually emits category.index as {code: pos}; the spec also
    allows a [code, ...] list. Handle both.
    """
    cat = dimension.get(name, {}).get("category", {}).get("index", {})
    if isinstance(cat, list):
        return {i: code for i, code in enumerate(cat)}
    if isinstance(cat, dict):
        return {int(pos): code for code, pos in cat.items()}
    return {}


def _decode_jsonstat(js: dict) -> list[tuple[str, str, float]]:
    """Decode a JSON-stat cube into [(geo, period, value), ...].

    The flat `value` map is keyed by a row-major linear index over the
    dimensions listed in `id` with cardinalities `size`. We only need
    the geo and time positions; the filtered dims (freq/unit/purchase)
    collapse to size 1 but the general unravel doesn't care.
    """
    ids = js.get("id") or []
    size = js.get("size") or []
    if not ids or len(ids) != len(size):
        logger.error("Eurostat JSON-stat: id/size mismatch (%s / %s)",
                      ids, size)
        return []

    dims = js.get("dimension", {})
    try:
        gi_dim = ids.index("geo")
        ti_dim = ids.index("time")
    except ValueError:
        logger.error("Eurostat JSON-stat: missing geo/time dim in %s", ids)
        return []

    geo_inv = _inv_index(dims, "geo")
    time_inv = _inv_index(dims, "time")

    # Row-major strides.
    strides = [1] * len(size)
    for k in range(len(size) - 2, -1, -1):
        strides[k] = strides[k + 1] * size[k + 1]

    values = js.get("value")
    if isinstance(values, list):
        items = enumerate(values)
    elif isinstance(values, dict):
        items = ((int(k), v) for k, v in values.items())
    else:
        logger.error("Eurostat JSON-stat: unexpected value type %s",
                      type(values).__name__)
        return []

    out: list[tuple[str, str, float]] = []
    for lin, val in items:
        if val is None:
            continue
        gi = (lin // strides[gi_dim]) % size[gi_dim]
        ti = (lin // strides[ti_dim]) % size[ti_dim]
        geo = geo_inv.get(gi)
        period = time_inv.get(ti)
        if not geo or not period:
            continue
        ts = _period_to_iso(period)
        if ts is None:
            continue
        try:
            out.append((geo, ts, float(val)))
        except (ValueError, TypeError):
            continue
    return out


async def main() -> None:
    url = f"{EUROSTAT_API_BASE}/data/{DATASET}"
    params: list[tuple[str, str]] = [
        ("format", "JSON"),
        ("lang", "EN"),
        ("unit", UNIT),
        ("purchase", PURCHASE),
        ("sinceTimePeriod", SINCE_PERIOD),
    ]
    params += [("geo", g) for g in GEOS]

    logger.info(
        "Eurostat HPI ingestion: dataset=%s unit=%s geos=%s",
        DATASET, UNIT, ",".join(GEOS),
    )

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, params=params, timeout=30)
            resp.raise_for_status()
            js = resp.json()
    except Exception as e:
        logger.error("Eurostat fetch failed: %s", e)
        return

    decoded = _decode_jsonstat(js)
    if not decoded:
        logger.warning(
            "Eurostat HPI produced 0 rows — check EUROSTAT_API_BASE / "
            "dataset dims. Nothing written.",
        )
        return

    # series_id keeps the Eurostat geo code (PT, EA20, EU27_2020, ...).
    rows = [
        (f"EUROSTAT_HPI_{geo}", ts, val) for geo, ts, val in decoded
    ]
    n = upsert_indicators(rows)

    geos_seen = sorted({geo for geo, _, _ in decoded})
    logger.info(
        "Eurostat HPI done: %d observations upserted across %d geos "
        "(%s) (run %s).",
        n, len(geos_seen), ",".join(geos_seen),
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


if __name__ == "__main__":
    asyncio.run(main())
