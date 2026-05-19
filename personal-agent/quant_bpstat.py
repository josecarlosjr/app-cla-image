"""Banco de Portugal (BPstat) house-price ingestion.

Adds GRANULAR Portuguese residential property data — the dimension the
quant layer was missing for a PT-based user. Eurostat (gap #2) gives a
single national PT HPI; BPstat gives the Banco de Portugal series from
the national source, incl. total / new / existing dwellings and the
year-on-year rate.

Writes into `quant_indicators` (same TimescaleDB hypertable as the
FRED / BIS / Eurostat series) — no schema change, consistent with
gaps #1 and #2.

Source: BPstat Data API v1 (https://bpstat.bportugal.pt/data/v1).
Free, no key. The API is *series-id driven*, so it's a two-step call
per series:

  1. GET /series/?lang=EN&series_ids={id}
        -> series metadata: domain id + dataset id + human label
  2. GET /domains/{domain}/datasets/{dataset}/?lang=EN&series_ids={id}
        -> JSON-stat cube (time dimension flagged via role.time)

Default series (domain 39 "Preços de habitação", quarterly):
  12559645  Indice de precos da habitacao - Total      (index level)
  12559646  ...                                          (sibling)
  12559647  ...                                          (sibling)
  5739035   Indice de precos da habitacao - Total - TVH  (y-o-y %)

12559645 + 5739035 are confirmed; 12559646/47 are the new/existing
siblings that appear alongside 12559645 in the official series viewer.
All are env-overridable and the job logs each series' label from the
metadata response, so the exact set can be verified / pruned from the
cron log on first run — same verify-via-log loop as BIS / Eurostat.

Env:
  BPSTAT_API_BASE    override if BPstat moves it.
                     default https://bpstat.bportugal.pt/data/v1
  BPSTAT_SERIES_IDS  comma list of numeric series ids.
                     default 12559645,12559646,12559647,5739035
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

BPSTAT_API_BASE = os.getenv(
    "BPSTAT_API_BASE", "https://bpstat.bportugal.pt/data/v1",
).rstrip("/")

_DEFAULT_SERIES = "12559645,12559646,12559647,5739035"
SERIES_IDS = [
    s.strip()
    for s in os.getenv("BPSTAT_SERIES_IDS", _DEFAULT_SERIES).split(",")
    if s.strip()
]

LANG = "EN"

# Bank-of-Portugal portal sits behind the same kind of UA wall as BIS;
# a normal browser UA is enough (no auth).
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/json",
}

_QUARTER_END = {1: (3, 31), 2: (6, 30), 3: (9, 30), 4: (12, 31)}
_PERIOD_Q = re.compile(r"^(\d{4})[-/]?Q([1-4])$", re.IGNORECASE)
_PERIOD_M = re.compile(r"^(\d{4})[-/](\d{1,2})$")
_PERIOD_D = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
_PERIOD_Y = re.compile(r"^(\d{4})$")
_MONTH_END = {
    1: 31, 2: 28, 3: 31, 4: 30, 5: 31, 6: 30,
    7: 31, 8: 31, 9: 30, 10: 31, 11: 30, 12: 31,
}


def _period_to_iso(period: str) -> str | None:
    """BPstat period code -> ISO timestamp at period end (UTC).

    Handles quarterly ('2024-Q3' / '2024Q3'), monthly ('2024-09'),
    explicit ISO date, and annual ('2024'). Anything else -> None.
    """
    p = (period or "").strip()
    m = _PERIOD_Q.match(p)
    if m:
        year, q = int(m.group(1)), int(m.group(2))
        month, day = _QUARTER_END[q]
        return f"{year:04d}-{month:02d}-{day:02d}T00:00:00+00:00"
    m = _PERIOD_D.match(p)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T00:00:00+00:00"
    m = _PERIOD_M.match(p)
    if m:
        year, mon = int(m.group(1)), int(m.group(2))
        if 1 <= mon <= 12:
            return f"{year:04d}-{mon:02d}-{_MONTH_END[mon]:02d}T00:00:00+00:00"
    m = _PERIOD_Y.match(p)
    if m:
        return f"{int(m.group(1)):04d}-12-31T00:00:00+00:00"
    return None


def _first(obj):
    """series metadata comes back as a list (or {'series':[...]})."""
    if isinstance(obj, list):
        return obj[0] if obj else None
    if isinstance(obj, dict):
        for key in ("series", "results", "data"):
            v = obj.get(key)
            if isinstance(v, list) and v:
                return v[0]
        return obj
    return None


async def _series_meta(
    client: httpx.AsyncClient, series_id: str,
) -> tuple[str, str, str] | None:
    """Return (domain_id, dataset_id, label) for a series, or None."""
    url = f"{BPSTAT_API_BASE}/series/"
    try:
        resp = await client.get(
            url,
            params={"lang": LANG, "series_ids": series_id},
            headers=_HEADERS,
            timeout=30,
        )
        resp.raise_for_status()
        meta = _first(resp.json())
    except Exception as e:
        logger.error("BPstat %s metadata fetch failed: %s", series_id, e)
        return None
    if not isinstance(meta, dict):
        logger.error("BPstat %s: unexpected metadata shape", series_id)
        return None

    domains = meta.get("domain_ids") or meta.get("domains") or []
    if isinstance(domains, list) and domains:
        domain_id = str(domains[0])
    else:
        domain_id = str(domains) if domains else ""
    dataset_id = str(meta.get("dataset_id") or meta.get("dataset") or "")
    label = str(meta.get("label") or meta.get("name") or series_id)
    if not domain_id or not dataset_id:
        logger.error(
            "BPstat %s: missing domain/dataset in metadata (%s)",
            series_id, list(meta.keys()),
        )
        return None
    return domain_id, dataset_id, label


def _decode_jsonstat(js: dict) -> list[tuple[str, float]]:
    """Decode a BPstat JSON-stat cube -> [(period_code, value), ...].

    Robust to JSON-stat v1 (id/size under `dimension`) and v2 (top
    level), and finds the time dimension via role.time with a name
    fallback. We query one series at a time so non-time dims are size
    1, but the general row-major unravel doesn't rely on that.
    """
    ids = js.get("id") or js.get("dimension", {}).get("id") or []
    size = js.get("size") or js.get("dimension", {}).get("size") or []
    if not ids or len(ids) != len(size):
        logger.error("BPstat JSON-stat: id/size mismatch (%s / %s)",
                      ids, size)
        return []

    time_dim = None
    role_time = (js.get("role") or {}).get("time") or []
    if isinstance(role_time, list) and role_time:
        time_dim = role_time[0]
    if time_dim not in ids:
        time_dim = next(
            (d for d in ids
             if any(k in d.lower() for k in ("time", "date", "period"))),
            None,
        )
    if time_dim not in ids:
        logger.error("BPstat JSON-stat: no time dimension in %s", ids)
        return []
    ti_dim = ids.index(time_dim)

    cat = (
        js.get("dimension", {})
        .get(time_dim, {})
        .get("category", {})
        .get("index", {})
    )
    if isinstance(cat, list):
        time_inv = {i: code for i, code in enumerate(cat)}
    elif isinstance(cat, dict):
        time_inv = {int(pos): code for code, pos in cat.items()}
    else:
        logger.error("BPstat JSON-stat: bad time category")
        return []

    strides = [1] * len(size)
    for k in range(len(size) - 2, -1, -1):
        strides[k] = strides[k + 1] * size[k + 1]

    values = js.get("value")
    if isinstance(values, list):
        items = enumerate(values)
    elif isinstance(values, dict):
        items = ((int(k), v) for k, v in values.items())
    else:
        logger.error("BPstat JSON-stat: unexpected value type %s",
                      type(values).__name__)
        return []

    out: list[tuple[str, float]] = []
    for lin, val in items:
        if val is None:
            continue
        ti = (lin // strides[ti_dim]) % size[ti_dim]
        period = time_inv.get(ti)
        if not period:
            continue
        try:
            out.append((period, float(val)))
        except (ValueError, TypeError):
            continue
    return out


async def fetch_series(
    client: httpx.AsyncClient, series_id: str,
) -> list[tuple[str, str, float]]:
    """Resolve + fetch one BPstat series. Tolerates any failure."""
    meta = await _series_meta(client, series_id)
    if meta is None:
        return []
    domain_id, dataset_id, label = meta

    url = f"{BPSTAT_API_BASE}/domains/{domain_id}/datasets/{dataset_id}/"
    try:
        resp = await client.get(
            url,
            params={"lang": LANG, "series_ids": series_id},
            headers=_HEADERS,
            timeout=30,
        )
        resp.raise_for_status()
        js = resp.json()
    except Exception as e:
        logger.error("BPstat %s (%s) data fetch failed: %s",
                      series_id, label, e)
        return []

    obs = _decode_jsonstat(js)
    out: list[tuple[str, str, float]] = []
    for period, val in obs:
        ts = _period_to_iso(period)
        if ts is None:
            continue
        out.append((f"BPSTAT_{series_id}", ts, val))
    logger.info("BPstat %s [%s]: %d observations", series_id, label, len(out))
    return out


async def main() -> None:
    logger.info(
        "BPstat house-price ingestion: %d series (%s)",
        len(SERIES_IDS), ",".join(SERIES_IDS),
    )

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[fetch_series(client, s) for s in SERIES_IDS],
            return_exceptions=False,
        )

    all_rows = [row for rows in results for row in rows]
    if not all_rows:
        logger.warning(
            "BPstat ingestion produced 0 rows — check BPSTAT_API_BASE / "
            "BPSTAT_SERIES_IDS. Nothing written.",
        )
        return

    n = upsert_indicators(all_rows)
    n_series = sum(1 for rows in results if rows)
    logger.info(
        "BPstat ingestion done: %d observations upserted across %d/%d "
        "series (run %s).",
        n, n_series, len(SERIES_IDS),
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


if __name__ == "__main__":
    asyncio.run(main())
