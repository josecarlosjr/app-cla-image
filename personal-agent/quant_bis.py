"""BIS credit-to-GDP gap ingestion.

The credit-to-GDP gap (Borio & Drehmann, BIS) is the deviation of the
credit-to-GDP ratio from its long-run one-sided HP-filter trend. It is
the single best-validated early-warning indicator for banking crises
and credit-fuelled asset bubbles — Basel III's countercyclical capital
buffer is keyed to it. We pull the GAP series for a focused country set
into `quant_indicators` (same TimescaleDB hypertable as the FRED macro
series), so the dashboard / bubble alerts can read it next to the yield
curve, VIX, etc.

Source: BIS SDMX REST API, dataflow BIS,WS_CREDIT_GAP,1.0. Free, no key.

Series key: FREQ.COUNTRY.TC_BORROWERS.TC_LENDERS.CG_DTYPE
  Q  quarterly
  XX borrowers' country (US, PT, BR, GB, ...)
  P  private non-financial sector
  A  all lending sectors
  C  credit-to-GDP GAP   <- what we want
     (the same key with a trailing `A` is the ratio, `B` the trend)

Verified key shape from the BIS data portal, e.g. `Q.US.P.A.C` (US gap),
`Q.GB.P.A.C` (UK gap).

BIS publishes quarterly, so a weekly cron is plenty — the upsert is
idempotent so re-runs just re-confirm.

Env:
  BIS_API_BASE  override if BIS moves the endpoint. The data-side host
                blocks unknown user-agents, so we send a browser UA.
                default: https://stats.bis.org/api/v1
  BIS_COUNTRIES comma list of borrower country codes
                default: US,PT,BR,GB,DE,FR,ES,CN,JP
  DATABASE_URL  postgres connection, from postgres-secrets
"""

import asyncio
import csv
import io
import logging
import os
import re
from datetime import datetime, timezone

import httpx

from pg_database import upsert_indicators
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

BIS_API_BASE = os.getenv("BIS_API_BASE", "https://stats.bis.org/api/v1").rstrip("/")
BIS_DATAFLOW = "BIS,WS_CREDIT_GAP,1.0"

_DEFAULT_COUNTRIES = "US,PT,BR,GB,DE,FR,ES,CN,JP"
COUNTRIES = [
    c.strip().upper()
    for c in os.getenv("BIS_COUNTRIES", _DEFAULT_COUNTRIES).split(",")
    if c.strip()
]

# Only pull a bounded history. The gap moves slowly (quarterly), and the
# bubble context only needs the recent regime, not 1961-onward.
START_PERIOD = "2000"

# BIS blocks the default httpx UA on the data host (same anti-bot we hit
# from Yahoo in monitor.py). A normal browser UA is enough — no auth.
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/vnd.sdmx.data+csv, text/csv, */*",
}

_QUARTER_END = {1: (3, 31), 2: (6, 30), 3: (9, 30), 4: (12, 31)}
_PERIOD_Q = re.compile(r"^(\d{4})-?Q([1-4])$", re.IGNORECASE)
_PERIOD_Y = re.compile(r"^(\d{4})$")


def _period_to_iso(period: str) -> str | None:
    """BIS TIME_PERIOD -> ISO timestamp at quarter/year end (UTC).

    Quarterly: '2024-Q3' -> 2024-09-30. Annual fallback: '2024' ->
    2024-12-31. Anything else is skipped (logged by the caller).
    """
    p = (period or "").strip()
    m = _PERIOD_Q.match(p)
    if m:
        year, q = int(m.group(1)), int(m.group(2))
        month, day = _QUARTER_END[q]
        return f"{year:04d}-{month:02d}-{day:02d}T00:00:00+00:00"
    m = _PERIOD_Y.match(p)
    if m:
        return f"{int(m.group(1)):04d}-12-31T00:00:00+00:00"
    return None


def _find_col(fieldnames: list[str], *needles: str) -> str | None:
    """Locate an SDMX-CSV column by case-insensitive substring.

    SDMX-CSV variants spell columns differently ('TIME_PERIOD' vs
    'TIME_PERIOD:Time period'), so match on a fragment instead of an
    exact name.
    """
    for fn in fieldnames:
        low = fn.lower()
        if any(n in low for n in needles):
            return fn
    return None


def _parse_sdmx_csv(text: str) -> list[tuple[str, float]]:
    """Return [(iso_ts, value), ...] from a BIS SDMX-CSV payload."""
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    time_col = _find_col(reader.fieldnames, "time_period", "time period")
    val_col = _find_col(reader.fieldnames, "obs_value", "observation value")
    if not time_col or not val_col:
        logger.error(
            "BIS CSV missing expected columns; headers=%s",
            reader.fieldnames,
        )
        return []

    out: list[tuple[str, float]] = []
    for row in reader:
        raw = (row.get(val_col) or "").strip()
        if raw in ("", "NaN", "NA", "."):
            continue
        ts = _period_to_iso(row.get(time_col, ""))
        if ts is None:
            continue
        try:
            out.append((ts, float(raw)))
        except (ValueError, TypeError):
            continue
    return out


async def fetch_country(
    client: httpx.AsyncClient, country: str,
) -> list[tuple[str, str, float]]:
    """Fetch the credit-to-GDP GAP for one country.

    Returns [(series_id, iso_ts, value), ...] ready for upsert_indicators.
    Tolerates any failure (logs, returns []): one bad country must not
    sink the whole run.
    """
    series_id = f"BIS_CREDIT_GAP_{country}"
    key = f"Q.{country}.P.A.C"
    url = f"{BIS_API_BASE}/data/{BIS_DATAFLOW}/{key}/all"
    params = {"format": "csv", "startPeriod": START_PERIOD}

    try:
        resp = await client.get(
            url, params=params, headers=_HEADERS, timeout=30,
        )
        resp.raise_for_status()
        body = resp.text
    except Exception as e:
        logger.error("BIS %s fetch failed: %s", country, e)
        return []

    # Defensive: if the host returns HTML (error page / bot wall) the
    # CSV parse would silently yield nothing — surface it instead.
    head = body.lstrip()[:1].lower()
    if head in ("<",):
        logger.error(
            "BIS %s: non-CSV response (first 120 chars: %r)",
            country, body[:120],
        )
        return []

    obs = _parse_sdmx_csv(body)
    logger.info("BIS %s: %d observations", country, len(obs))
    return [(series_id, ts, val) for ts, val in obs]


async def main() -> None:
    logger.info(
        "BIS credit-to-GDP gap ingestion: %d countries (%s)",
        len(COUNTRIES), ",".join(COUNTRIES),
    )

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[fetch_country(client, c) for c in COUNTRIES],
            return_exceptions=False,
        )

    all_rows = [row for rows in results for row in rows]
    if not all_rows:
        logger.warning(
            "BIS ingestion produced 0 rows — check BIS_API_BASE / key "
            "shape. Nothing written.",
        )
        return

    n = upsert_indicators(all_rows)
    n_countries = sum(1 for rows in results if rows)
    logger.info(
        "BIS ingestion done: %d observations upserted across %d/%d "
        "countries (run %s).",
        n, n_countries, len(COUNTRIES),
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


if __name__ == "__main__":
    asyncio.run(main())
