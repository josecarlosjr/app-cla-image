"""Macro indicators daily fetcher (Onda 12 Sprint 1, Camada B).

Daily cron entry point. For each of the 5 indicators in
``macro_repository.INDICATORS``, hits the upstream source (FRED for 4,
Shiller Yale XLSX for CAPE), upserts via ``macro_repository`` (idempotent
INSERT OR IGNORE), and emits structured ``log_event`` records.

Invocation:
    python jobs/macro_fetcher.py
(CronJob WORKDIR is ``/app/personal-agent``; the bootstrap below ensures
relative imports work regardless of how the script is launched.)

This file is the **3a skeleton** — function signatures + dispatch +
entry point in place; the actual fetch logic lands in 3b (Shiller),
3c (FRED) and 3d (orchestration).
"""

from __future__ import annotations

import os
import sys

# Make sibling modules (macro_repository, log_config) importable when this
# script is launched as ``python jobs/macro_fetcher.py`` from inside
# /app/personal-agent.
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_SELF_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr                    # noqa: E402
from log_config import setup_logging, log_event  # noqa: E402

setup_logging()


# ---------------------------------------------------------------------------
# Per-source fetchers — each returns ``list[dict]`` ready for
# ``mr.upsert_observations(indicator, rows)``. Row contract:
#     {"ts": "YYYY-MM-DD", "value": float, "metadata": dict | None}
# Fetchers raise on hard failure; the orchestrator catches and logs a
# ``macro_fetch_error`` event so a single bad source doesn't kill the run.
# ---------------------------------------------------------------------------

def fetch_shiller_cape(*, start: str | None = None) -> list[dict]:
    """Fetch the Shiller CAPE monthly series from Yale's XLSX (canonical
    URL first, then a public-mirror fallback). Returns rows tagged with
    metadata ``{column, xlsx_url, vintage}``. Raises ``RuntimeError`` if
    both URLs fail. **Implemented in step 3b.**"""
    raise NotImplementedError("step 3b -- Shiller XLSX fetcher")


def fetch_fred_series(indicator: str, *, start: str | None = None) -> list[dict]:
    """Fetch a FRED daily series (one of vix, hy_oas, sp500_close,
    tnx_yield). Returns rows tagged with metadata
    ``{series_id, realtime_start, realtime_end}`` from FRED's per-row
    revisions. Raises ``RuntimeError`` on FRED error/timeout.
    **Implemented in step 3c.**"""
    raise NotImplementedError("step 3c -- FRED fetcher")


# ---------------------------------------------------------------------------
# Dispatch — keyed exactly to ``macro_repository.INDICATORS``. The
# orchestrator (step 3d) iterates this dict to drive the run.
# ---------------------------------------------------------------------------

_FETCHERS = {
    "cape_shiller": fetch_shiller_cape,
    "vix":         lambda **kw: fetch_fred_series("vix", **kw),
    "hy_oas":      lambda **kw: fetch_fred_series("hy_oas", **kw),
    "sp500_close": lambda **kw: fetch_fred_series("sp500_close", **kw),
    "tnx_yield":   lambda **kw: fetch_fred_series("tnx_yield", **kw),
}


# ---------------------------------------------------------------------------
# Orchestration -- populated in step 3d.
# ---------------------------------------------------------------------------

def run_all(*, start: str | None = None) -> dict:
    """Run every fetcher, upsert results, emit per-indicator
    ``macro_fetch`` events, a final ``macro_fetcher_run`` summary, and
    a ``macro_fetch_error`` per failing source. Returns
    ``{by_indicator: {...}, totals: {inserted, skipped, failed},
    duration_ms: int}``. **Implemented in step 3d.**"""
    raise NotImplementedError("step 3d -- orchestrator")


if __name__ == "__main__":
    run_all()
