"""One-shot macro indicators backfill (Onda 12 Sprint 1, Camada B).

Idempotent full-history fetch for the 5 indicators in
``macro_repository.INDICATORS``. Designed for manual invocation, not
scheduled — the CronJob uses ``macro_fetcher.py`` with ``mode="daily"``
and a short lookback window instead.

Invocation
----------
Inside the cluster::

    kubectl -n personal-agent exec -it deploy/personal-agent-api -- \\
        sh -c 'cd /app/personal-agent && python jobs/macro_backfill.py'

Locally against a copy of the DB::

    DB_PATH=/path/to/agent.db python jobs/macro_backfill.py

Guardrails
----------
1. Pre-flight: prints the existing ``macro_indicators`` row count and
   sleeps :data:`WARM_UP_S` seconds before kicking off; this protects
   against accidentally running it twice in quick succession (e.g. a
   mis-targeted ``kubectl exec``) and gives the operator a window to
   ``Ctrl+C`` after seeing they're pointing at the wrong DB.
2. ``mode="backfill"`` is forwarded to ``macro_fetcher.run_all``: this
   makes "zero numeric in window" a fatal error per indicator (caught,
   logged, tallied), as opposed to the daily mode's "empty = warning".
3. Idempotency: the underlying upsert is ``INSERT OR IGNORE`` on
   PRIMARY KEY ``(indicator, ts)``, so re-running this script after a
   successful backfill inserts 0 new rows — proven by the Checkpoint 4
   "run twice" assertion.

Sources
-------
* CAPE (``cape_shiller``)  : multpl scrape, 1871-> (live row filtered).
* VIX  (``vix``)            : FRED VIXCLS, 1990->.
* HY OAS (``hy_oas``)        : FRED BAMLH0A0HYM2. **Capped to a rolling
  ~3-year window** by a FRED licensing change around April 2026 that
  applied to the entire ICE BofA family. The underlying series starts
  1996-12-31 but FRED no longer serves the pre-cap history. Long-history
  HY OAS needs a different vendor (ICE direct, Bloomberg) — operator
  decision at PR review, no auto-fallback.
* SP500 (``sp500_close``)    : FRED SP500. **Capped to ~10 years of
  daily history** by S&P / Dow Jones licensing — backfill fetches what
  is available with no auto-fallback to ^GSPC, Shiller's price column,
  or any other source. Long-history SP500 is an operator decision.
* 10y yield (``tnx_yield``) : FRED DGS10, 1962->.

Reports
-------
At the end the script emits a single ``log_event("macro_backfill_run")``
with per-indicator breakdown + DB date range, and prints a human-readable
report to stdout for the operator running ``kubectl exec``.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone

# Bootstrap sibling imports the same way macro_fetcher does — works under
# both ``python jobs/macro_backfill.py`` and ``python -m jobs.macro_backfill``.
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_SELF_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr                     # noqa: E402
from log_config import setup_logging, log_event   # noqa: E402
from jobs import macro_fetcher as mf              # noqa: E402

setup_logging()

WARM_UP_S = 3   # operator-abort window before the fetch starts


def _preflight(stream=None) -> dict[str, int]:
    """Print existing row counts, then sleep so the operator can abort.

    Returns ``count_by_indicator()`` so the caller has the baseline for
    the post-run delta. ``stream`` is a test seam — defaults to stdout.
    """
    stream = stream or sys.stdout
    counts = mr.count_by_indicator()
    total = sum(counts.values())
    print(
        f"Existing rows: {total}. Idempotent (INSERT OR IGNORE). "
        f"Proceeding in {WARM_UP_S}s (Ctrl+C to abort)",
        file=stream, flush=True,
    )
    if counts:
        # Show the per-indicator baseline so the operator can spot e.g.
        # a partial previous run before re-launching.
        for ind in mr.INDICATORS:
            n = counts.get(ind, 0)
            print(f"  {ind:14}: {n} rows", file=stream, flush=True)
    try:
        time.sleep(WARM_UP_S)
    except KeyboardInterrupt:
        print("\nAborted before fetch started.", file=stream, flush=True)
        sys.exit(130)   # 128 + SIGINT
    return counts


def _format_report(summary: dict, ranges: dict[str, dict | None]) -> str:
    """Build the end-of-run human report from the orchestrator summary
    and the per-indicator (first_ts, last_ts) ranges from the DB.

    Carries the ``updated`` counter introduced for the CAPE
    ``update_on_change`` write path so the operator can tell apart
    "row already there, identical value" (skipped) from "row already
    there, value restated upstream" (updated). For FRED indicators
    this counter is always 0 — they use ``on_conflict="ignore"``.
    """
    totals = summary["totals"]
    lines = [
        f"Indicators: {len(mr.INDICATORS)}. "
        f"Inserted: {totals['inserted']}. "
        f"Updated: {totals.get('updated', 0)}. "
        f"Skipped: {totals['skipped']}. "
        f"Failed: {totals['failed']}.",
        "",
        "Per indicator:",
    ]
    for ind in mr.INDICATORS:
        b = summary["by_indicator"].get(ind, {})
        rng = ranges.get(ind)
        if "error" in b:
            lines.append(f"  {ind:14}: FAILED — {b['error']}")
            continue
        # Build the optional [dropped_*] suffix only if something was dropped.
        extras = []
        if b.get("dropped_policy"):
            extras.append(f"dropped_policy={b['dropped_policy']}")
        if b.get("dropped_source"):
            extras.append(f"dropped_source={b['dropped_source']}")
        extra_str = f" [{', '.join(extras)}]" if extras else ""
        if rng is None:
            lines.append(
                f"  {ind:14}: 0 rows in DB (fetched={b.get('fetched', 0)})"
                f"{extra_str}"
            )
        else:
            lines.append(
                f"  {ind:14}: {rng['count']} rows in DB, "
                f"{rng['first_ts']} → {rng['last_ts']}, "
                f"inserted={b.get('inserted', 0)}, "
                f"updated={b.get('updated', 0)}, "
                f"skipped={b.get('skipped_dup', 0)}{extra_str}"
            )
    # FRED history caps documented inline so the operator running
    # kubectl exec sees them without having to dig in module docstrings.
    lines += [
        "",
        "FRED history caps (no auto-fallback — operator decisions at review):",
        "  sp500_close  : ~10y, S&P / Dow Jones licensing (alts: ^GSPC, Shiller)",
        "  hy_oas       : rolling ~3y, ICE BofA family change ~April 2026",
        "                  (alts: ICE direct, Bloomberg)",
        "  VIX / DGS10  : unaffected — full history.",
    ]
    return "\n".join(lines)


def main(*, run_all=None, stream=None) -> int:
    """Pre-flight → backfill → report. Returns process exit code.

    ``run_all`` is a test seam (defaults to ``macro_fetcher.run_all``);
    ``stream`` defaults to stdout. Mirrors :func:`macro_fetcher.__main__`'s
    exit-code rule: 0 if any indicator succeeded, 1 only if all failed.
    """
    stream = stream or sys.stdout
    _preflight(stream=stream)

    runner = run_all or mf.run_all
    summary = runner(mode=mf.MODE_BACKFILL)

    ranges = {ind: mr.get_ts_range(ind) for ind in mr.INDICATORS}
    report = _format_report(summary, ranges)
    print(file=stream)
    print(report, file=stream, flush=True)

    log_event(
        "macro_backfill_run",
        duration_ms=summary["duration_ms"],
        by_indicator={
            ind: {
                **summary["by_indicator"].get(ind, {}),
                "range": ranges.get(ind),
            }
            for ind in mr.INDICATORS
        },
        totals=summary["totals"],
    )

    n_total = len(mr.INDICATORS)
    n_failed = summary["totals"]["failed"]
    return 0 if n_failed < n_total else 1


if __name__ == "__main__":
    sys.exit(main())
