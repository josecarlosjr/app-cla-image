"""Bubble Engine orchestrator (Onda 13, Step 2).

The scoring core in `bubble_scoring.py` is PURE — data in, a Signal out.
This module is the "thin shell" its docstring promised: it fetches the
live data each signal needs, builds the three Signals, and runs
`composite_score` once per watchlist ticker.

Scope (decided for Step 2): **per ticker**, combining

  - momentum         ← price   (BSADF explosive-root test, quant_features) "ticker+preço"
  - temporal         ← news    (attention acceleration, temporal.py)    "ticker+news"
  - graph_fragility  ← news    (knowledge-graph contagion surface)      "ticker+news"
  - valuation        ← quant   (Shiller CAPE, trailing P/E fallback)    "ticker+preço"
  - credit           ← quant   (BIS credit-to-GDP gap, macro backdrop)

i.e. each ticker is scored from its own price history AND from the
news/graph signal attached to it, plus the valuation and macro-credit
backdrop. Sector-level ("categoria") scoring is deliberately out of
scope here. sentiment/structure remain unimplemented (weight 0).

IMPORTANT — no automatic alerting. Per docs/backtest-plan.md §8 the
sequence is: Step 2 (this — real scores per ticker, *no* Telegram) →
backtest (calibrate weights/thresholds) → forward-test the narrative
signals → only then automatic bubble alerts. So this module computes and
surfaces scores; it never sends a message. `should_flag` is reported per
ticker as information, not as a trigger.

Layering for testability mirrors bubble_scoring: the pure functions
(`score_ticker`, `temporal_ratio_for_ticker`, the ticker→news map) live
at module top and import nothing heavy, so they're unit-testable with no
DB / cluster. The live-data fetch (`gather_and_score`) lazy-imports
pg_database / temporal / quant_alerts inside the function.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from bubble_scoring import (
    momentum_signal,
    temporal_signal,
    graph_fragility_signal,
    valuation_signal,
    credit_signal,
    composite_score,
    DEFAULT_WEIGHTS,
    FLAG_MIN_COMPOSITE,
    FLAG_MIN_CONFIDENCE,
)

logger = logging.getLogger(__name__)

# Mirrors quant_detectors.WINDOW_DAYS — the LPPL/GSADF fit window. We cap
# the bar count at this so n_points reflects what a fit actually used
# (the detector reads the most-recent WINDOW_DAYS closes), and so the
# momentum confidence ramp (full at ~250 pts) lines up with reality.
_DETECTOR_WINDOW = 252

# How much BSADF history the momentum persistence rule gets to see.
# It needs _GSADF_MIN_CONSECUTIVE (2) observations; a few more are
# fetched so the detail string can report the length of a longer run,
# and so one missed cron day doesn't collapse the history to a single
# point. Same batched query either way, so the extra rows are free.
_BSADF_HISTORY_POINTS = 5


# The "ticker+news" link. temporal.py measures attention acceleration per
# *news category* (pillars.py categories), not per ticker — so each price
# ticker maps to the news theme(s) whose acceleration is a sensible proxy
# for it, and we take the strongest (max ratio) across them. Crypto has no
# dedicated news category, so BTC/ETH lean on "financas" here while their
# *ticker-specific* news signal comes through graph_fragility (the KG has
# bitcoin/ethereum entities). Categories MUST be valid keys of
# pillars.CATEGORY_TO_PILLAR.
TICKER_NEWS_CATEGORIES: dict[str, list[str]] = {
    "SPY": ["financas"],
    "QQQ": ["chips_ia", "financas"],          # Nasdaq — tech-heavy
    "IWM": ["financas"],
    "BTC-USD": ["financas"],
    "ETH-USD": ["financas"],
    "XLK": ["chips_ia", "ciberseguranca", "ciencia"],
    "XLE": ["energia"],
    "XLF": ["financas"],
    "GLD": ["financas"],
    "TLT": ["financas"],
    "HYG": ["financas"],
}


# ---------------------------------------------------------------------------
# Pure layer — no DB, no network (unit-testable)
# ---------------------------------------------------------------------------

def temporal_ratio_for_ticker(
    ticker: str, accel_by_category: dict[str, float],
) -> float | None:
    """Acceleration ratio for `ticker` = max over its mapped categories.

    `accel_by_category` is {category: ratio} from temporal.detect_
    acceleration(). Returns None when the ticker has no mapped category
    present in the data, so temporal_signal abstains rather than
    inventing a 1.0.
    """
    cats = TICKER_NEWS_CATEGORIES.get(ticker, [])
    ratios = [accel_by_category[c] for c in cats if c in accel_by_category]
    return max(ratios) if ratios else None


def score_ticker(
    ticker: str,
    *,
    bsadf_recent: list[float] | None,
    n_points: int | None,
    accel_ratio: float | None,
    graph_edges: list | None,
    pe: float | None = None,
    cape: float | None = None,
    credit_gap_pct: float | None = None,
    context: dict | None = None,
) -> dict:
    """Build the five Signals for one ticker and run the composite.

    Pure: every input is already-fetched data. valuation (pe/cape) and
    credit (credit_gap_pct) default to None so a caller with only the
    price+news inputs still gets a valid score (those signals abstain).
    Returns the composite_score dict (composite, aggregate_confidence,
    coverage, flagged, components, ...) plus the ticker and optional
    display context.

    `bsadf_recent` is the recent BSADF history, oldest first — a list,
    not a scalar, because momentum requires the exceedance to persist.
    It replaced `lppl_bubble_prob`: see momentum_signal on why R² of a
    log-periodic fit was not measuring what it was weighted for.
    """
    signals = [
        momentum_signal(bsadf_recent, n_points),
        temporal_signal(accel_ratio),
        graph_fragility_signal(graph_edges),
        valuation_signal(pe, cape),
        credit_signal(credit_gap_pct),
    ]
    row = {"ticker": ticker, **composite_score(signals)}
    if context:
        row["context"] = context
    return row


# ---------------------------------------------------------------------------
# Impure layer — live data fetch (lazy heavy imports, never crash on
# enrichment failure: a signal abstains instead, same discipline as the
# scoring core and quant_alerts)
# ---------------------------------------------------------------------------

def _accel_by_category() -> dict[str, float]:
    try:
        from temporal import detect_acceleration
        return {a["category"]: a["ratio"] for a in detect_acceleration()}
    except Exception as e:  # noqa: BLE001 — enrichment, must not break scoring
        logger.warning(
            "temporal acceleration unavailable (%s); temporal signal abstains", e,
        )
        return {}


def _load_approved_graph() -> dict:
    try:
        from quant_alerts import _load_approved_graph as load
        return load()
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "approved graph unavailable (%s); graph_fragility abstains", e,
        )
        return {"entities": [], "relationships": []}


def _us_credit_gap() -> float | None:
    """Latest US BIS credit-to-GDP gap, from the SQLite macro catalog.

    The BIS data lives in ``macro_indicators`` (Onda 12 C1), keyed
    lowercase (``bis_credit_gap_us``) — NOT in the quant Postgres, which
    has zero BIS rows (that was the CRED=0.00 bug: the orchestrator read
    the empty Postgres). A negative gap (deleveraging) is REAL data
    (credit_signal -> score 0, conf 0.7, "sem froth de crédito"), not
    missing data; only a true absence returns None (signal abstains).
    US-only for now — the watchlist is US-listed; multi-país é o passo
    seguinte.
    """
    try:
        import macro_repository as mr
        row = mr.get_latest("bis_credit_gap_us")
        return float(row["value"]) if row is not None else None
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "credit gap unavailable (%s); credit signal abstains", e,
        )
        return None


def _cape_shiller() -> float | None:
    """Latest Shiller CAPE, from the SQLite macro catalog.

    Same source and shape as ``_us_credit_gap``: ``macro_indicators``
    (Onda 12), keyed ``cape_shiller``, monthly, 1871-> . None on any
    failure, which makes ``valuation_signal`` fall back to its
    trailing-P/E proxy (conf 0.3) instead of crashing — exactly the
    behaviour before this was wired up.
    """
    try:
        import macro_repository as mr
        row = mr.get_latest("cape_shiller")
        return float(row["value"]) if row is not None else None
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "CAPE unavailable (%s); valuation falls back to the P/E proxy", e,
        )
        return None


# Which tickers the CAPE legitimately describes.
#
# CAPE is the cyclically-adjusted P/E of the S&P 500 — a US large-cap
# EQUITY multiple. Feeding it to gold, treasuries, high-yield credit or
# crypto would assert "this is expensive" on the strength of a number
# computed from something else entirely. Those keep cape=None and fall
# back to the trailing-P/E proxy, which for them abstains anyway (no
# meaningful P/E), leaving valuation at conf 0.0 — unchanged from today.
#
# Explicit set, not a heuristic: no inferring "equity" from the absence
# of "-USD" or from a P/E being present. A new ticker gets no CAPE until
# someone adds it here on purpose.
#
# QQQ/IWM/XLK/XLE/XLF are not the S&P itself, so this is an
# approximation — the US equity valuation backdrop, not each index's own
# CAPE. It is the same approximation ``credit_signal`` already makes by
# giving every ticker the US credit-to-GDP gap, and it is why the detail
# string says "CAPE", naming the source rather than implying it was
# computed per ticker.
_CAPE_TICKERS: frozenset[str] = frozenset({
    "^GSPC",   # the S&P 500 index itself — what CAPE is actually computed on
    "SPY",     # S&P 500 ETF
    "QQQ",     # Nasdaq 100
    "IWM",     # Russell 2000
    "XLK", "XLE", "XLF",   # US sector SPDRs
})


def _latest_vix() -> tuple[float | None, str | None]:
    """Latest VIX and its dashboard band, for the STRESS dimension.

    Reuses pg_database's own ``_vix_status`` so the Bubble Engine and
    the Quant dashboard cannot disagree about what "nervoso" means.
    Degrades to (None, None), which renders STRESS from the drawdown
    alone.
    """
    try:
        import pg_database as pg
        series = pg.get_indicator_series("VIXCLS", 30)
        if not series:
            return None, None
        latest = float(series[-1]["value"])
        return latest, pg._vix_status(latest)
    except Exception as e:  # noqa: BLE001
        logger.warning("VIX unavailable (%s); stress uses drawdown only", e)
        return None, None


def _graph_edges(ticker: str, graph: dict) -> list[str]:
    """Reuse quant_alerts' 1-2 hop walk so the Bubble Engine and the
    quant alerts see the *same* graph neighbourhood (the edge cap in
    bubble_scoring already mirrors quant_alerts on purpose)."""
    try:
        from quant_alerts import _fetch_graph_context
        return _fetch_graph_context(ticker, graph)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "graph walk failed for %s (%s); graph_fragility abstains", ticker, e,
        )
        return []


def gather_and_score() -> dict:
    """Fetch live data and score every watchlist ticker.

    On-demand (no persisted table): a few indexed queries + a pure graph
    walk per ticker, same cost profile as the quant dashboard endpoint.
    Returns a report dict ready to serve as JSON / render on the Bubble
    Engine page. Scores only — see module docstring on why nothing here
    sends an alert.
    """
    import pg_database as pg

    watchlist = pg.get_watchlist()
    tickers = [w["ticker"] for w in watchlist]
    bar_counts = pg.get_bar_counts(tickers)
    # Momentum needs the recent BSADF history, not just the latest
    # point, so a lone threshold crossing cannot score on its own.
    # One batched query for every ticker — see get_recent_feature_by_target.
    bsadf_hist = pg.get_recent_feature_by_target(
        "gsadf_stat", n=_BSADF_HISTORY_POINTS,
    )
    accel = _accel_by_category()
    graph = _load_approved_graph()
    # Credit is a macro backdrop; the watchlist is US-listed (plus global
    # crypto/gold), so every ticker gets the US credit-to-GDP gap (SQLite
    # macro catalog — the Postgres BIS series is empty).
    us_credit_gap = _us_credit_gap()
    # One read for the whole run: CAPE is monthly and market-wide, not
    # per ticker. Handed only to the equity tickers (see _CAPE_TICKERS).
    cape = _cape_shiller()

    import risk_dimensions as rd
    from bubble_scoring import _GSADF_CRIT95, _GSADF_MIN_CONSECUTIVE
    vix_latest, vix_status = _latest_vix()

    rows: list[dict] = []
    for w in watchlist:
        t = w["ticker"]
        ticker_cape = cape if t in _CAPE_TICKERS else None
        rows.append(score_ticker(
            t,
            bsadf_recent=bsadf_hist.get(t),
            n_points=min(bar_counts.get(t, 0), _DETECTOR_WINDOW),
            accel_ratio=temporal_ratio_for_ticker(t, accel),
            graph_edges=_graph_edges(t, graph),
            pe=w.get("pe"),
            cape=ticker_cape,
            credit_gap_pct=us_credit_gap,
            context={
                "close": w.get("close"),
                "change_pct_30d": w.get("change_pct_30d"),
                "pe": w.get("pe"),
                "cape": ticker_cape,
                "gsadf_explosive": w.get("gsadf_explosive", False),
            },
        ))
        # The two per-ticker dimensions. VALUATION and CRÉDITO are
        # market-wide and would be the same text on all 12 rows, so
        # they go in the header instead (see `dims` below) rather than
        # repeating — the panel should not imply they were measured
        # per asset.
        rows[-1]["dimensions"] = [
            rd.explosive_dimension(
                bsadf_hist.get(t), _GSADF_CRIT95, _GSADF_MIN_CONSECUTIVE,
            ),
            rd.stress_dimension(
                w.get("drawdown_pct_rank"), w.get("drawdown_pct"),
                vix_latest, vix_status,
            ),
        ]

    # The two market-wide dimensions, once, for the page header. Shown
    # here rather than on every row so the panel does not suggest the
    # CAPE or the US credit gap were measured per ticker.
    dims = {
        "dimensions": [
            rd.valuation_dimension(cape),
            rd.credit_dimension(us_credit_gap),
        ],
        "legend": rd.LEGEND,
        "scope": "mercado (repetem-se em todos os tickers)",
    }

    # Strongest (composite, then evidence) first.
    rows.sort(
        key=lambda r: (r["composite"], r["aggregate_confidence"]),
        reverse=True,
    )

    return {
        "engine": "bubble_orchestrator",
        "step": "Onda 13 / Step 2",
        "scope": "per-ticker · preço (momentum) + notícias (temporal, graph) + quant (valuation, credit)",
        "alerting_enabled": False,
        "alerting_note": (
            "scores apenas — alertas automáticos seguem bloqueados até o "
            "backtest validar a calibração (docs/backtest-plan.md §8)"
        ),
        "weights": DEFAULT_WEIGHTS,
        "flag_rule": {
            "min_composite": FLAG_MIN_COMPOSITE,
            "min_confidence": FLAG_MIN_CONFIDENCE,
        },
        "risk_dimensions": dims,
        "n_tickers": len(rows),
        "n_flagged": sum(1 for r in rows if r["flagged"]),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tickers": rows,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(gather_and_score(), indent=2, ensure_ascii=False))
