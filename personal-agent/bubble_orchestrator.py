"""Bubble Engine orchestrator (Onda 13, Step 2).

The scoring core in `bubble_scoring.py` is PURE — data in, a Signal out.
This module is the "thin shell" its docstring promised: it fetches the
live data each signal needs, builds the three Signals, and runs
`composite_score` once per watchlist ticker.

Scope (decided for Step 2): **per ticker**, combining

  - momentum         ← price   (LPPL bubble prob from quant_features)   "ticker+preço"
  - temporal         ← news    (attention acceleration, temporal.py)    "ticker+news"
  - graph_fragility  ← news    (knowledge-graph contagion surface)      "ticker+news"

i.e. each ticker is scored from its own price history AND from the
news/graph signal attached to it. Sector-level ("categoria") scoring is
deliberately out of scope here.

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
_LPPL_WINDOW = 252


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
    lppl_bubble_prob: float | None,
    n_points: int | None,
    accel_ratio: float | None,
    graph_edges: list | None,
    context: dict | None = None,
) -> dict:
    """Build the three Signals for one ticker and run the composite.

    Pure: every input is already-fetched data. Returns the
    composite_score dict (composite, aggregate_confidence, coverage,
    flagged, components, ...) plus the ticker and optional display
    context.
    """
    signals = [
        momentum_signal(lppl_bubble_prob, n_points),
        temporal_signal(accel_ratio),
        graph_fragility_signal(graph_edges),
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
    accel = _accel_by_category()
    graph = _load_approved_graph()

    rows: list[dict] = []
    for w in watchlist:
        t = w["ticker"]
        rows.append(score_ticker(
            t,
            lppl_bubble_prob=w.get("lppl_bubble_prob"),
            n_points=min(bar_counts.get(t, 0), _LPPL_WINDOW),
            accel_ratio=temporal_ratio_for_ticker(t, accel),
            graph_edges=_graph_edges(t, graph),
            context={
                "close": w.get("close"),
                "change_pct_30d": w.get("change_pct_30d"),
                "gsadf_explosive": w.get("gsadf_explosive", False),
            },
        ))

    # Strongest (composite, then evidence) first.
    rows.sort(
        key=lambda r: (r["composite"], r["aggregate_confidence"]),
        reverse=True,
    )

    return {
        "engine": "bubble_orchestrator",
        "step": "Onda 13 / Step 2",
        "scope": "per-ticker · momentum=preço · temporal+graph_fragility=notícias",
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
        "n_tickers": len(rows),
        "n_flagged": sum(1 for r in rows if r["flagged"]),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tickers": rows,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(gather_and_score(), indent=2, ensure_ascii=False))
