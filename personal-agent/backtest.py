"""Backtesting & snapshot infra (Onda 11).

Two distinct capabilities:

1. **System snapshots** — periodic capture of trend scores, supply chain
   analysis and active cross-pillar chains so we can replay the dashboard
   state at any historical point. Captured by cron via `capture_snapshots()`.

2. **Backtest replay** — given a [start, end] window, simulates what the
   pattern detector / cross-pillar engine would have seen using only data
   available AT each evaluation point, then compares against what actually
   occurred next.

Both feed the quality metrics so the user can answer "is the system
generating useful signals or just noise?".
"""

import logging
from datetime import datetime, timedelta, timezone

from database import (
    insert_snapshot,
    get_articles_in_window,
    get_patterns_in_window,
    get_chains_in_window,
    get_outcomes,
    insert_backtest_run,
    get_quality_metrics,
)

logger = logging.getLogger(__name__)

SNAPSHOT_TYPES = ("trends", "cross_pillar", "supply_chain", "graph")


# ---------------------------------------------------------------------------
# Snapshots — capture system state at intervals
# ---------------------------------------------------------------------------

def capture_snapshots() -> dict:
    """Capture all snapshot types. Idempotent — call from cron every 6h."""
    captured = {}

    try:
        from database import get_trend_scores_data
        scores = get_trend_scores_data() or {}
        if scores:
            sid = insert_snapshot("trends", scores)
            captured["trends"] = sid
    except Exception as e:
        logger.warning("trends snapshot failed: %s", e)

    try:
        from cross_pillar import detect_chains
        chains = detect_chains(window_hours=168)
        sid = insert_snapshot("cross_pillar", {"chains": chains})
        captured["cross_pillar"] = sid
    except Exception as e:
        logger.warning("cross_pillar snapshot failed: %s", e)

    try:
        from supply_chain_analyzer import analyze
        analysis = analyze()
        sid = insert_snapshot("supply_chain", analysis)
        captured["supply_chain"] = sid
    except Exception as e:
        logger.warning("supply_chain snapshot failed: %s", e)

    try:
        from database import get_graph_for_display
        graph = get_graph_for_display(status="approved")
        graph_summary = {
            "entity_count": len(graph["entities"]),
            "relationship_count": len(graph["relationships"]),
            "by_type": _count_by(graph["entities"], "entity_type"),
        }
        sid = insert_snapshot("graph", graph_summary)
        captured["graph"] = sid
    except Exception as e:
        logger.warning("graph snapshot failed: %s", e)

    logger.info("Snapshots captured: %s", captured)
    return captured


def _count_by(items: list[dict], key: str) -> dict:
    counts: dict = {}
    for item in items:
        v = item.get(key, "?")
        counts[v] = counts.get(v, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Replay — what would the system have seen at point T?
# ---------------------------------------------------------------------------

def replay_window(
    start_iso: str,
    end_iso: str,
    *,
    eval_step_hours: int = 24,
    pattern_lookback_hours: int = 48,
) -> dict:
    """Walk through the window in eval_step_hours increments.

    At each tick, count how many articles, patterns and chains were
    visible at that moment using historical data (no future leakage).
    Returns a per-tick summary suitable for a chart.
    """
    start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=timezone.utc)

    if end_dt <= start_dt:
        return {"ticks": [], "summary": {"error": "end must be after start"}}

    ticks = []
    cursor = start_dt
    total_articles = 0
    total_patterns = 0
    total_chains = 0

    while cursor < end_dt:
        next_cursor = min(cursor + timedelta(hours=eval_step_hours), end_dt)
        window_start_iso = (cursor - timedelta(hours=pattern_lookback_hours)).isoformat()
        cursor_iso = cursor.isoformat()

        articles = get_articles_in_window(
            start_iso=window_start_iso, end_iso=cursor_iso, limit=2000,
        )
        patterns = get_patterns_in_window(
            start_iso=window_start_iso, end_iso=cursor_iso,
        )
        chains = get_chains_in_window(
            start_iso=window_start_iso, end_iso=cursor_iso,
        )

        article_categories = _count_by(articles, "category")
        pattern_confidence = _count_by(patterns, "confidence")

        tick = {
            "at": cursor_iso,
            "articles_visible": len(articles),
            "articles_by_category": article_categories,
            "patterns_visible": len(patterns),
            "patterns_by_confidence": pattern_confidence,
            "chains_visible": len(chains),
            "chain_pillars": [c["pillars"] for c in chains],
        }
        ticks.append(tick)

        total_articles += len(articles)
        total_patterns += len(patterns)
        total_chains += len(chains)

        cursor = next_cursor

    summary = {
        "tick_count": len(ticks),
        "eval_step_hours": eval_step_hours,
        "pattern_lookback_hours": pattern_lookback_hours,
        "total_articles_observed": total_articles,
        "total_patterns_observed": total_patterns,
        "total_chains_observed": total_chains,
    }

    return {"window_start": start_iso, "window_end": end_iso,
            "ticks": ticks, "summary": summary}


def run_backtest(
    *,
    days_back: int = 30,
    eval_step_hours: int = 24,
    pattern_lookback_hours: int = 48,
) -> dict:
    """Convenience wrapper: replay last N days and persist the result."""
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=days_back)

    config = {
        "days_back": days_back,
        "eval_step_hours": eval_step_hours,
        "pattern_lookback_hours": pattern_lookback_hours,
    }
    result = replay_window(
        start_dt.isoformat(),
        end_dt.isoformat(),
        eval_step_hours=eval_step_hours,
        pattern_lookback_hours=pattern_lookback_hours,
    )
    result["quality"] = get_quality_metrics(days=max(days_back, 30))
    result["outcomes_in_window"] = _outcomes_in_window(
        start_dt.isoformat(), end_dt.isoformat(),
    )

    run_id = insert_backtest_run(
        window_start=start_dt.isoformat(),
        window_end=end_dt.isoformat(),
        config=config,
        result=result,
    )
    result["run_id"] = run_id
    return result


def _outcomes_in_window(start_iso: str, end_iso: str) -> dict:
    """Count outcomes whose event_timestamp falls inside the window."""
    outcomes = get_outcomes(limit=1000)
    counts = {"true_positive": 0, "false_positive": 0, "unclear": 0}
    for o in outcomes:
        ts = o.get("event_timestamp", "")
        if ts and start_iso <= ts < end_iso:
            counts[o.get("outcome", "unclear")] = counts.get(o.get("outcome", "unclear"), 0) + 1
    return counts
