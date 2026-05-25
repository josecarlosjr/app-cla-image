"""Tests for the bubble orchestrator's PURE layer (Onda 13, Step 2).

Covers the ticker→news-category mapping and `score_ticker` — the parts
that need no DB / cluster. The live fetch (`gather_and_score`) is the
impure shell and is exercised via the /api/bubble/scores endpoint.

Runnable with pytest, or standalone (`python test_bubble_orchestrator.py`)
since the cluster image doesn't ship pytest.
"""

from bubble_orchestrator import (
    TICKER_NEWS_CATEGORIES,
    temporal_ratio_for_ticker,
    score_ticker,
)


# The watchlist this engine scores (mirrors quant_yfinance.WATCHLIST /
# quant_detectors.WATCHLIST). Hardcoded so the test fails loudly if the
# news map drifts away from the tickers actually ingested.
_WATCHLIST = {
    "SPY", "QQQ", "IWM", "BTC-USD", "ETH-USD",
    "XLK", "XLE", "XLF", "GLD", "TLT", "HYG",
}


# --- ticker → news category map ----------------------------------------

def test_map_covers_exactly_the_watchlist():
    assert set(TICKER_NEWS_CATEGORIES) == _WATCHLIST


def test_map_categories_are_valid_pillars():
    from pillars import CATEGORY_TO_PILLAR
    for ticker, cats in TICKER_NEWS_CATEGORIES.items():
        assert cats, f"{ticker} has no news categories"
        for c in cats:
            assert c in CATEGORY_TO_PILLAR, f"{ticker}: unknown category {c!r}"


# --- temporal_ratio_for_ticker -----------------------------------------

def test_temporal_takes_max_over_mapped_categories():
    # XLK maps to chips_ia, ciberseguranca, ciencia — take the strongest.
    accel = {"chips_ia": 1.4, "ciberseguranca": 3.1, "ciencia": 1.0}
    assert temporal_ratio_for_ticker("XLK", accel) == 3.1


def test_temporal_single_category():
    assert temporal_ratio_for_ticker("XLE", {"energia": 2.2}) == 2.2


def test_temporal_none_when_no_mapped_category_present():
    # SPY maps to financas; data only has energia -> abstain (None).
    assert temporal_ratio_for_ticker("SPY", {"energia": 5.0}) is None


def test_temporal_none_for_unknown_ticker():
    assert temporal_ratio_for_ticker("NVDA", {"chips_ia": 4.0}) is None


def test_temporal_empty_data_is_none():
    assert temporal_ratio_for_ticker("SPY", {}) is None


# --- score_ticker -------------------------------------------------------

def test_score_ticker_clear_bubble_flags():
    r = score_ticker(
        "QQQ",
        lppl_bubble_prob=0.91, n_points=252,
        accel_ratio=3.2,
        graph_edges=["a->b", "b->c", "c->d", "d->e", "e->f", "f->g"],
    )
    assert r["ticker"] == "QQQ"
    assert r["composite"] > 0.70
    assert r["aggregate_confidence"] >= 0.50
    assert r["coverage"] == 1.0
    assert r["flagged"] is True


def test_score_ticker_calm_does_not_flag():
    r = score_ticker(
        "SPY",
        lppl_bubble_prob=0.15, n_points=252,
        accel_ratio=1.0,
        graph_edges=[],
    )
    assert r["composite"] < 0.25
    assert r["flagged"] is False


def test_score_ticker_no_data_abstains_without_crash():
    r = score_ticker(
        "TLT",
        lppl_bubble_prob=None, n_points=0,
        accel_ratio=None,
        graph_edges=None,
    )
    assert r["composite"] == 0.0
    assert r["coverage"] == 0.0
    assert r["aggregate_confidence"] == 0.0
    assert r["flagged"] is False
    # full shape is still present
    assert {"composite", "aggregate_confidence", "coverage",
            "flagged", "components"} <= set(r)


def test_score_ticker_lone_strong_news_signal_does_not_flag():
    # Only graph_fragility, at max score but thin confidence: composite
    # renormalises to 1.0, but the guard (aggregate_confidence) holds —
    # one news signal must not call a bubble. (Sornette discipline,
    # inherited from the scoring core through the orchestrator.)
    r = score_ticker(
        "BTC-USD",
        lppl_bubble_prob=None, n_points=0,
        accel_ratio=None,
        graph_edges=["a->b", "b->c", "c->d", "d->e", "e->f", "f->g"],
    )
    assert r["composite"] > 0.9
    assert r["aggregate_confidence"] < 0.2
    assert r["flagged"] is False


def test_score_ticker_attaches_context():
    r = score_ticker(
        "GLD",
        lppl_bubble_prob=0.2, n_points=252,
        accel_ratio=None, graph_edges=[],
        context={"close": 200.0, "change_pct_30d": 1.2},
    )
    assert r["context"]["close"] == 200.0


# --- standalone runner (no pytest in the cluster image) -----------------

if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed, failed = 0, 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{passed + failed} passed")
    sys.exit(1 if failed else 0)
