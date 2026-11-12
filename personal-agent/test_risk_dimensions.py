"""Tests for the PURE layer of Sprint 4: the BSADF momentum rule, the
four risk dimensions, and the drawdown stress measure.

Everything here is a pure function — no DB, no network. The live
assembly (`_build_risk_dimensions`, `gather_and_score`) is the impure
shell and is exercised through the endpoints.

Runnable with pytest, or standalone (`python test_risk_dimensions.py`)
since the cluster image doesn't ship pytest.
"""

import numpy as np

import risk_dimensions as rd
from bubble_scoring import (
    _GSADF_CRIT95, _GSADF_CRIT99, _GSADF_MIN_CONSECUTIVE, momentum_signal,
)
from quant_detectors import _GSADF_CRIT_95, drawdown_stress

C95, C99 = _GSADF_CRIT95, _GSADF_CRIT99


# --- the critical values must not drift apart --------------------------

def test_detector_and_scoring_share_the_critical_value():
    """quant_detectors.explosive and momentum_signal must agree.

    They are separate constants in separate modules; if one is tuned
    and the other isn't, the dashboard shows `explosive: false` beside
    a red EXPLOSIVO tile for the same ticker.
    """
    assert _GSADF_CRIT_95 == C95


def test_critical_values_are_the_measured_ones():
    # Monte Carlo, 30 000 paths — see research/gsadf_critical_values.py.
    # Guards against a silent revert to the PSY table value (1.49),
    # which sits at the 99.4th percentile of this estimator's null.
    assert C95 == 0.628
    assert C99 == 1.281
    assert C95 < C99


# --- momentum: persistence ---------------------------------------------

def _bsadf_for(score: float) -> float:
    return C95 + score * (C99 - C95)


def test_momentum_abstains_without_data():
    for series, n in ((None, 252), ([], 252), ([1.4, 1.4], None),
                      ([1.4, 1.4], 10)):
        s = momentum_signal(series, n)
        assert s.score == 0.0 and s.confidence == 0.0


def test_momentum_below_threshold_scores_zero_but_keeps_confidence():
    """Measured calm is data, not absence — same rule as credit_signal."""
    s = momentum_signal([-1.0, -0.8], 252)
    assert s.score == 0.0
    assert s.confidence > 0.5


def test_momentum_single_exceedance_does_not_score():
    s = momentum_signal([-0.5, 2.0], 252)
    assert s.score == 0.0
    assert "persistência" in s.detail


def test_momentum_broken_run_does_not_score():
    # Above, dips below, above again: the run restarts at 1.
    s = momentum_signal([2.0, 0.1, 2.0], 252)
    assert s.score == 0.0


def test_momentum_persisted_exceedance_scores():
    s = momentum_signal([2.0, 2.0], 252)
    assert s.score > 0.0
    assert "consecutivas" in s.detail


def test_momentum_requires_exactly_min_consecutive():
    run_of = lambda k: momentum_signal([-1.0] + [2.0] * k, 252).score
    assert run_of(_GSADF_MIN_CONSECUTIVE - 1) == 0.0
    assert run_of(_GSADF_MIN_CONSECUTIVE) > 0.0


def test_momentum_is_anchored_on_the_null_distribution():
    """0 at p95, 1 at p99, linear between — the whole point of the change."""
    assert momentum_signal([C95, C95], 252).score == 0.0   # strict >
    assert abs(momentum_signal([_bsadf_for(0.5)] * 2, 252).score - 0.5) < 1e-9
    assert momentum_signal([C99, C99], 252).score == 1.0
    assert momentum_signal([99.0, 99.0], 252).score == 1.0  # clamped


def test_momentum_confidence_ramps_with_points_not_with_score():
    low = momentum_signal([2.0, 2.0], 50)
    high = momentum_signal([2.0, 2.0], 250)
    assert low.score == high.score
    assert low.confidence < high.confidence


# --- worst() ------------------------------------------------------------

def test_worst_picks_the_most_severe():
    assert rd.worst(rd.CALM, rd.DANGER) == rd.DANGER
    assert rd.worst(rd.CALM, rd.WATCH) == rd.WATCH
    assert rd.worst(rd.CALM, rd.CALM) == rd.CALM


def test_worst_ignores_unknown_unless_everything_is():
    assert rd.worst(rd.UNKNOWN, rd.CALM) == rd.CALM
    assert rd.worst(rd.UNKNOWN, rd.UNKNOWN) == rd.UNKNOWN


# --- the four dimensions ------------------------------------------------

def test_explosive_states_follow_the_persistence_rule():
    mk = lambda s: rd.explosive_dimension(s, C95, _GSADF_MIN_CONSECUTIVE)
    assert mk(None)["state"] == rd.UNKNOWN
    assert mk([-1.0])["state"] == rd.CALM
    assert mk([2.0])["state"] == rd.WATCH            # one crossing only
    assert mk([2.0, 2.0])["state"] == rd.DANGER
    assert mk([2.0, 0.1])["state"] == rd.CALM        # fell back below


def test_valuation_states():
    assert rd.valuation_dimension(None)["state"] == rd.UNKNOWN
    assert rd.valuation_dimension(18.0)["state"] == rd.CALM
    assert rd.valuation_dimension(25.0)["state"] == rd.WATCH
    assert rd.valuation_dimension(39.8)["state"] == rd.DANGER


def test_credit_states():
    assert rd.credit_dimension(None)["state"] == rd.UNKNOWN
    assert rd.credit_dimension(-11.3)["state"] == rd.CALM
    assert rd.credit_dimension(1.0)["state"] == rd.WATCH
    assert rd.credit_dimension(3.0)["state"] == rd.DANGER


def test_stress_takes_the_worse_of_drawdown_and_vix():
    # Calm drawdown, panicking VIX -> danger.
    d = rd.stress_dimension(10.0, -1.0, 45.0, "panic")
    assert d["state"] == rd.DANGER
    # Deep drawdown, calm VIX -> danger.
    d = rd.stress_dimension(99.0, -40.0, 12.0, "calm")
    assert d["state"] == rd.DANGER
    # Both calm -> calm.
    d = rd.stress_dimension(10.0, -1.0, 12.0, "calm")
    assert d["state"] == rd.CALM


def test_stress_survives_a_missing_input():
    assert rd.stress_dimension(None, None, 12.0, "calm")["state"] == rd.CALM
    assert rd.stress_dimension(10.0, -1.0, None, None)["state"] == rd.CALM
    assert rd.stress_dimension(None, None, None, None)["state"] == rd.UNKNOWN


def test_every_dimension_declares_its_anchor():
    """The honesty contract: no tile without a stated anchor."""
    dims = [
        rd.explosive_dimension([0.1], C95, 2),
        rd.valuation_dimension(39.8),
        rd.credit_dimension(-11.3),
        rd.stress_dimension(50.0, -5.0, 20.0, "nervous"),
    ]
    for d in dims:
        assert d["anchor"], f"{d['key']} has no anchor"
        assert d["anchor_kind"] in ("external", "design")
        assert d["measures"], f"{d['key']} does not say what it measures"
        assert d["applied"], f"{d['key']} does not say which threshold applied"
        assert d["state"] in (rd.CALM, rd.WATCH, rd.DANGER, rd.UNKNOWN)


def test_design_choice_bands_admit_it():
    """Amber bands are our invention; the tooltip has to say so."""
    for d in (rd.valuation_dimension(25.0),
              rd.stress_dimension(85.0, -9.0, 20.0, "nervous")):
        assert "escolha de desenho" in d["caveat"]


def test_legend_covers_every_dimension():
    keys = {d["key"] for d in rd.LEGEND}
    assert keys == {"explosive", "valuation", "credit", "stress"}


# --- the watchlist contract --------------------------------------------
#
# These exist because of a real bug: `drawdown_pct_rank` was computed by
# the detector, stored in quant_features and returned by
# get_latest_features_by_target — and then dropped by get_watchlist's
# enrichment, which carried a hand-written list of keys. Nothing threw.
# STRESS simply rendered from the VIX alone and reported the drawdown
# half as `unknown`, which is indistinguishable from a genuine outage.

def _row(ticker, **features):
    """A watchlist row built the way get_watchlist() builds one.

    Crucially the detector values go in as the FEATURES dict and reach
    the row only through `apply_feature_contract` — the same seam the
    real enrichment uses. Setting them directly on the row would
    bypass the very step that dropped them, which is how the first
    version of these tests passed against the bug.
    """
    return rd.apply_feature_contract(
        {"ticker": ticker, "close": 100.0}, features,
    )


def test_market_panel_uses_the_drawdown_when_the_row_carries_it():
    """The regression. Fails against the shipped bug."""
    panel = rd.market_panel(
        [_row("XLK", gsadf_bsadf=0.27, drawdown_pct_rank=92.89,
              drawdown_pct=-15.4)],
        cape=39.8, credit_gap_pct=-11.3, vix=19.9, vix_status="nervous",
        crit95=C95, min_consec=_GSADF_MIN_CONSECUTIVE,
    )
    stress = next(d for d in panel["dimensions"] if d["key"] == "stress")
    assert stress["drawdown_state"] != rd.UNKNOWN, \
        "o STRESS ignorou o drawdown que a linha trazia"
    assert stress["value"] == 92.89
    assert stress["display"] == "p93"
    assert "XLK" in stress["applied"]
    assert stress["state"] == rd.WATCH     # p93 amber beats VIX 19.9 nervous


def test_market_panel_reports_unknown_only_when_truly_absent():
    panel = rd.market_panel(
        [_row("XLK", gsadf_bsadf=0.27)],     # drawdown keys at default None
        cape=39.8, credit_gap_pct=-11.3, vix=19.9, vix_status="nervous",
        crit95=C95, min_consec=_GSADF_MIN_CONSECUTIVE,
    )
    stress = next(d for d in panel["dimensions"] if d["key"] == "stress")
    assert stress["drawdown_state"] == rd.UNKNOWN
    assert stress["state"] == rd.WATCH      # falls back to the VIX band


def test_contract_carries_everything_the_detector_produced():
    """The seam itself: what the detector wrote must reach the row.

    `features` is shaped exactly like one entry of
    get_latest_features_by_target. If a key the detector produces is
    not in the contract, it never lands on the row — which is the bug,
    and this is the assertion that catches it.
    """
    produced = {
        "lppl_bubble_prob": 0.86,
        "gsadf_bsadf": 0.27,
        "gsadf_explosive": False,
        "drawdown_pct": -15.4,
        "drawdown_pct_rank": 92.89,
    }
    row = rd.apply_feature_contract({"ticker": "XLK"}, produced)
    for key, value in produced.items():
        assert key in row, (
            f"{key} foi calculado e lido da BD mas não chega à linha — "
            "falta em WATCHLIST_FEATURE_DEFAULTS"
        )
        assert row[key] == value


def test_contract_covers_every_key_the_panel_reads():
    """A key the panel reads but the contract doesn't carry shows up
    here as a dimension stuck on `unknown` despite full detector data.

    The VIX is deliberately absent: with it present, a panicking VIX
    pulls STRESS to `danger` even when the drawdown half is missing,
    which is precisely how the shipped bug looked healthy from the
    outside. Combined states hide missing inputs, so the sub-states
    are asserted too.
    """
    panel = rd.market_panel(
        [_row("XLK", gsadf_bsadf=2.0, drawdown_pct_rank=99.0,
              drawdown_pct=-30.0)],
        cape=39.8, credit_gap_pct=3.0, vix=None, vix_status=None,
        crit95=C95, min_consec=_GSADF_MIN_CONSECUTIVE,
    )
    for d in panel["dimensions"]:
        assert d["state"] != rd.UNKNOWN, (
            f"{d['key']} ficou unknown com dados completos do detetor — "
            "lê uma chave que o contrato não transporta"
        )
    stress = next(d for d in panel["dimensions"] if d["key"] == "stress")
    assert stress["drawdown_state"] != rd.UNKNOWN
    assert stress["drawdown_pct"] == -30.0


def test_contract_declares_both_halves_of_stress():
    # The percentile drives the state; the raw % is what the tooltip
    # shows. Losing either one degrades the tile.
    assert "drawdown_pct_rank" in rd.WATCHLIST_FEATURE_DEFAULTS
    assert "drawdown_pct" in rd.WATCHLIST_FEATURE_DEFAULTS


def test_market_panel_picks_the_worst_ticker_not_the_first():
    rows = [
        _row("SPY", gsadf_bsadf=-0.35, drawdown_pct_rank=68.7, drawdown_pct=-4.0),
        _row("XLK", gsadf_bsadf=0.27, drawdown_pct_rank=92.9, drawdown_pct=-15.4),
        _row("TLT", gsadf_bsadf=-0.95, drawdown_pct_rank=38.8, drawdown_pct=-2.0),
    ]
    panel = rd.market_panel(
        rows, cape=39.8, credit_gap_pct=-11.3, vix=19.9, vix_status="nervous",
        crit95=C95, min_consec=_GSADF_MIN_CONSECUTIVE,
    )
    by = {d["key"]: d for d in panel["dimensions"]}
    assert by["stress"]["ticker"] == "XLK"
    assert by["explosive"]["ticker"] == "XLK"


def test_market_panel_survives_an_empty_watchlist():
    panel = rd.market_panel(
        [], cape=None, credit_gap_pct=None, vix=None, vix_status=None,
        crit95=C95, min_consec=_GSADF_MIN_CONSECUTIVE,
    )
    assert len(panel["dimensions"]) == 4
    assert all(d["state"] == rd.UNKNOWN for d in panel["dimensions"])


# --- drawdown stress ----------------------------------------------------

def test_drawdown_needs_enough_history():
    assert drawdown_stress(np.linspace(100, 120, 50)) is None


def test_drawdown_at_an_all_time_high_is_the_calmest():
    closes = np.linspace(100.0, 300.0, 400)      # monotone rise
    r = drawdown_stress(closes)
    assert r is not None
    assert abs(r["drawdown_pct"]) < 1e-6
    # Never been in a drawdown -> tied with every other observation.
    assert r["pct_rank"] == 100.0


def test_drawdown_deepest_ever_ranks_at_the_top():
    rng = np.random.default_rng(7)
    closes = 100 + np.cumsum(rng.standard_normal(600)) * 0.5
    closes = np.append(closes, closes[-1] * 0.5)   # a crash at the end
    r = drawdown_stress(closes)
    assert r["drawdown_pct"] < -20
    assert r["pct_rank"] > 99


def test_drawdown_is_self_calibrating():
    """The same -10% is routine for a volatile series and extreme for a
    placid one. That is the point of ranking against own history."""
    rng = np.random.default_rng(11)
    base = np.linspace(100, 140, 600)
    placid = base + rng.standard_normal(600) * 0.3
    volatile = base + rng.standard_normal(600) * 12.0
    for series in (placid, volatile):
        s = np.append(series, series[-1] * 0.90)   # same -10% shock
        assert drawdown_stress(s) is not None
    r_placid = drawdown_stress(np.append(placid, placid[-1] * 0.90))
    r_vol = drawdown_stress(np.append(volatile, volatile[-1] * 0.90))
    assert r_placid["pct_rank"] > r_vol["pct_rank"]


def test_drawdown_reports_its_sample_size():
    closes = np.linspace(100.0, 200.0, 500)
    r = drawdown_stress(closes)
    assert r["n_obs"] > 300 and r["window"] == 90


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
