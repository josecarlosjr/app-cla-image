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
