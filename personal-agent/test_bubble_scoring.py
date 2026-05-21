"""Tests for the bubble-scoring core (Onda 13, Step 1).

Pure functions, no fixtures, no DB — runnable with `pytest` anywhere.
Mirrors the scenarios in run_selftest() plus a few targeted edge cases
on the individual scorers and the confidence-weighting invariant.
"""

from bubble_scoring import (
    Signal,
    momentum_signal,
    temporal_signal,
    graph_fragility_signal,
    composite_score,
    run_selftest,
)


# --- the bundled self-test must be fully green --------------------------

def test_selftest_all_pass():
    report = run_selftest()
    assert report["all_pass"], report


# --- momentum scorer ----------------------------------------------------

def test_momentum_insufficient_history_abstains():
    s = momentum_signal(0.9, 10)
    assert s.score == 0.0 and s.confidence == 0.0


def test_momentum_none_prob_abstains():
    s = momentum_signal(None, 300)
    assert s.confidence == 0.0


def test_momentum_full_history_high_confidence():
    s = momentum_signal(0.75, 300)
    assert s.score == 0.75
    assert s.confidence == 1.0


def test_momentum_confidence_floor():
    # Just above the minimum point count -> small but non-zero conf.
    s = momentum_signal(0.5, 55)
    assert 0.0 < s.confidence <= 0.5


# --- temporal scorer ----------------------------------------------------

def test_temporal_no_acceleration_is_zero():
    s = temporal_signal(1.0)
    assert s.score == 0.0
    assert s.confidence > 0.0  # we DO have data, it just says "flat"


def test_temporal_strong_acceleration():
    s = temporal_signal(3.5)
    assert s.score == 1.0


def test_temporal_missing_abstains():
    s = temporal_signal(None)
    assert s.confidence == 0.0


# --- graph fragility scorer --------------------------------------------

def test_graph_empty_abstains():
    s = graph_fragility_signal([])
    assert s.score == 0.0 and s.confidence == 0.0


def test_graph_caps_at_one():
    s = graph_fragility_signal(["e"] * 20)
    assert s.score == 1.0


# --- composite invariants ----------------------------------------------

def test_composite_all_missing_is_zero_not_crash():
    comp = composite_score([
        Signal("momentum", 0.0, 0.0, ""),
        Signal("temporal", 0.0, 0.0, ""),
    ])
    assert comp["composite"] == 0.0
    assert comp["coverage"] == 0.0


def test_composite_partial_not_diluted():
    # Only momentum present at score 0.8 -> composite must be 0.8,
    # not pulled toward 0 by the absent signals.
    comp = composite_score([
        Signal("momentum", 0.8, 1.0, ""),
        Signal("temporal", 0.0, 0.0, ""),
        Signal("graph_fragility", 0.0, 0.0, ""),
    ])
    assert abs(comp["composite"] - 0.8) < 1e-9
    assert comp["n_signals_used"] == 1


def test_composite_confidence_weighting():
    # Two signals, equal weight, but one is half-confident. The
    # high-confidence one should dominate.
    comp = composite_score(
        [
            Signal("momentum", 1.0, 1.0, ""),
            Signal("temporal", 0.0, 0.5, ""),
        ],
        weights={"momentum": 0.5, "temporal": 0.5},
    )
    # num = .5*1*1 + .5*0*.5 = .5 ; den = .5*1 + .5*.5 = .75 ; = .667
    assert abs(comp["composite"] - (0.5 / 0.75)) < 1e-6
