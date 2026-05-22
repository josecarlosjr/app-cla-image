"""Tests for the bubble-scoring core (Onda 13, Step 1 + 1.5).

Pure functions, no fixtures, no DB — runnable with `pytest` anywhere.
Mirrors the scenarios in run_selftest() plus targeted edge cases on the
individual scorers, the confidence-weighting invariant, the
aggregate_confidence gauge, and the should_flag consumption rule.
"""

from bubble_scoring import (
    Signal,
    momentum_signal,
    temporal_signal,
    graph_fragility_signal,
    composite_score,
    should_flag,
    run_selftest,
)


# --- the bundled self-test must be fully green --------------------------

def test_selftest_all_pass():
    report = run_selftest()
    assert report["all_pass"], report


def test_selftest_has_six_cases():
    report = run_selftest()
    assert report["total"] == 6


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
    assert comp["aggregate_confidence"] == 0.0
    assert comp["flagged"] is False


def test_composite_partial_not_diluted_but_low_confidence():
    # Only momentum present at score 0.8 -> composite 0.8 (not pulled
    # toward 0) but aggregate_confidence reflects the thin coverage.
    comp = composite_score([
        Signal("momentum", 0.8, 1.0, ""),
        Signal("temporal", 0.0, 0.0, ""),
        Signal("graph_fragility", 0.0, 0.0, ""),
    ])
    assert abs(comp["composite"] - 0.8) < 1e-9
    assert comp["n_signals_used"] == 1
    # aggregate_confidence = (0.4*1.0) / (0.4+0.3+0.3) = 0.40
    assert abs(comp["aggregate_confidence"] - 0.40) < 1e-6
    assert comp["flagged"] is False  # 0.40 < 0.50 -> one signal can't flag


def test_composite_confidence_weighting():
    comp = composite_score(
        [
            Signal("momentum", 1.0, 1.0, ""),
            Signal("temporal", 0.0, 0.5, ""),
        ],
        weights={"momentum": 0.5, "temporal": 0.5},
    )
    # num = .5*1*1 + .5*0*.5 = .5 ; den = .5*1 + .5*.5 = .75 ; = .667
    assert abs(comp["composite"] - (0.5 / 0.75)) < 1e-6


def test_lone_weak_signal_high_composite_but_not_flagged():
    # The trap: a single weak-confidence signal at score 1.0.
    comp = composite_score([
        Signal("momentum", 0.0, 0.0, ""),
        Signal("temporal", 0.0, 0.0, ""),
        Signal("graph_fragility", 1.0, 0.4, ""),
    ])
    assert comp["composite"] == 1.0          # renormalised
    assert comp["aggregate_confidence"] < 0.2  # but evidence is thin
    assert comp["flagged"] is False           # guard holds


# --- should_flag rule ---------------------------------------------------

def test_should_flag_requires_both():
    assert should_flag(0.9, 0.7) is True
    assert should_flag(0.9, 0.3) is False   # strong but thin
    assert should_flag(0.4, 0.9) is False   # well-evidenced but weak
    assert should_flag(0.69, 0.9) is False  # just under composite floor


def test_should_flag_thresholds_tunable():
    assert should_flag(0.5, 0.5, min_composite=0.4, min_confidence=0.4) is True
