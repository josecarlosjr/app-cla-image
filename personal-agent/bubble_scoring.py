"""Bubble Detection Engine — scoring core (Onda 13, Step 1).

This module is intentionally PURE: data goes in, a Signal goes out, no
DB / network / LLM. That is what makes it testable without a running
cluster — the orchestrator that fetches live data lives elsewhere (a
later step) and is a thin shell over these functions.

The design decision that prevents the worst class of error in a
composite scorer (a confident number built on missing data) is the
Signal contract:

    Signal(score 0..1, confidence 0..1, detail)

  - score      = bubble intensity for this single dimension, normalised.
  - confidence = data coverage / reliability (0 = no data, 1 = full).

The composite is a confidence-weighted average:

    composite = sum(w_i * score_i * conf_i) / sum(w_i * conf_i)

so a signal with conf=0 drops out entirely instead of dragging the
score toward zero, and a sector with only one usable signal scores on
that signal alone (not diluted). `coverage` reports how many of the
signals actually had data, so the consumer never mistakes a
thin-evidence score for a strong one.

Step 1 wires only the three dimensions that already exist as data from
Onda 12 / earlier waves:
  - momentum         (LPPL bubble probability, quant_features)
  - temporal         (acceleration ratio, Onda 5a temporal.py)
  - graph_fragility  (KG dependency-chain size, Onda 10 + Phase C)

valuation / credit / sentiment / structure come in later steps; their
weights are listed but currently unused, and the composite normalises
over whatever is present.

Weights are PLACEHOLDER — there is no labelled bubble dataset to fit
them, so they're hand-set and must be treated as a starting point, not
a calibrated model.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class Signal:
    name: str
    score: float        # 0..1 bubble intensity for this dimension
    confidence: float   # 0..1 data coverage / reliability
    detail: str         # human-readable why


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


# ---------------------------------------------------------------------------
# Individual signal scorers (pure)
# ---------------------------------------------------------------------------

# LPPL needs a meaningful price history. Below this it isn't fit at all.
_LPPL_MIN_POINTS = 50
# Full confidence at roughly one trading year of daily points.
_LPPL_FULL_POINTS = 250


def momentum_signal(
    lppl_bubble_prob: float | None, n_points: int | None,
) -> Signal:
    """Super-exponential price growth via the LPPL bubble probability.

    `lppl_bubble_prob` already comes 0..1 from quant_detectors (R² of
    the best log-periodic fit, discounted when params fall outside
    Sornette ranges), so it maps straight to score. Confidence scales
    with how many price points fed the fit.
    """
    if (lppl_bubble_prob is None or n_points is None
            or n_points < _LPPL_MIN_POINTS):
        return Signal("momentum", 0.0, 0.0,
                      "insufficient price history for LPPL fit")
    conf = _clamp01(
        (n_points - _LPPL_MIN_POINTS)
        / (_LPPL_FULL_POINTS - _LPPL_MIN_POINTS)
    )
    # Any valid fit earns a floor of confidence so it isn't ignored.
    conf = max(0.2, conf)
    return Signal(
        "momentum", _clamp01(lppl_bubble_prob), conf,
        f"LPPL prob {lppl_bubble_prob:.2f} from {n_points} pts",
    )


def temporal_signal(acceleration_ratio: float | None) -> Signal:
    """Acceleration of attention/price change (Onda 5a).

    `acceleration_ratio` = recent rate / baseline rate. 1.0 means no
    acceleration; >1 means speeding up. Mapped with a soft ramp so 2x
    -> 0.4, 3x -> 0.8, capped at 1. Confidence is fixed-moderate: when
    we have a ratio at all the temporal series is usually adequate, but
    it's a coarser signal than a fitted model.
    """
    if acceleration_ratio is None:
        return Signal("temporal", 0.0, 0.0, "no temporal acceleration data")
    excess = max(0.0, acceleration_ratio - 1.0)
    score = _clamp01(excess / 2.5)
    return Signal(
        "temporal", score, 0.7,
        f"acceleration {acceleration_ratio:.2f}x baseline",
    )


# More dependency edges around a sector = more contagion surface. The
# cap mirrors MAX_GRAPH_EDGES_PER_TICKER in quant_alerts so the two
# views of the graph stay consistent.
_GRAPH_EDGE_CAP = 6


def graph_fragility_signal(chain_edges: list | None) -> Signal:
    """Contagion surface from the knowledge graph (Onda 10 + Phase C).

    `chain_edges` is the 1-2 hop dependency neighbourhood around the
    sector (the same walk quant_alerts already does). More edges =
    more ways stress propagates in. Confidence is low on purpose: the
    financial KG ontology is still accumulating and under human review.
    """
    n = len(chain_edges) if chain_edges else 0
    if n == 0:
        return Signal("graph_fragility", 0.0, 0.0,
                      "no dependency chains in graph neighbourhood")
    return Signal(
        "graph_fragility", _clamp01(n / _GRAPH_EDGE_CAP), 0.4,
        f"{n} dependency edge(s) in 1-2 hop neighbourhood",
    )


# ---------------------------------------------------------------------------
# Composite
# ---------------------------------------------------------------------------

# Placeholder weights. The three live signals sum to 1.0; the rest are
# declared (so the shape is visible) but score nothing until their
# steps land. NOT calibrated — no labelled bubble dataset exists.
DEFAULT_WEIGHTS: dict[str, float] = {
    "momentum": 0.40,
    "temporal": 0.30,
    "graph_fragility": 0.30,
    # --- not implemented yet (Step 2+) ---
    "valuation": 0.0,
    "credit": 0.0,
    "sentiment": 0.0,
    "structure": 0.0,
}


def composite_score(
    signals: list[Signal], weights: dict[str, float] | None = None,
) -> dict:
    """Confidence-weighted blend of signals.

    composite = sum(w*score*conf) / sum(w*conf). A zero-confidence
    signal contributes nothing to numerator or denominator, so missing
    data neither inflates nor deflates the score. `coverage` is the
    fraction of signals that had any data.
    """
    weights = weights or DEFAULT_WEIGHTS
    num = 0.0
    den = 0.0
    used = 0
    for s in signals:
        w = weights.get(s.name, 0.0)
        num += w * s.score * s.confidence
        den += w * s.confidence
        if s.confidence > 0:
            used += 1
    composite = (num / den) if den > 0 else 0.0
    coverage = (used / len(signals)) if signals else 0.0
    return {
        "composite": round(composite, 4),
        "coverage": round(coverage, 4),
        "n_signals_used": used,
        "n_signals_total": len(signals),
        "components": [asdict(s) for s in signals],
    }


# ---------------------------------------------------------------------------
# Self-test — synthetic scenarios, surfaced on the Bubble Engine page
# ---------------------------------------------------------------------------

def run_selftest() -> dict:
    """Run the scoring math against hand-built scenarios.

    Pure and deterministic (same output every call) so two runs can be
    diffed. Exercises the behaviours that matter for correctness:
    a clear bubble scores high, a calm market scores low, fully-missing
    data abstains (composite 0, doesn't crash), and partial data scores
    on the present signal alone (not diluted by absent ones).
    """
    cases: list[dict] = []

    def add(name: str, expectation: str, signals: list[Signal],
            check) -> None:
        comp = composite_score(signals)
        cases.append({
            "name": name,
            "expectation": expectation,
            "result": comp,
            "pass": bool(check(comp)),
        })

    # 1. Clear bubble: strong LPPL, strongly accelerating, fragile graph.
    add(
        "clear_bubble",
        "composite alto (>0.6), cobertura 3/3",
        [
            momentum_signal(0.91, 252),
            temporal_signal(3.2),
            graph_fragility_signal(["a->b", "b->c", "c->d",
                                    "d->e", "e->f", "f->g"]),
        ],
        lambda c: c["composite"] > 0.6 and c["coverage"] == 1.0,
    )

    # 2. Calm market: low LPPL, no acceleration, no graph chains.
    add(
        "calm_market",
        "composite baixo (<0.25)",
        [
            momentum_signal(0.15, 252),
            temporal_signal(1.0),
            graph_fragility_signal([]),
        ],
        lambda c: c["composite"] < 0.25,
    )

    # 3. Sparse data: LPPL too few points, no temporal, no graph.
    #    Must abstain (composite 0, coverage 0) and not raise.
    add(
        "sparse_data",
        "cobertura 0/3, composite 0, sem crash",
        [
            momentum_signal(None, 12),
            temporal_signal(None),
            graph_fragility_signal([]),
        ],
        lambda c: c["coverage"] == 0.0 and c["composite"] == 0.0,
    )

    # 4. Partial: only momentum has data. Composite must equal the
    #    momentum score (0.80), NOT be dragged down by the two absent
    #    signals — the core anti-sparsity property.
    add(
        "partial_momentum_only",
        "composite ~= score do momentum (0.80), 1 sinal usado",
        [
            momentum_signal(0.80, 252),
            temporal_signal(None),
            graph_fragility_signal([]),
        ],
        lambda c: abs(c["composite"] - 0.80) < 0.05
        and c["n_signals_used"] == 1,
    )

    n_pass = sum(1 for c in cases if c["pass"])
    return {
        "suite": "bubble_scoring_selftest",
        "step": "Onda 13 / Step 1",
        "passed": n_pass,
        "total": len(cases),
        "all_pass": n_pass == len(cases),
        "weights": DEFAULT_WEIGHTS,
        "cases": cases,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_selftest(), indent=2, ensure_ascii=False))
