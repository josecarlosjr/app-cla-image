"""Bubble Detection Engine — scoring core (Onda 13, Step 1 + 1.5).

This module is intentionally PURE: data goes in, a Signal goes out, no
DB / network / LLM. That is what makes it testable without a running
cluster — the orchestrator that fetches live data lives elsewhere (a
later step) and is a thin shell over these functions.

The Signal contract:

    Signal(score 0..1, confidence 0..1, detail)

  - score      = bubble intensity for this single dimension, normalised.
  - confidence = data coverage / reliability (0 = no data, 1 = full).

Two distinct numbers come out of the composite, and Step 1.5 exists to
separate them properly because they answer different questions:

  composite             = HOW bubbly, given the evidence we have.
      = sum(w*score*conf) / sum(w*conf)
    A zero-confidence signal drops out (no dilution); one usable signal
    scores on its own merit.

  aggregate_confidence  = HOW MUCH evidence is behind that number.
      = sum(w*conf) / sum(w)            (over all signals present)
    Absent signals keep their weight in the denominator, so thin
    coverage drags this down even when `composite` looks strong.

Why both: confidence-weighting alone solves "missing data must not drag
the score down" but NOT "thin evidence must not look as strong as
corroborated evidence". A lone weak-confidence signal at score 1.0
produces composite=1.0 — only `aggregate_confidence` (and `coverage`)
reveal it's flimsy. The consumption rule `should_flag()` therefore
requires composite AND aggregate_confidence to clear thresholds, so a
single signal can never trigger a bubble call on its own (the
Sornette-style discipline: corroboration required).

Step 1 wired the three dimensions that already existed as data:
  - momentum         (LPPL bubble probability, quant_features)
  - temporal         (acceleration ratio, Onda 5a temporal.py)
  - graph_fragility  (KG dependency-chain size, Onda 10 + Phase C)

Step 2 adds the two backtestable quant dimensions whose data also
already exists:
  - valuation        (CAPE if available, else trailing-P/E proxy)
  - credit           (BIS credit-to-GDP gap)

sentiment / structure come later; their weights are declared (shape
visible) but score nothing until their steps land.

Weights are PLACEHOLDER — no labelled bubble dataset exists to fit them,
so they're hand-set. Treat as a starting point, not a calibrated model;
calibration needs the backtest against historical bubbles.
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


# Valuation. CAPE (Shiller cyclically-adjusted P/E) is the right input —
# a century of earnings-cycle-adjusted history — but it isn't ingested
# yet, so we accept it optionally and fall back to trailing P/E at LOW
# confidence. This is exactly what the confidence machinery is for: a
# crude proxy can nudge the composite but can never flag a bubble on its
# own. Thresholds are placeholder (calibrate via the backtest).
_PE_RICH = 25.0       # below this: no valuation concern
_PE_EXTREME = 45.0    # at/above this: maxed out
_CAPE_RICH = 22.0
_CAPE_EXTREME = 44.0  # ~dotcom peak


def valuation_signal(
    pe: float | None, cape: float | None = None,
) -> Signal:
    """Stretched multiples. CAPE if available (high confidence), else a
    low-confidence trailing-P/E proxy. Non-positive / missing -> abstain
    (bonds, loss-makers and crypto have no meaningful P/E)."""
    if cape is not None and cape > 0:
        score = _clamp01((cape - _CAPE_RICH) / (_CAPE_EXTREME - _CAPE_RICH))
        return Signal("valuation", score, 0.8, f"CAPE {cape:.1f}")
    if pe is not None and pe > 0:
        score = _clamp01((pe - _PE_RICH) / (_PE_EXTREME - _PE_RICH))
        return Signal("valuation", score, 0.3,
                      f"trailing P/E {pe:.1f} (proxy, sem CAPE)")
    return Signal("valuation", 0.0, 0.0, "no valuation data")


# Credit. BIS credit-to-GDP gap (%) — the strongest historical leading
# indicator of credit bubbles (Basel III uses it for the countercyclical
# capital buffer). Same convention quant_alerts already states: >2% =
# buffer trigger, ~10%+ = historical bubble territory. Country-level (a
# macro backdrop), so the orchestrator feeds each ticker its home-market
# gap. A negative gap (deleveraging) scores 0 but keeps confidence — we
# have the data, it just says "no credit froth".
_CREDIT_GAP_TRIGGER = 2.0
_CREDIT_GAP_MAX = 10.0


def credit_signal(credit_gap_pct: float | None) -> Signal:
    if credit_gap_pct is None:
        return Signal("credit", 0.0, 0.0, "no BIS credit-gap data")
    score = _clamp01(
        (credit_gap_pct - _CREDIT_GAP_TRIGGER)
        / (_CREDIT_GAP_MAX - _CREDIT_GAP_TRIGGER)
    )
    return Signal("credit", score, 0.7,
                  f"BIS credit-to-GDP gap {credit_gap_pct:+.1f}%")


# ---------------------------------------------------------------------------
# Composite + flag rule
# ---------------------------------------------------------------------------

# Placeholder weights — NOT calibrated (no labelled bubble dataset; the
# backtest is what calibrates these). momentum/temporal/graph_fragility
# are the price+news signals (Step 1); valuation/credit are the quant
# signals (Step 2). sentiment/structure are still declared-only (score
# nothing until their steps land). Absolute weights need not sum to 1 —
# composite_score normalises — but every declared weight counts in the
# evidence denominator, so a missing signal correctly drags confidence.
DEFAULT_WEIGHTS: dict[str, float] = {
    "momentum": 0.40,
    "temporal": 0.30,
    "graph_fragility": 0.30,
    "valuation": 0.20,
    "credit": 0.20,
    # --- not implemented yet (later steps) ---
    "sentiment": 0.0,
    "structure": 0.0,
}

# Consumption rule defaults. A bubble is only "flagged" when the score
# is strong AND there's enough corroborating evidence behind it.
# min_confidence = 0.50 is deliberately above what any single signal
# can contribute on its own (e.g. momentum alone at full confidence
# only reaches aggregate_confidence ~0.40), so one signal never flags.
FLAG_MIN_COMPOSITE = 0.70
FLAG_MIN_CONFIDENCE = 0.50


def should_flag(
    composite: float,
    aggregate_confidence: float,
    min_composite: float = FLAG_MIN_COMPOSITE,
    min_confidence: float = FLAG_MIN_CONFIDENCE,
) -> bool:
    """Single source of truth for "is this a bubble call?".

    Requires BOTH a strong composite and enough aggregate confidence,
    so a lone weak-confidence signal at score 1.0 (composite 1.0 but
    aggregate_confidence ~0.12) does NOT trigger.
    """
    return composite >= min_composite and aggregate_confidence >= min_confidence


def composite_score(
    signals: list[Signal], weights: dict[str, float] | None = None,
) -> dict:
    """Confidence-weighted blend + an explicit evidence gauge.

      composite             = sum(w*score*conf) / sum(w*conf)
      aggregate_confidence  = sum(w*conf) / sum(w)
      coverage              = fraction of signals with any data

    composite says how bubbly; aggregate_confidence says how much
    evidence is behind it (thin coverage pulls it down even when
    composite looks strong). See module docstring for why both are
    needed.
    """
    weights = weights or DEFAULT_WEIGHTS
    num = 0.0
    den = 0.0           # sum(w*conf)
    weight_present = 0.0  # sum(w) over signals actually passed in
    used = 0
    for s in signals:
        w = weights.get(s.name, 0.0)
        num += w * s.score * s.confidence
        den += w * s.confidence
        weight_present += w
        if s.confidence > 0:
            used += 1
    composite = (num / den) if den > 0 else 0.0
    aggregate_confidence = (den / weight_present) if weight_present > 0 else 0.0
    coverage = (used / len(signals)) if signals else 0.0
    return {
        "composite": round(composite, 4),
        "aggregate_confidence": round(aggregate_confidence, 4),
        "coverage": round(coverage, 4),
        "n_signals_used": used,
        "n_signals_total": len(signals),
        "flagged": should_flag(composite, aggregate_confidence),
        "components": [
            {
                "name": s.name,
                "score": round(s.score, 4),
                "confidence": round(s.confidence, 4),
                "detail": s.detail,
            }
            for s in signals
        ],
    }


# ---------------------------------------------------------------------------
# Self-test — synthetic scenarios, surfaced on the Bubble Engine page
# ---------------------------------------------------------------------------

def run_selftest() -> dict:
    """Run the scoring math against hand-built scenarios.

    Pure and deterministic. Exercises the behaviours that matter:
    a clear bubble flags; a calm market doesn't; fully-missing data
    abstains (composite 0, no crash); partial data isn't diluted but
    also does NOT flag on a single signal; conflicting signals dampen;
    and a lone weak-confidence signal at max score is caught by the
    flag rule despite composite 1.0.
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
        "composite alto (>0.6), cobertura 3/3, DISPARA",
        [
            momentum_signal(0.91, 252),
            temporal_signal(3.2),
            graph_fragility_signal(["a->b", "b->c", "c->d",
                                    "d->e", "e->f", "f->g"]),
        ],
        lambda c: c["composite"] > 0.6 and c["coverage"] == 1.0
        and c["flagged"] is True,
    )

    # 2. Calm market: low LPPL, no acceleration, no graph chains.
    add(
        "calm_market",
        "composite baixo (<0.25), NAO dispara",
        [
            momentum_signal(0.15, 252),
            temporal_signal(1.0),
            graph_fragility_signal([]),
        ],
        lambda c: c["composite"] < 0.25 and c["flagged"] is False,
    )

    # 3. Sparse data: must abstain (composite 0, coverage 0) and not raise.
    add(
        "sparse_data",
        "cobertura 0/3, composite 0, conf 0, NAO dispara, sem crash",
        [
            momentum_signal(None, 12),
            temporal_signal(None),
            graph_fragility_signal([]),
        ],
        lambda c: c["coverage"] == 0.0 and c["composite"] == 0.0
        and c["aggregate_confidence"] == 0.0 and c["flagged"] is False,
    )

    # 4. Partial: only momentum has data. Composite = momentum score
    #    (not diluted) BUT aggregate_confidence ~0.40 < 0.50, so it must
    #    NOT flag — one signal isn't a bubble call.
    add(
        "partial_momentum_only",
        "composite ~=0.80 (nao diluido) mas conf ~0.40, NAO dispara",
        [
            momentum_signal(0.80, 252),
            temporal_signal(None),
            graph_fragility_signal([]),
        ],
        lambda c: abs(c["composite"] - 0.80) < 0.05
        and c["n_signals_used"] == 1
        and c["aggregate_confidence"] < 0.5
        and c["flagged"] is False,
    )

    # 5. Conflicting: strong LPPL but flat temporal (price fit a
    #    log-periodic shape yet isn't actually accelerating — a
    #    plausible false-LPPL). The flat temporal must dampen the
    #    composite well below the momentum score, and it must not flag.
    add(
        "conflicting_signals",
        "momentum alto + temporal flat -> composite amortecido (0.4-0.75), NAO dispara",
        [
            momentum_signal(0.90, 252),
            temporal_signal(1.0),
            graph_fragility_signal([]),
        ],
        lambda c: 0.4 < c["composite"] < 0.75 and c["flagged"] is False,
    )

    # 6. Lone weak signal at max: only graph_fragility, score 1.0 but
    #    confidence 0.4. composite renormalises to 1.0 — the trap. The
    #    guard: aggregate_confidence ~0.12 keeps `flagged` False.
    add(
        "lone_weak_signal_at_max",
        "composite 1.0 (renormalizado) mas conf ~0.12 -> NAO dispara (a guarda)",
        [
            momentum_signal(None, 0),
            temporal_signal(None),
            graph_fragility_signal(["a->b", "b->c", "c->d",
                                    "d->e", "e->f", "f->g"]),
        ],
        lambda c: c["composite"] > 0.9
        and c["aggregate_confidence"] < 0.2
        and c["flagged"] is False,
    )

    # 7. Full quant bubble: price + news + valuation + credit all hot.
    #    All five signals present -> high composite, full coverage, FIRES.
    add(
        "full_quant_bubble",
        "5/5 sinais quentes -> composite alto, cobertura 5/5, DISPARA",
        [
            momentum_signal(0.90, 252),
            temporal_signal(3.0),
            graph_fragility_signal(["a->b", "b->c", "c->d",
                                    "d->e", "e->f", "f->g"]),
            valuation_signal(None, cape=42.0),
            credit_signal(9.0),
        ],
        lambda c: c["composite"] > 0.7 and c["coverage"] == 1.0
        and c["flagged"] is True,
    )

    # 8. Valuation + credit agree, but no price/news corroboration. The
    #    composite renormalises high, yet only 2/5 of the evidence is in,
    #    so aggregate_confidence stays well under the bar -> does NOT fire.
    #    (Two quant signals alone aren't a bubble call.)
    add(
        "valuation_credit_only",
        "só valuation+credit (2/5) -> composite alto mas conf baixa, NAO dispara",
        [
            momentum_signal(None, 0),
            temporal_signal(None),
            graph_fragility_signal([]),
            valuation_signal(44.0),
            credit_signal(9.0),
        ],
        lambda c: c["composite"] > 0.7
        and c["aggregate_confidence"] < 0.5
        and c["flagged"] is False,
    )

    n_pass = sum(1 for c in cases if c["pass"])
    return {
        "suite": "bubble_scoring_selftest",
        "step": "Onda 13 / Step 1.5",
        "passed": n_pass,
        "total": len(cases),
        "all_pass": n_pass == len(cases),
        "weights": DEFAULT_WEIGHTS,
        "flag_rule": {
            "min_composite": FLAG_MIN_COMPOSITE,
            "min_confidence": FLAG_MIN_CONFIDENCE,
        },
        "cases": cases,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_selftest(), indent=2, ensure_ascii=False))
