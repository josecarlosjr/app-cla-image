"""Bubble + crisis detectors — LPPL fit + GSADF test.

Two complementary detectors operating on daily close prices in
`quant_bars`. Output goes to `quant_features`:

  feature_id          target      value                       meta
  lppl_bubble_prob    SPY         [0, 1] bubble probability   fit params + R^2
  gsadf_stat          SPY         BSADF statistic at t=now    {gsadf, critical_95, explosive}
  ...

References:
  - LPPL: Sornette (2003), "Why Stock Markets Crash"
  - GSADF: Phillips, Shi, Yu (2015), "Testing for Multiple Bubbles"

Both are pure-numpy implementations — no scipy/statsmodels dep.
~70s total runtime for the 11-ticker watchlist.

Run as a CronJob at 23:00 UTC, after the 22:00 yfinance ingestion.
"""

import logging
from datetime import datetime, timezone

import numpy as np

from pg_database import connect, upsert_feature
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


WATCHLIST = [
    "SPY", "QQQ", "IWM",
    "BTC-USD", "ETH-USD",
    "XLK", "XLE", "XLF",
    "GLD", "TLT", "HYG",
]

# ~1 trading year of history. Long enough for both detectors; short
# enough that "current bubble" doesn't get diluted by ancient data.
WINDOW_DAYS = 252


def get_close_prices(ticker: str, days: int) -> np.ndarray:
    """Return the most-recent N closes for a ticker, chronologically ordered."""
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT close FROM quant_bars
               WHERE ticker = %s
               ORDER BY ts DESC LIMIT %s""",
            (ticker, days),
        )
        rows = cur.fetchall()
    if not rows:
        return np.array([])
    rows.reverse()
    return np.array([float(r["close"]) for r in rows], dtype=float)


# ===========================================================================
# LPPL — log-periodic power law (Sornette 2003)
# ===========================================================================
#
# Model:  log(P(t)) = A + B*(tc - t)^β + C*(tc - t)^β * cos(ω*log(tc - t) - φ)
#
# 7 parameters, highly nonlinear, dozens of local minima — direct
# nonlinear fitting is unreliable. We separate the linear params
# (A, B, C) from the nonlinear ones (tc, β, ω, φ): coarse-grid search
# the four nonlinear params, then closed-form lstsq for the three
# linear ones at each grid point. Best R² wins.
# ===========================================================================

# Grid sizes chosen so the total ~5k fits per ticker run in a few seconds.
_TC_RANGE = (5, 60, 12)        # crash 5 to 60 days ahead, 12 candidates
_BETA_RANGE = (0.15, 0.5, 8)   # typical bubble exponent
_OMEGA_RANGE = (6.0, 13.0, 8)  # typical log-frequency
_PHI_RANGE = (0.0, 2 * np.pi, 6)


def fit_lppl(log_prices: np.ndarray) -> dict:
    """Fit LPPL via grid + lstsq. Returns parameters, R², bubble_prob.

    bubble_prob is the R² of the best fit, **only** if the fitted
    parameters fall inside the bubble-typical ranges (Sornette's
    rule of thumb): β in [0.15, 0.5], ω in [6, 13], B < 0 (super-
    exponential growth in the trend term). Otherwise we discount
    the score by 70 %, since fits at the boundary are usually
    artefacts of grid search rather than real bubble signatures.
    """
    n = len(log_prices)
    if n < 50:
        return {"fitted": False, "bubble_prob": 0.0, "r2": 0.0}

    t = np.arange(n, dtype=float)

    tcs = np.linspace(n + _TC_RANGE[0], n + _TC_RANGE[1], _TC_RANGE[2])
    betas = np.linspace(*_BETA_RANGE)
    omegas = np.linspace(*_OMEGA_RANGE)
    phis = np.linspace(*_PHI_RANGE)

    ss_tot = float(np.sum((log_prices - log_prices.mean()) ** 2))
    if ss_tot == 0:
        return {"fitted": False, "bubble_prob": 0.0, "r2": 0.0}

    best_r2 = 0.0
    best: dict | None = None

    for tc in tcs:
        dt = np.maximum(tc - t, 1e-6)
        log_dt = np.log(dt)
        for beta in betas:
            f1 = dt ** beta
            for omega in omegas:
                cos_arg_base = omega * log_dt
                for phi in phis:
                    f2 = f1 * np.cos(cos_arg_base - phi)
                    X = np.column_stack([np.ones(n), f1, f2])
                    try:
                        coefs, *_ = np.linalg.lstsq(X, log_prices, rcond=None)
                    except np.linalg.LinAlgError:
                        continue
                    pred = X @ coefs
                    ss_res = float(np.sum((log_prices - pred) ** 2))
                    r2 = 1.0 - ss_res / ss_tot
                    if r2 > best_r2:
                        best_r2 = r2
                        best = {
                            "tc_offset": float(tc - n),
                            "beta": float(beta),
                            "omega": float(omega),
                            "phi": float(phi),
                            "A": float(coefs[0]),
                            "B": float(coefs[1]),
                            "C": float(coefs[2]),
                            "r2": float(r2),
                        }

    if best is None:
        return {"fitted": False, "bubble_prob": 0.0, "r2": 0.0}

    valid_beta = 0.15 <= best["beta"] <= 0.5
    valid_omega = 6.0 <= best["omega"] <= 13.0
    valid_sign = best["B"] < 0  # accelerating up = B negative
    valid = valid_beta and valid_omega and valid_sign
    bubble_prob = best["r2"] if valid else best["r2"] * 0.3
    best["bubble_prob"] = float(min(1.0, max(0.0, bubble_prob)))
    best["fitted"] = True
    best["params_valid"] = valid
    return best


# ===========================================================================
# GSADF — Generalized Sup ADF (Phillips, Shi, Yu 2015)
# ===========================================================================
#
# For each window endpoint t in [r0, n], scan starting points r1
# in [0, t - r0] and run an ADF test on log_prices[r1:t]. Take the
# supremum t-statistic over r1 → BSADF(t). Take the supremum over
# all t → GSADF.
#
# We use a simple ADF with a constant and no augmentation lags. That's
# both faster (~50µs/test) and adequate for daily close series.
# ===========================================================================

_R0 = 30                # minimum window size for the inner ADF
_GSADF_CRIT_95 = 1.49   # PSY (2015) Table 1, n≈250, no lag → 95% critical


def _adf_stat(y: np.ndarray) -> float:
    """ADF t-statistic for the unit-root coefficient with constant trend.

    Regression: Δy_t = α + ρ·y_{t-1} + ε_t  → t-stat for ρ.
    """
    n = len(y)
    if n < 10:
        return 0.0
    dy = y[1:] - y[:-1]
    X = np.column_stack([np.ones(n - 1), y[:-1]])
    try:
        coefs, *_ = np.linalg.lstsq(X, dy, rcond=None)
        residuals = dy - X @ coefs
        df_resid = max(1, n - 1 - X.shape[1])
        sigma2 = float(np.sum(residuals ** 2) / df_resid)
        cov = sigma2 * np.linalg.inv(X.T @ X)
        se = float(np.sqrt(cov[1, 1]))
        return float(coefs[1] / se) if se > 0 else 0.0
    except (np.linalg.LinAlgError, ValueError, ZeroDivisionError):
        return 0.0


def gsadf(log_prices: np.ndarray, r0: int = _R0) -> dict:
    """Compute the BSADF time series and return GSADF stats."""
    n = len(log_prices)
    if n < r0 + 30:
        return {"fitted": False, "gsadf": 0.0, "bsadf_latest": 0.0,
                "critical_95": _GSADF_CRIT_95, "explosive": False}

    bsadf_series = []
    for t in range(r0, n + 1):
        max_adf = -np.inf
        for r1 in range(0, t - r0 + 1):
            stat = _adf_stat(log_prices[r1:t])
            if stat > max_adf:
                max_adf = stat
        bsadf_series.append(float(max_adf))

    gsadf_value = float(max(bsadf_series))
    bsadf_latest = float(bsadf_series[-1])

    return {
        "fitted": True,
        "gsadf": gsadf_value,
        "bsadf_latest": bsadf_latest,
        "critical_95": _GSADF_CRIT_95,
        "explosive": bool(bsadf_latest > _GSADF_CRIT_95),
    }


# ===========================================================================
# Per-ticker driver + main entry
# ===========================================================================

def run_for_ticker(ticker: str) -> dict:
    closes = get_close_prices(ticker, WINDOW_DAYS)
    if len(closes) < 50:
        logger.warning("%s: only %d bars available, skipping",
                       ticker, len(closes))
        return {"ticker": ticker, "skipped": True}

    log_prices = np.log(closes)
    ts_now = datetime.now(timezone.utc).isoformat()

    summary: dict = {"ticker": ticker}

    lppl_result = fit_lppl(log_prices)
    if lppl_result.get("fitted"):
        upsert_feature(
            "lppl_bubble_prob", ticker, ts_now,
            lppl_result["bubble_prob"],
            meta={k: v for k, v in lppl_result.items()
                  if k not in ("bubble_prob", "fitted")},
        )
        summary["lppl_bubble_prob"] = lppl_result["bubble_prob"]
    else:
        summary["lppl_bubble_prob"] = None

    gsadf_result = gsadf(log_prices)
    if gsadf_result.get("fitted"):
        upsert_feature(
            "gsadf_stat", ticker, ts_now,
            gsadf_result["bsadf_latest"],
            meta={k: v for k, v in gsadf_result.items() if k != "fitted"},
        )
        summary["gsadf_bsadf"] = gsadf_result["bsadf_latest"]
        summary["gsadf_explosive"] = gsadf_result["explosive"]
    else:
        summary["gsadf_bsadf"] = None
        summary["gsadf_explosive"] = False

    return summary


def main():
    logger.info("Quant detectors starting (%d tickers)", len(WATCHLIST))
    results = []
    for ticker in WATCHLIST:
        try:
            r = run_for_ticker(ticker)
            results.append(r)
            if r.get("skipped"):
                continue
            logger.info(
                "%s: lppl=%.3f gsadf=%.3f explosive=%s",
                r["ticker"],
                r.get("lppl_bubble_prob") or 0.0,
                r.get("gsadf_bsadf") or 0.0,
                r.get("gsadf_explosive"),
            )
        except Exception as e:
            logger.error("%s: detector run failed: %s", ticker, e)

    n_explosive = sum(1 for r in results if r.get("gsadf_explosive"))
    n_bubbly = sum(1 for r in results
                   if (r.get("lppl_bubble_prob") or 0) > 0.7)
    logger.info(
        "Detectors done: %d tickers, %d explosive (GSADF>%s), %d bubbly (LPPL>0.7)",
        len(results), n_explosive, _GSADF_CRIT_95, n_bubbly,
    )


if __name__ == "__main__":
    main()
