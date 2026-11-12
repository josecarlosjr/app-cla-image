"""Monte Carlo critical values for the BSADF statistic as implemented here.

Run this to re-derive the constants in ``quant_detectors._GSADF_CRIT_95``
and ``bubble_scoring._GSADF_CRIT95`` / ``_GSADF_CRIT99``. It exists
because those numbers must not be quoted from a paper: the estimator in
``quant_detectors._adf_stat`` has a constant and NO lag augmentation, so
the published PSY (2015) tables describe a different null distribution.

What it showed when the constants were set (2026-11):

    BSADF at the latest point, n=250, r0=30, 30 000 paths
    (6 independent batches of 5 000, seeds 1000..1005)

        p95 = 0.6283   batch spread 0.596-0.674, sd 0.024
        p99 = 1.2806   batch spread 1.219-1.343, sd 0.046

    Where the previously-used constants land in that null:

        1.49  (PSY Table 1, was _GSADF_CRIT_95) -> percentile 99.4
        0.526 (first proposal for CRIT95)       -> percentile 93.7
        1.211 (first proposal for CRIT99)       -> percentile 98.8

    The double-sup GSADF is a different, much larger statistic: its
    simulated p95 is ~2.15, which puts 1.49 at its 77th percentile. So
    1.49 was wrong for both readings, not merely mismatched.

Reporting batches rather than one pooled number is deliberate — the
spread is the honest error bar on the constant, and it is what shows
whether a disagreement with another run is sampling noise or a real
difference in setup.

Usage::

    python research/gsadf_critical_values.py [N_PER_BATCH] [N_BATCHES]

Takes ~3 minutes for the default 30 000 paths. Pure Monte Carlo: no DB,
no network, deterministic given the seeds.
"""

import sys
import time

import numpy as np

# Import the production ADF estimator without dragging in pg_database.
_SRC = __file__.rsplit("/", 2)[0] + "/quant_detectors.py"
_text = open(_SRC).read()
_ns: dict = {"np": np}
exec(compile(_text[_text.index("def _adf_stat"):_text.index("def gsadf")],
             "quant_detectors.py", "exec"), _ns)
_adf_stat = _ns["_adf_stat"]

N = 250        # sample size the detector runs on (WINDOW_DAYS)
R0 = 30        # minimum inner window (_R0)


def bsadf_latest(y: np.ndarray, r0: int = R0) -> float:
    """sup over start points of ADF(y[r1:n]) — what the detector stores."""
    n = len(y)
    best = -np.inf
    for r1 in range(0, n - r0 + 1):
        s = _adf_stat(y[r1:n])
        if s > best:
            best = s
    return float(best)


def main(per_batch: int = 5000, n_batches: int = 6) -> None:
    print(f"H0: random walk sem deriva, n={N}, r0={R0}, "
          f"{n_batches} lotes de {per_batch}")
    t0 = time.perf_counter()
    batches, p95s, p99s = [], [], []
    for b in range(n_batches):
        rng = np.random.default_rng(1000 + b)
        v = np.array([
            bsadf_latest(np.cumsum(rng.standard_normal(N)))
            for _ in range(per_batch)
        ])
        batches.append(v)
        p95s.append(float(np.quantile(v, 0.95)))
        p99s.append(float(np.quantile(v, 0.99)))
        print(f"  lote {b + 1}/{n_batches}  p95={p95s[-1]:+.3f}  "
              f"p99={p99s[-1]:+.3f}")

    pool = np.concatenate(batches)
    print(f"\n({time.perf_counter() - t0:.0f}s) {len(pool)} simulacoes")
    print(f"  p95 {np.quantile(pool, 0.95):+.4f}  "
          f"(lotes {min(p95s):+.3f}..{max(p95s):+.3f}, sd {np.std(p95s):.4f})")
    print(f"  p99 {np.quantile(pool, 0.99):+.4f}  "
          f"(lotes {min(p99s):+.3f}..{max(p99s):+.3f}, sd {np.std(p99s):.4f})")
    print("\n  percentil de cada constante nesta distribuicao nula:")
    for name, c in (("1.49  (PSY Table 1)", 1.49),
                    ("0.526 (proposta inicial)", 0.526),
                    ("1.211 (proposta inicial)", 1.211),
                    ("0.628 (CRIT95 em uso)", 0.628),
                    ("1.281 (CRIT99 em uso)", 1.281)):
        print(f"    {name:26s} -> {float((pool < c).mean()) * 100:5.2f}")


if __name__ == "__main__":
    main(
        int(sys.argv[1]) if len(sys.argv) > 1 else 5000,
        int(sys.argv[2]) if len(sys.argv) > 2 else 6,
    )
