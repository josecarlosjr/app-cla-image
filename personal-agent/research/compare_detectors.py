"""Comparação de detectores (Onda 13 Sprint B, Partes 1+3).

Corre LPPL v1 (R²), LPPL v2 (composto oscilação), e GSADF sobre as MESMAS
5 famílias sintéticas × N seeds. Mede discriminação bolha-vs-não-bolha.

Um detector discrimina se pontua ALTO na família LPPL (bolha real) e
BAIXO nas não-bolhas (gbm_flat/gbm_drift/exp_trend/linear). Métrica de
separação por detector = média(bolha) / pior média(não-bolha). >1 = a
bolha destaca-se; <=1 = não discrimina.

Determinístico (seeds fixos). Zero afinação — importa os 3 as-is.
"""
from __future__ import annotations

import os
import sys

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for p in (_PARENT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from quant_detectors import gsadf  # noqa: E402
from lppl_v2 import fit_lppl_v2    # noqa: E402
from lppl_characterization import (  # noqa: E402  (mesmas 5 famílias)
    gbm_flat, gbm_drift, exp_trend, linear_trend, lppl_bubble,
)

FAMILIES = {
    "gbm_flat  (no-bubble)": gbm_flat,
    "gbm_drift (no-bubble)": gbm_drift,
    "exp_trend (no-bubble)": exp_trend,
    "linear    (no-bubble)": linear_trend,
    "LPPL      (POS control)": lppl_bubble,
}
NB_KEYS = [k for k in FAMILIES if "no-bubble" in k]
POS_KEY = "LPPL      (POS control)"
CRIT = 1.49  # GSADF critical_95 (PSY 2015), o mesmo do quant_detectors


def run(n_seeds: int, out_path: str) -> None:
    rows = {}
    for label, gen in FAMILIES.items():
        v1, v2, osc, amp, bsadf, expl = [], [], [], [], [], []
        for s in range(n_seeds):
            lp = gen(s)
            r = fit_lppl_v2(lp)              # inclui v1 (fit_lppl) + v2
            v1.append(r.get("bubble_prob_v1", 0.0))
            v2.append(r.get("bubble_prob_v2", 0.0))
            osc.append(r.get("osc_indicator", 0.0))
            amp.append(r.get("amp_ratio", 0.0))
            g = gsadf(lp)
            bsadf.append(g.get("bsadf_latest", 0.0))
            expl.append(1 if g.get("explosive") else 0)
        rows[label] = {
            "v1_mean": np.mean(v1), "v1_flag": 100 * np.mean(np.array(v1) > 0.7),
            "v2_mean": np.mean(v2), "v2_med": np.median(v2),
            "osc_mean": np.mean(osc), "amp_med": np.median(amp),
            "bsadf_mean": np.mean(bsadf), "gsadf_expl": 100 * np.mean(expl),
        }

    lines = []
    def p(s=""):
        lines.append(s); print(s)

    p(f"Comparação de detectores — {n_seeds} seeds/família, window=252\n")
    p(f"{'família':<24} {'v1 mean':>8} {'v1 %fl':>7} | "
      f"{'v2 mean':>8} {'osc':>6} {'|C/B|med':>8} | {'bsadf':>7} {'%expl':>6}")
    p("-" * 82)
    for label, r in rows.items():
        p(f"{label:<24} {r['v1_mean']:>8.3f} {r['v1_flag']:>6.0f}% | "
          f"{r['v2_mean']:>8.3f} {r['osc_mean']:>6.3f} {r['amp_med']:>8.3f} | "
          f"{r['bsadf_mean']:>7.2f} {r['gsadf_expl']:>5.0f}%")

    # Separação: média(bolha) / pior média(não-bolha). >1 discrimina.
    def sep(key):
        pos = rows[POS_KEY][key]
        worst_nb = max(rows[k][key] for k in NB_KEYS)
        return pos, worst_nb, (pos / worst_nb if worst_nb > 0 else float("inf"))

    p("\nSeparação bolha-vs-pior-não-bolha (>1 = discrimina):")
    for name, key in (("LPPL v1 (R²)", "v1_mean"),
                      ("LPPL v2 (composto)", "v2_mean"),
                      ("GSADF (bsadf)", "bsadf_mean")):
        pos, wnb, ratio = sep(key)
        p(f"  {name:<20} bolha={pos:.3f}  pior_nao_bolha={wnb:.3f}  "
          f"ratio={ratio:.2f}")

    # GSADF explosive rate: quieto nas não-bolhas, aceso na bolha?
    p("\nGSADF %explosive por família (quieto nas não-bolhas = bom):")
    for label in FAMILIES:
        p(f"  {label:<24} {rows[label]['gsadf_expl']:>5.0f}%")

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/compare_out.txt"
    run(n, out)
