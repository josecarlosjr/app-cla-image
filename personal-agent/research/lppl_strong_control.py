"""Controlo positivo REALISTA — correcção de método (Onda 13 Sprint B).

DESCOBERTA: o ``lppl_bubble`` de lppl_characterization.py sobe só ~7% na
janela (B=-0.02), com ruído cumulativo (~0.13 log) MAIOR que o sinal
(0.066). É um controlo positivo inválido — uma bolha real sobe 50-200%.
Isso confunde o v2 (oscilação afogada em ruído) e o GSADF (7% não é
explosivo). O v1 não notou porque R² é relativo à variância total.

Esta correcção NÃO é afinação de detector (regra de integridade intacta):
os 3 detectores continuam importados as-is. Só se corrige o ESTÍMULO —
uma bolha com amplitude realista — para os julgar de forma justa.

lppl_bubble_strong: B=-0.18, C=0.036 (|C/B|=0.20, oscilação realista),
mesmo tc/β/ω/φ, mesmo ruído 0.008. Subida ~80% na janela.

Corre os 3 detectores sobre o controlo forte × N seeds. As linhas das
não-bolhas (amplitude-independentes) reutilizam-se da corrida de 60 seeds
do compare_detectors.py.
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

from quant_detectors import gsadf          # noqa: E402
from lppl_v2 import fit_lppl_v2            # noqa: E402

N = 252


def lppl_bubble_strong(seed: int) -> np.ndarray:
    """Bolha LPPL com amplitude realista (~80% de subida)."""
    rng = np.random.default_rng(seed)
    t = np.arange(N, dtype=float)
    tc = N + 10.0
    beta, omega, phi = 0.33, 9.0, 1.0
    A, B, C = 8.0, -0.18, 0.036
    dt = tc - t
    lp = A + B * dt**beta + C * dt**beta * np.cos(omega * np.log(dt) - phi)
    return lp + rng.normal(0.0, 0.008, N)


def run(n_seeds: int) -> None:
    lp0 = lppl_bubble_strong(0)
    rise = lp0[-20:].mean() - lp0[:20].mean()
    print(f"controlo forte: subida ~{(np.exp(rise)-1)*100:.0f}% na janela\n")
    v1, v2, osc, bsadf, expl = [], [], [], [], []
    for s in range(n_seeds):
        lp = lppl_bubble_strong(s)
        r = fit_lppl_v2(lp)
        v1.append(r.get("bubble_prob_v1", 0.0))
        v2.append(r.get("bubble_prob_v2", 0.0))
        osc.append(r.get("osc_indicator", 0.0))
        g = gsadf(lp)
        bsadf.append(g.get("bsadf_latest", 0.0))
        expl.append(1 if g.get("explosive") else 0)
    print(f"LPPL forte ({n_seeds} seeds):")
    print(f"  v1  mean={np.mean(v1):.3f}  %flag(>0.7)={100*np.mean(np.array(v1)>0.7):.0f}%")
    print(f"  v2  mean={np.mean(v2):.3f}  osc_mean={np.mean(osc):.3f}")
    print(f"  GSADF bsadf_mean={np.mean(bsadf):.2f}  %explosive={100*np.mean(expl):.0f}%")


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 60)
