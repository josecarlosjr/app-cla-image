"""LPPL estimator characterization — Onda 13 Sprint 1, evidência sintética.

Objetivo: medir se ``quant_detectors.fit_lppl`` (as-is, PARÂMETROS FIXOS)
discrimina bolhas de não-bolhas, usando séries sintéticas controladas.

Isto NÃO é o gate histórico (esse precisa de ^GSPC real, in-pod). É a
pergunta que dá para responder no sandbox: dado um sinal cuja definição é
``bubble_prob = R² do melhor fit log-periódico`` (penalizado 0.3 se params
fora das ranges Sornette), qual a distribuição de ``bubble_prob`` em séries
que NÃO são bolhas (random walk, tendência exponencial, linear) vs. uma
bolha LPPL sintética (controlo positivo)?

Se as não-bolhas produzirem ``bubble_prob`` alto com frequência comparável
à bolha, o estimador não discrimina — e o R² é o problema, como suspeitado.

REGRA DE INTEGRIDADE: zero afinação. Importa ``fit_lppl`` tal como está.
Só mede. Determinístico (seeds fixos) para ser reproduzível.
"""
from __future__ import annotations

import os
import sys

import numpy as np

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from quant_detectors import fit_lppl, WINDOW_DAYS  # noqa: E402

N = WINDOW_DAYS  # 252 — a mesma janela que o detector de produção usa
FLAG = 0.7       # limiar "bubbly" que quant_detectors.main usa (LPPL>0.7)


# ---------------------------------------------------------------------------
# Geradores de séries — devolvem LOG-preços (é o que fit_lppl espera)
# ---------------------------------------------------------------------------

def gbm_flat(seed: int) -> np.ndarray:
    """Random walk sem drift — puro ruído. NÃO é bolha."""
    rng = np.random.default_rng(seed)
    return np.cumsum(rng.normal(0.0, 0.01, N)) + 7.0


def gbm_drift(seed: int) -> np.ndarray:
    """Random walk + drift positivo — bull market normal. NÃO é bolha."""
    rng = np.random.default_rng(seed)
    return np.cumsum(rng.normal(0.0004, 0.01, N)) + 7.0


def exp_trend(seed: int) -> np.ndarray:
    """Tendência exponencial suave + ruído. Acelera, mas SEM oscilação
    log-periódica. NÃO é bolha (no sentido Sornette)."""
    rng = np.random.default_rng(seed)
    t = np.arange(N)
    return 7.0 + 0.5 * (t / N) + rng.normal(0.0, 0.01, N).cumsum() * 0.3


def linear_trend(seed: int) -> np.ndarray:
    """Tendência linear + ruído. NÃO é bolha."""
    rng = np.random.default_rng(seed)
    t = np.arange(N)
    return 7.0 + 0.4 * (t / N) + rng.normal(0.0, 0.02, N)


def lppl_bubble(seed: int) -> np.ndarray:
    """Bolha LPPL sintética (CONTROLO POSITIVO) — gerada a partir do
    próprio modelo, tc logo a seguir à janela, B<0 (super-exponencial).
    Deve pontuar alto — se nem isto pontua, o estimador está partido."""
    rng = np.random.default_rng(seed)
    t = np.arange(N, dtype=float)
    tc = N + 10.0
    beta, omega, phi = 0.33, 9.0, 1.0
    A, B, C = 8.0, -0.02, 0.004
    dt = tc - t
    lp = A + B * dt**beta + C * dt**beta * np.cos(omega * np.log(dt) - phi)
    return lp + rng.normal(0.0, 0.008, N)


FAMILIES = {
    "gbm_flat  (no-bubble)": gbm_flat,
    "gbm_drift (no-bubble)": gbm_drift,
    "exp_trend (no-bubble)": exp_trend,
    "linear    (no-bubble)": linear_trend,
    "LPPL      (POS control)": lppl_bubble,
}


def characterize(n_seeds: int = 120) -> None:
    print(f"fit_lppl characterization — {n_seeds} seeds/family, "
          f"window={N}, flag threshold={FLAG}\n")
    print(f"{'family':<24} {'mean':>6} {'median':>7} {'p90':>6} "
          f"{'%valid':>7} {'%>0.7':>6}")
    print("-" * 62)
    summary = {}
    for label, gen in FAMILIES.items():
        probs, valids = [], []
        for s in range(n_seeds):
            r = fit_lppl(gen(s))
            probs.append(r.get("bubble_prob", 0.0))
            valids.append(1 if r.get("params_valid") else 0)
        probs = np.array(probs)
        pct_flag = float(np.mean(probs > FLAG)) * 100
        row = {
            "mean": float(probs.mean()),
            "median": float(np.median(probs)),
            "p90": float(np.percentile(probs, 90)),
            "pct_valid": float(np.mean(valids)) * 100,
            "pct_flag": pct_flag,
        }
        summary[label] = row
        print(f"{label:<24} {row['mean']:>6.3f} {row['median']:>7.3f} "
              f"{row['p90']:>6.3f} {row['pct_valid']:>6.1f}% {pct_flag:>5.1f}%")
    print()
    # Veredito simples de discriminação: a fracção de flags das não-bolhas
    # vs. do controlo positivo.
    nb = [v["pct_flag"] for k, v in summary.items() if "no-bubble" in k]
    pos = summary["LPPL      (POS control)"]["pct_flag"]
    worst_nb = max(nb)
    print(f"Controlo positivo (LPPL) dispara {pos:.1f}% das vezes.")
    print(f"Pior não-bolha dispara {worst_nb:.1f}% das vezes.")
    if worst_nb >= pos * 0.5:
        print("VEREDITO: fit_lppl NÃO discrimina — não-bolhas disparam a "
              "taxa comparável ao controlo. R²-como-sinal é o problema.")
    elif worst_nb >= 20:
        print("VEREDITO: discriminação FRACA — taxa de falsos positivos alta "
              "nas não-bolhas.")
    else:
        print("VEREDITO: discriminação razoável no sintético (não prova o "
              "gate histórico).")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    characterize(n)
