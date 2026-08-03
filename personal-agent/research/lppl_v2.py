"""LPPL v2 — composto oscilação-consciente (Onda 13 Sprint B, research).

Testa uma variante de bubble_prob que corrige o modo de falha do v1
(bubble_prob=R², que acende em qualquer tendência suave). NÃO toca
quant_detectors.py: reutiliza fit_lppl as-is e ADICIONA um passo de
decomposição por cima.

=====================================================================
JUSTIFICAÇÃO DOS LIMIARES — escrita ANTES de ver o resultado sintético
(regra de integridade anti-overfitting):
=====================================================================

O v1 falha porque bubble_prob=R² não exige que a OSCILAÇÃO log-periódica
contribua. No modelo
    log P(t) = A + B·(tc-t)^β  +  C·(tc-t)^β·cos(ω·log(tc-t) - φ)
o 1º termo (B) é a tendência super-exponencial; o 2º (C) é a assinatura
log-periódica. Uma exponencial/reta pura é ajustada só pelo termo-B com
R²≈1, e o cosseno contribui ~0 (C≈0) — mas o R² continua alto. A
assinatura de bolha Sornette **É** a oscilação; se ela não explica nada,
não é uma bolha LPPL, por muito alto que o R² esteja.

Indicador escolhido — decomposição de variância, SEM parâmetro livre
(escolhido precisamente para não haver limiar para afinar):

  osc_indicator = (R²_full − R²_trend) / R²_full   ∈ [0, 1]

onde R²_trend é o R² do MESMO fit mas usando só {1, (tc-t)^β} (dropa a
coluna do cosseno), aos MESMOS (tc, β) do melhor fit. Isto é a fracção
da variância explicada que vem da oscilação, não da tendência. Um
exp/linear → osc_indicator ≈ 0; uma bolha log-periódica real → > 0.

  bubble_prob_v2 = R²_full × osc_indicator            (fix c)

Monótono em ambos, zero parâmetros livres, fixado ANTES dos resultados.

|C|/|B| (fix a) é REPORTADO de forma descritiva (distribuição por
família) mas NÃO entra no score — para não introduzir um limiar afinável.
Se um limiar |C|/|B| separar as famílias, vê-se na distribuição.

tc-estável (fix b) só é aplicável no walk-forward (janelas consecutivas);
deixo o hook `tc_stability()` documentado mas NÃO é exercido numa única
janela sintética — isso é a Fase A histórica.
"""
from __future__ import annotations

import os
import sys

import numpy as np

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from quant_detectors import fit_lppl  # noqa: E402  (as-is, não alterado)


def fit_lppl_v2(log_prices: np.ndarray) -> dict:
    """v1 (fit_lppl as-is) + decomposição de oscilação → bubble_prob_v2.

    Devolve o dict do v1 acrescido de: r2_trend, osc_marginal,
    osc_indicator, amp_ratio (|C|/|B|), bubble_prob_v2.
    """
    base = fit_lppl(log_prices)
    out = dict(base)
    out["bubble_prob_v1"] = base.get("bubble_prob", 0.0)
    out["bubble_prob_v2"] = 0.0
    out["osc_indicator"] = 0.0
    out["amp_ratio"] = 0.0
    if not base.get("fitted"):
        return out

    n = len(log_prices)
    t = np.arange(n, dtype=float)
    tc = n + base["tc_offset"]
    beta = base["beta"]
    dt = np.maximum(tc - t, 1e-6)
    f1 = dt ** beta

    ss_tot = float(np.sum((log_prices - log_prices.mean()) ** 2))
    if ss_tot == 0:
        return out

    # R²_trend: só {1, f1} (sem cosseno), aos mesmos (tc, β).
    X_trend = np.column_stack([np.ones(n), f1])
    try:
        coefs, *_ = np.linalg.lstsq(X_trend, log_prices, rcond=None)
    except np.linalg.LinAlgError:
        return out
    pred_trend = X_trend @ coefs
    r2_trend = 1.0 - float(np.sum((log_prices - pred_trend) ** 2)) / ss_tot

    r2_full = base["r2"]
    osc_marginal = max(0.0, r2_full - r2_trend)
    osc_indicator = (osc_marginal / r2_full) if r2_full > 0 else 0.0
    osc_indicator = max(0.0, min(1.0, osc_indicator))

    B = base.get("B", 0.0)
    C = base.get("C", 0.0)
    amp_ratio = abs(C) / abs(B) if B != 0 else 0.0

    out["r2_trend"] = round(r2_trend, 4)
    out["osc_marginal"] = round(osc_marginal, 4)
    out["osc_indicator"] = round(osc_indicator, 4)
    out["amp_ratio"] = round(amp_ratio, 4)
    out["bubble_prob_v2"] = round(r2_full * osc_indicator, 4)
    return out


def tc_stability(tc_offsets: list[float]) -> float:
    """HOOK (fix b) — coef. de variação do tc previsto em janelas
    consecutivas. Uma bolha real prevê um tc consistente; ruído/trend dá
    tc a saltar. NÃO exercido na caracterização de janela única — só no
    walk-forward histórico (Fase A). Documentado, não usado no score aqui.

    Devolve CV = std/|mean| (menor = mais estável). Vazio/insuficiente
    → inf (sem evidência de estabilidade).
    """
    arr = np.array([x for x in tc_offsets if x is not None], dtype=float)
    if len(arr) < 3 or arr.mean() == 0:
        return float("inf")
    return float(arr.std() / abs(arr.mean()))


if __name__ == "__main__":
    # smoke
    rng = np.random.default_rng(0)
    lp = np.cumsum(rng.normal(0, 0.01, 252)) + 7.0
    r = fit_lppl_v2(lp)
    print("smoke:", {k: r[k] for k in
                     ("bubble_prob_v1", "bubble_prob_v2",
                      "osc_indicator", "amp_ratio", "params_valid")})
