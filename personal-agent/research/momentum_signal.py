"""Peça 4 — sinal de ATENÇÃO de momentum (Onda 13, research).

PARALELO à máquina de estados — NÃO entra nela, NÃO afeta o estado. É uma
camada informativa que reporta "quão extremo é o momentum atual face à
história do PRÓPRIO ativo". Sinaliza movimentos grandes que o GSADF não vê
(ex. 2ª perna do BTC 2021, +130% jul-nov, invisível ao GSADF) como AVISO
DE CONTEXTO — não como deteção de bolha.

Um movimento grande que não deu em bolha NÃO é falso positivo: o sinal
reporta um FACTO (subiu muito), não faz uma previsão.

ANTI-OVERFITTING: limiar por PERCENTIL histórico auto-calibrado (expanding,
sem lookahead) — a distribuição do próprio ativo define o extremo. Zero
números escolhidos para apanhar casos conhecidos.

  momentum_90d(t) = (preço(t) - preço(t-W)) / preço(t-W)
  percentil(t)    = fracção da história ATÉ t (só dados <= t) com momentum
                    <= momentum(t)  (expanding empirical CDF, ZERO lookahead)
  nível:  percentil >= 95 -> "ALTO"  (top 5%)
          percentil >= 90 -> "MEDIO" (top 10%)
          senão           -> "-"

Janela W: BARRAS. Para cripto (diário, inclui fins-de-semana) 90 barras =
90 dias de calendário — é o default. Para equities (dias de trading) usar
W=63 para ~90 dias de calendário (passar --window/param).

Núcleo puro (array de preços in → série out), testável sem DB.
"""
from __future__ import annotations

from bisect import bisect_right, insort

import numpy as np

MOM_WINDOW = 90        # barras (= 90 dias p/ cripto diário)
MIN_HISTORY = 252      # amostras de momentum antes de emitir nível (~1 ano)
P_ALTO = 95.0
P_MEDIO = 90.0


def compute_momentum(
    dates: list,
    closes: np.ndarray,
    *,
    window: int = MOM_WINDOW,
    min_history: int = MIN_HISTORY,
) -> list[dict]:
    """Por ponto: {ts, momentum, percentile, level}. Percentil expanding
    (só dados <= t) — zero lookahead. Nível "-" enquanto i < window ou a
    história de momentum < min_history (amostra insuficiente)."""
    n = len(closes)
    if len(dates) != n:
        raise ValueError(f"dates ({len(dates)}) != closes ({n})")
    out: list[dict] = []
    hist: list[float] = []   # momentum acumulado (ordenado, p/ percentil)
    for i in range(n):
        ts = dates[i].isoformat() if hasattr(dates[i], "isoformat") else str(dates[i])
        if i < window or closes[i - window] == 0:
            out.append({"ts": ts, "momentum": None,
                        "percentile": None, "level": "-"})
            continue
        m = float((closes[i] - closes[i - window]) / closes[i - window])
        insort(hist, m)                    # inclui o ponto actual
        k = len(hist)
        if k < min_history:
            out.append({"ts": ts, "momentum": round(m, 4),
                        "percentile": None, "level": "-"})
            continue
        rank = bisect_right(hist, m)       # nº de elementos <= m (incl. m)
        pct = 100.0 * rank / k
        level = ("ALTO" if pct >= P_ALTO
                 else "MEDIO" if pct >= P_MEDIO else "-")
        out.append({"ts": ts, "momentum": round(m, 4),
                    "percentile": round(pct, 1), "level": level})
    return out
