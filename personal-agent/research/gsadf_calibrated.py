"""GSADF calibrado — limiar Monte Carlo dependente de n (Peça 1, Task 2).

Troca o limiar fixo 1.49 do gsadf_walkforward pelo valor crítico da
distribuição nula (gsadf_critical_values.json), interpolado para o
tamanho da janela. Reutiliza o walk-forward existente as-is; só
re-thresholda.

REGRA DE INTEGRIDADE: o limiar vem do JSON Monte Carlo, não é escolhido.
Importa gsadf/walk_forward as-is.
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for p in (_PARENT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from quant_detectors import gsadf, WINDOW_DAYS      # noqa: E402
from gsadf_walkforward import walk_forward_gsadf     # noqa: E402

DEFAULT_JSON = os.path.join(_HERE, "gsadf_critical_values.json")


def load_critical_values(path: str = DEFAULT_JSON) -> dict:
    with open(path) as f:
        return json.load(f)


def interp_crit(n: int, table: dict, key: str = "p95") -> float:
    """Valor crítico para janela de tamanho n, interpolação linear sobre
    os tamanhos tabelados. Clampa nos extremos (não extrapola para fora)."""
    cv = table["critical_values"]
    sizes = sorted(int(s) for s in cv)
    vals = [cv[str(s)][key] for s in sizes]
    if n <= sizes[0]:
        return float(vals[0])
    if n >= sizes[-1]:
        return float(vals[-1])
    return float(np.interp(n, sizes, vals))


def calibrated_gsadf(log_prices: np.ndarray, table: dict) -> dict:
    """gsadf() as-is + limiar calibrado ao n desta janela."""
    n = len(log_prices)
    g = gsadf(log_prices)
    bsadf = float(g.get("bsadf_latest", 0.0))
    c95 = interp_crit(n, table, "p95")
    c99 = interp_crit(n, table, "p99")
    return {
        "n": n,
        "bsadf_latest": round(bsadf, 4),
        "gsadf_max": round(float(g.get("gsadf", 0.0)), 4),
        "crit_95": round(c95, 4),
        "crit_99": round(c99, 4),
        "explosive_95": bool(bsadf > c95),
        "explosive_99": bool(bsadf > c99),
    }


def walk_forward_calibrated(
    dates: list,
    closes: np.ndarray,
    table: dict,
    *,
    step: int = 21,
    window: int = WINDOW_DAYS,
) -> list[dict]:
    """Reutiliza o walk-forward existente (bsadf_latest por ponto) e
    aplica o limiar calibrado. Como a janela é fixa, o crit é constante
    (interpolado ao tamanho da janela). Mantém `explosive` fixo (>1.49)
    lado a lado para comparação direta calibrado-vs-fixo."""
    base = walk_forward_gsadf(dates, closes, step=step, window=window)
    c95 = interp_crit(window, table, "p95")
    c99 = interp_crit(window, table, "p99")
    for r in base:
        b = r["bsadf_latest"]
        r["crit_95"] = round(c95, 4)
        r["crit_99"] = round(c99, 4)
        r["explosive_cal95"] = bool(b > c95)
        r["explosive_cal99"] = bool(b > c99)
        # r["explosive"] (>1.49) já vem do harness — fica para comparação.
    return base
