"""Classificação de regime macro — função pura, sem I/O.

Dado os quatro indicadores canónicos (VIX, HY OAS, CAPE Shiller, 10Y yield)
devolve um `regime snapshot`: dict de schema fixo que mapeia cada uma
das quatro famílias (vix, hy_oas, cape, erp) para um dos rótulos
definidos em REGIME_DEFINITIONS_V1.

Design invariants
-----------------
- Puro. Sem I/O. A única fonte de não-determinismo é `computed_at`
  (timestamp de wall-clock UTC), que é metadata — não afecta a
  classificação. Mesma entrada → mesmos `regimes` e `derived`.
- Tabela de thresholds versionada por `REGIME_DEF_VERSION`. Bump da
  versão sempre que uma fronteira mudar, para que um snapshot antigo
  gravado em DB continue interpretável junto com a definição que o
  produziu.
- Input None é legítimo (indicador em falta ou stale a montante). O
  rótulo respectivo fica None e o snapshot é emitido na mesma —
  regime parcial é melhor do que rebentar no site de gravação.
- ERP é derivado: erp = (100 / CAPE) - ten_year. Se qualquer dos dois
  for None, `derived["erp"]` E `regimes["erp"]` ficam None.

Convenção de fronteiras: intervalos [min, max) — min inclusivo, max
exclusivo. Isto torna o bucketing não-ambíguo quando o valor cai
exactamente sobre uma fronteira (ex.: hy_oas=3.5 vai para "normal",
não "apertado"). As tabelas cobrem (-inf, +inf) sem gaps nem overlap.

Contrato de unidades (LER antes de chamar)
------------------------------------------
- vix: pontos do índice (16.59, não 0.1659)
- hy_oas: pontos percentuais (2.75, não 0.0275)
- cape: rácio Shiller adimensional (41.66)
- ten_year_yield: pontos percentuais anualizados (4.48, não 0.0448)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

REGIME_DEF_VERSION = 1

REGIME_DEFINITIONS_V1 = {
    "vix": {
        "baixo":  {"max": 15},
        "normal": {"min": 15, "max": 25},
        "alto":   {"min": 25},
    },
    "hy_oas": {
        "apertado": {"max": 3.5},
        "normal":   {"min": 3.5, "max": 6.0},
        "stress":   {"min": 6.0},
    },
    "cape_shiller": {
        "barato":  {"max": 20},
        "normal":  {"min": 20, "max": 30},
        "caro":    {"min": 30, "max": 40},
        "extremo": {"min": 40},
    },
    "erp": {
        "comprimido": {"max": 1.0},
        "normal":     {"min": 1.0, "max": 4.0},
        "expandido":  {"min": 4.0},
    },
}


def _classify(value: Optional[float], table: dict) -> Optional[str]:
    if value is None:
        return None
    for label, bounds in table.items():
        lo = bounds.get("min", float("-inf"))
        hi = bounds.get("max", float("inf"))
        if lo <= value < hi:
            return label
    return None


def compute_regime_snapshot(
    vix: Optional[float],
    hy_oas: Optional[float],
    cape: Optional[float],
    ten_year_yield: Optional[float],
) -> dict:
    """Devolve dict de snapshot de regime. Contrato no docstring do módulo."""
    erp: Optional[float] = None
    if cape is not None and ten_year_yield is not None:
        erp = round(100.0 / cape - ten_year_yield, 4)

    regimes = {
        "vix":    _classify(vix,    REGIME_DEFINITIONS_V1["vix"]),
        "hy_oas": _classify(hy_oas, REGIME_DEFINITIONS_V1["hy_oas"]),
        "cape":   _classify(cape,   REGIME_DEFINITIONS_V1["cape_shiller"]),
        "erp":    _classify(erp,    REGIME_DEFINITIONS_V1["erp"]),
    }
    return {
        "def_version": REGIME_DEF_VERSION,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "vix": vix,
            "hy_oas": hy_oas,
            "cape": cape,
            "ten_year": ten_year_yield,
        },
        "regimes": regimes,
        "derived": {"erp": erp},
    }
