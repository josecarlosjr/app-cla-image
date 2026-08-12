"""Peça 3 — detetor de reversão (Onda 13 Fase 2, research).

Deteta a ENTRADA em reversão: drawdown do preço face ao pico móvel de 90
dias cruza um threshold por classe de ativo.

    pico_90d(t)  = max(preço na janela de 90 barras que termina em t)
    drawdown(t)  = (pico_90d(t) - preço(t)) / pico_90d(t)
    in_reversal  = drawdown(t) >= threshold[classe]

Deteta APENAS a entrada (transição False→True), não a saída (isso é a
Peça 2). Puro e sem contexto: dispara sempre que o drawdown cruza o
threshold, independentemente de ter havido bolha antes (o "só conta se
houve bolha" é da Peça 2).

REGRA DE INTEGRIDADE: os thresholds vêm de decisão de mercado do Jose,
NÃO de afinar até as reversões conhecidas dispararem.

Núcleo puro (arrays in → resultado out), testável sem DB.

Nota sobre "90 dias": a janela é de 90 BARRAS. Para BTC (diário, inclui
fins-de-semana) 90 barras = 90 dias de calendário. Para equities 90
barras ≈ 4,3 meses. O pico inclui a barra t (drawdown ≥ 0 sempre; num
máximo novo o drawdown é 0).
"""
from __future__ import annotations

import numpy as np

# Threshold por classe (decisão de mercado do Jose — fixo, não afinado).
CLASS_THRESHOLD = {
    "equity":    0.35,
    "crypto":    0.50,
    "commodity": 0.35,
    "bond":      0.25,
}

# Mapa ticker → classe.
ASSET_CLASS = {
    "^GSPC": "equity", "SPY": "equity", "QQQ": "equity", "IWM": "equity",
    "XLK": "equity", "XLE": "equity", "XLF": "equity",
    "BTC-USD": "crypto", "ETH-USD": "crypto",
    "GLD": "commodity",
    "TLT": "bond", "HYG": "bond",
}

PEAK_WINDOW = 90


def class_for_ticker(ticker: str) -> str:
    if ticker not in ASSET_CLASS:
        raise ValueError(f"ticker sem classe mapeada: {ticker!r}")
    return ASSET_CLASS[ticker]


def compute_reversal(
    dates: list,
    closes: np.ndarray,
    asset_class: str,
    *,
    peak_window: int = PEAK_WINDOW,
) -> list[dict]:
    """Por ponto: {ts, price, peak_90d, drawdown, in_reversal}.

    Puro. ``asset_class`` escolhe o threshold. A janela de pico inclui a
    barra t (as primeiras barras usam a janela parcial disponível)."""
    if asset_class not in CLASS_THRESHOLD:
        raise ValueError(f"classe desconhecida: {asset_class!r}")
    thr = CLASS_THRESHOLD[asset_class]
    n = len(closes)
    if len(dates) != n:
        raise ValueError(f"dates ({len(dates)}) != closes ({n})")
    out: list[dict] = []
    for i in range(n):
        lo = max(0, i - peak_window + 1)   # janela [i-89, i] = 90 barras
        peak = float(np.max(closes[lo:i + 1]))
        price = float(closes[i])
        dd = (peak - price) / peak if peak > 0 else 0.0
        out.append({
            "ts": dates[i].isoformat() if hasattr(dates[i], "isoformat")
            else str(dates[i]),
            "price": round(price, 4),
            "peak_90d": round(peak, 4),
            "drawdown": round(dd, 4),
            "in_reversal": bool(dd >= thr),
        })
    return out


def reversal_entries(rows: list[dict]) -> list[dict]:
    """As ENTRADAS: pontos onde in_reversal vira True depois de False.
    Não marca cada ponto abaixo do threshold — só a transição."""
    entries: list[dict] = []
    prev = False
    for r in rows:
        cur = r["in_reversal"]
        if cur and not prev:
            entries.append({
                "ts": r["ts"],
                "drawdown": r["drawdown"],
                "price": r["price"],
                "peak_90d": r["peak_90d"],
            })
        prev = cur
    return entries
