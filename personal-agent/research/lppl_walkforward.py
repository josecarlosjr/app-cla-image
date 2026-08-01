"""Walk-forward LPPL harness — Onda 13 Sprint 1 (research, isolado).

Núcleo PURO (``walk_forward``) + shell fino de I/O (``from_quant_bars``,
``to_csv``). O núcleo aceita arrays já carregados, por isso corre local
com dados sintéticos (validação de mecânica) OU in-pod com ^GSPC real.

REGRA DE INTEGRIDADE: reutiliza ``quant_detectors.fit_lppl`` tal como
está — importa, não reescreve, não afina. Zero lookahead por construção
(assert incluído). Não escreve em ``quant_features`` nem toca produção.

Uso in-pod (depois da ingestão de ^GSPC em quant_bars):
    python research/lppl_walkforward.py --ticker '^GSPC' --step 21 \\
        --out /tmp/gspc_wf.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import date

import numpy as np

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from quant_detectors import fit_lppl, WINDOW_DAYS  # noqa: E402


# ---------------------------------------------------------------------------
# Núcleo puro — testável sem DB
# ---------------------------------------------------------------------------

def walk_forward(
    dates: list,
    closes: np.ndarray,
    *,
    step: int = 21,
    window: int = WINDOW_DAYS,
) -> list[dict]:
    """Corre fit_lppl numa janela deslizante, sem lookahead.

    Em cada ponto de avaliação ``i`` (de ``window`` até ``len``, passo
    ``step``), usa APENAS ``closes[i-window:i]`` — pontos estritamente
    ANTERIORES a ``i``. A data registada é ``dates[i-1]`` ("as of").
    Nenhum ponto com índice >= i entra no fit → zero lookahead.

    ``closes`` são preços crus; convertemos para log aqui (fit_lppl
    espera log-preços), a mesma transformação que quant_detectors faz.
    Retorna lista de dicts (um por ponto de avaliação).
    """
    n = len(closes)
    if len(dates) != n:
        raise ValueError(f"dates ({len(dates)}) != closes ({n})")
    out: list[dict] = []
    for i in range(window, n + 1, step):
        win = closes[i - window:i]
        # Guard de lookahead explícito: o último índice usado é i-1.
        assert len(win) == window
        lp = np.log(win)
        r = fit_lppl(lp)
        out.append({
            "as_of": dates[i - 1],
            "bubble_prob": round(float(r.get("bubble_prob", 0.0)), 4),
            "r2": round(float(r.get("r2", 0.0)), 4),
            "params_valid": bool(r.get("params_valid", False)),
            "tc_offset": round(float(r.get("tc_offset", 0.0)), 2)
            if r.get("fitted") else None,
            "beta": round(float(r.get("beta", 0.0)), 3)
            if r.get("fitted") else None,
            "omega": round(float(r.get("omega", 0.0)), 3)
            if r.get("fitted") else None,
        })
    return out


# ---------------------------------------------------------------------------
# Shell de I/O — só usado in-pod (lazy import de pg_database)
# ---------------------------------------------------------------------------

def from_quant_bars(ticker: str) -> tuple[list, np.ndarray]:
    """Carrega (dates, closes) de quant_bars para um ticker, asc por ts.
    Lazy import — não força dependência de Postgres para o núcleo puro."""
    from pg_database import connect
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT ts, close FROM quant_bars WHERE ticker = %s ORDER BY ts ASC",
            (ticker,),
        )
        rows = cur.fetchall()
    dates = [r["ts"].date() for r in rows]
    closes = np.array([float(r["close"]) for r in rows], dtype=float)
    return dates, closes


def to_csv(rows: list[dict], path: str) -> None:
    if not rows:
        raise ValueError("nada para escrever")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Walk-forward LPPL sobre quant_bars")
    ap.add_argument("--ticker", default="^GSPC")
    ap.add_argument("--step", type=int, default=21, help="passo em barras (21≈mensal)")
    ap.add_argument("--window", type=int, default=WINDOW_DAYS)
    ap.add_argument("--out", required=True, help="caminho do CSV de saída")
    args = ap.parse_args()

    dates, closes = from_quant_bars(args.ticker)
    if len(closes) < args.window:
        print(f"ERRO: {args.ticker} só tem {len(closes)} barras "
              f"(< window {args.window}). Correu a ingestão de ^GSPC?")
        return 1
    rows = walk_forward(dates, closes, step=args.step, window=args.window)
    to_csv(rows, args.out)
    n_flag = sum(1 for r in rows if r["bubble_prob"] > 0.7)
    print(f"{args.ticker}: {len(rows)} pontos {dates[0]}..{dates[-1]}, "
          f"{n_flag} com bubble_prob>0.7 ({100*n_flag/len(rows):.0f}%). "
          f"CSV -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
