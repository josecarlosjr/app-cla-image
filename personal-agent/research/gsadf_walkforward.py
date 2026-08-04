"""Walk-forward GSADF sobre ^GSPC — Onda 13 Fase A do gate (research).

Núcleo PURO (``walk_forward_gsadf``) + shell fino de I/O
(``from_quant_bars``, ``to_csv``). O núcleo aceita arrays já carregados,
por isso corre local com dados sintéticos (validação de mecânica) OU
in-pod com ^GSPC real de quant_bars.

REGRA DE INTEGRIDADE: importa ``quant_detectors.gsadf`` tal como está —
zero mudança. Zero lookahead por construção (assert incluído). Não escreve
em quant_features nem toca produção.

Portável: ``_PARENT`` resolve para o diretório onde vive quant_detectors —
``/app`` no pod (research/ copiado para /app/research), ou
``personal-agent/`` local. O mesmo ficheiro corre nos dois.

AVISO DE CUSTO: gsadf() é O(n²) na janela — ~2.4s por janela de 252. Um
walk-forward mensal (step=21) de 1970→2026 são ~660 janelas ≈ 26 min.
Reduz com --step maior (63=trimestral ≈ 9 min) se só quiseres a forma.

Uso in-pod (^GSPC já em quant_bars):
    python research/gsadf_walkforward.py --ticker '^GSPC' --start 1970 \\
        --step 21 --out /tmp/gspc_gsadf_wf.csv
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

from quant_detectors import gsadf, WINDOW_DAYS  # noqa: E402  (as-is)

CRIT_95 = 1.49  # PSY (2015) — o mesmo limiar fixo que quant_detectors usa


# ---------------------------------------------------------------------------
# Núcleo puro — testável sem DB
# ---------------------------------------------------------------------------

def walk_forward_gsadf(
    dates: list,
    closes: np.ndarray,
    *,
    step: int = 21,
    window: int = WINDOW_DAYS,
) -> list[dict]:
    """Corre gsadf() numa janela deslizante, sem lookahead.

    Em cada ponto de avaliação ``i`` (de ``window`` até ``len``, passo
    ``step``), usa APENAS ``closes[i-window:i]`` — pontos com índice
    <= i-1. A data registada é ``dates[i-1]`` ("as of"). Nenhum ponto
    com índice >= i entra no fit → zero lookahead (assert).

    Input do gsadf: log dos closes (o mesmo que quant_detectors faz).
    Grava por ponto: ts, bsadf_latest, gsadf_max, explosive (bsadf>1.49).
    """
    n = len(closes)
    if len(dates) != n:
        raise ValueError(f"dates ({len(dates)}) != closes ({n})")
    if n < window:
        return []
    out: list[dict] = []
    for i in range(window, n + 1, step):
        win = closes[i - window:i]
        # Guard de lookahead: o último índice usado é i-1; win não vê >= i.
        assert len(win) == window
        assert win[-1] == closes[i - 1]
        lp = np.log(win)
        g = gsadf(lp)
        bsadf = float(g.get("bsadf_latest", 0.0))
        out.append({
            "ts": dates[i - 1].isoformat()
            if hasattr(dates[i - 1], "isoformat") else str(dates[i - 1]),
            "bsadf_latest": round(bsadf, 4),
            "gsadf_max": round(float(g.get("gsadf", 0.0)), 4),
            "explosive": bool(bsadf > CRIT_95),
        })
    return out


# ---------------------------------------------------------------------------
# Shell de I/O — só usado in-pod (lazy import de pg_database)
# ---------------------------------------------------------------------------

def from_quant_bars(ticker: str, start_year: int) -> tuple[list, np.ndarray]:
    """Carrega (dates, closes) de quant_bars, asc por ts, ts >= start_year.

    Lazy import — não força dependência de Postgres para o núcleo puro.
    NB: a 1ª janela consome os primeiros ``window`` pontos, portanto o
    1º ponto de avaliação fica ~1 ano de trading após ``start_year``.
    """
    from pg_database import connect
    cutoff = date(start_year, 1, 1)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT ts, close FROM quant_bars "
            "WHERE ticker = %s AND ts >= %s ORDER BY ts ASC",
            (ticker, cutoff),
        )
        rows = cur.fetchall()
    dates = [r["ts"].date() for r in rows]
    closes = np.array([float(r["close"]) for r in rows], dtype=float)
    return dates, closes


def to_csv(rows: list[dict], path: str) -> None:
    if not rows:
        raise ValueError("nada para escrever (0 janelas)")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "bsadf_latest",
                                          "gsadf_max", "explosive"])
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Walk-forward GSADF sobre quant_bars (Fase A do gate). "
                    "AVISO: gsadf é O(n²) ~2.4s/janela; mensal 1970→2026 "
                    "~26 min. Usa --step 63 (trimestral, ~9 min) para a forma.",
    )
    ap.add_argument("--ticker", default="^GSPC")
    ap.add_argument("--start", type=int, default=1970, help="ano inicial")
    ap.add_argument("--step", type=int, default=21,
                    help="passo em barras (21≈mensal, 63≈trimestral)")
    ap.add_argument("--window", type=int, default=WINDOW_DAYS)
    ap.add_argument("--out", required=True, help="caminho do CSV de saída")
    args = ap.parse_args()

    dates, closes = from_quant_bars(args.ticker, args.start)
    if len(closes) < args.window:
        print(f"ERRO: {args.ticker} só tem {len(closes)} barras "
              f">= {args.start} (< window {args.window}). "
              f"Correu a ingestão de ^GSPC?")
        return 1
    rows = walk_forward_gsadf(dates, closes, step=args.step, window=args.window)
    to_csv(rows, args.out)
    n_expl = sum(1 for r in rows if r["explosive"])
    print(f"{args.ticker}: {len(rows)} janelas {rows[0]['ts']}..{rows[-1]['ts']}, "
          f"{n_expl} explosive (bsadf>{CRIT_95}) ({100*n_expl/len(rows):.0f}%). "
          f"CSV -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
