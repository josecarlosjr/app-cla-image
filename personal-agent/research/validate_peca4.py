"""Validação da Peça 4 — sinal de atenção de momentum (BTC real).

Corre o momentum signal em walk-forward diário sobre research_btc e
reporta quando acendeu ALTO/MEDIO, verificando especificamente se a 2ª
perna de 2021 (jul-nov, +130%, invisível ao GSADF) foi sinalizada.

É uma camada INFORMATIVA (não um detetor): reporta um facto (momentum
extremo), não faz previsão. Núcleos puros; shell psycopg direto.

Uso in-pod:
    PYTHONPATH=/app:/tmp/research python /tmp/research/validate_peca4.py
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import date

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for p in (_PARENT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from momentum_signal import compute_momentum  # noqa: E402

# Janelas conhecidas a verificar.
WINDOWS = {
    "1a perna 2017":        (date(2017, 1, 1), date(2017, 12, 31)),
    "1a perna 2020-21":     (date(2020, 10, 1), date(2021, 5, 31)),
    "2a perna 2021 (jul-nov, +130%, GSADF cego)":
                            (date(2021, 7, 1), date(2021, 11, 30)),
}


def _d(ts: str) -> date:
    return date.fromisoformat(ts[:10])


def spans(rows: list[dict], levels: set) -> list[dict]:
    """Troços contíguos onde level ∈ levels. Cada troço: início, fim,
    percentil de pico, momentum de pico."""
    out, cur = [], None
    for r in rows:
        if r["level"] in levels:
            if cur is None:
                cur = {"start": r["ts"], "end": r["ts"],
                       "peak_pct": r["percentile"] or 0.0,
                       "peak_mom": r["momentum"] or 0.0}
            else:
                cur["end"] = r["ts"]
                if (r["percentile"] or 0) > cur["peak_pct"]:
                    cur["peak_pct"] = r["percentile"]
                if (r["momentum"] or 0) > cur["peak_mom"]:
                    cur["peak_mom"] = r["momentum"]
        elif cur is not None:
            out.append(cur); cur = None
    if cur is not None:
        out.append(cur)
    return out


def window_check(rows: list[dict], lo: date, hi: date) -> dict:
    """Melhor nível e percentil de pico numa janela [lo,hi]."""
    win = [r for r in rows if r["percentile"] is not None
           and lo <= _d(r["ts"]) <= hi]
    if not win:
        return {"fired": "SEM DADOS", "peak_pct": None, "peak_date": None}
    best = max(win, key=lambda r: r["percentile"])
    fired = "ALTO" if any(r["level"] == "ALTO" for r in win) else (
        "MEDIO" if any(r["level"] == "MEDIO" for r in win) else "-")
    return {"fired": fired, "peak_pct": best["percentile"],
            "peak_date": best["ts"]}


def pct_alto(rows: list[dict]) -> float:
    leveled = [r for r in rows if r["percentile"] is not None]
    if not leveled:
        return 0.0
    return sum(1 for r in leveled if r["level"] == "ALTO") / len(leveled)


def report(rows: list[dict]) -> None:
    alto_spans = spans(rows, {"ALTO"})
    print(f"\nPeça 4 — momentum de atenção (BTC). Troços ALTO (top 5%):")
    for s in alto_spans:
        print(f"  {s['start']}..{s['end']}  pico percentil {s['peak_pct']}"
              f"  momentum pico {s['peak_mom']:+.2f}")

    print("\nJANELAS CONHECIDAS:")
    for label, (lo, hi) in WINDOWS.items():
        c = window_check(rows, lo, hi)
        print(f"  {label}")
        print(f"    → acendeu: {c['fired']}  (pico percentil {c['peak_pct']} "
              f"em {c['peak_date']})")

    frac = pct_alto(rows)
    print(f"\n% do tempo em ALTO: {100*frac:.1f}%  "
          f"(sanity: ~5% por construcao; >20% = percentil mal)")
    two_leg = window_check(rows, *WINDOWS[
        "2a perna 2021 (jul-nov, +130%, GSADF cego)"])["fired"]
    print(f"\nOBJETIVO desta peca — 2a perna nov/2021 sinalizada: "
          f"{'SIM (' + two_leg + ')' if two_leg in ('ALTO','MEDIO') else 'NAO'}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", default="research_btc",
                    choices=["research_btc", "research_eth"])
    ap.add_argument("--start", type=int, default=2014)
    args = ap.parse_args()
    from validate_peca1 import load_series
    dates, closes = load_series(args.table, args.start)
    print(f"{args.table}: {len(closes)} barras {dates[0]}..{dates[-1]}",
          flush=True)
    rows = compute_momentum(dates, closes)
    report(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
