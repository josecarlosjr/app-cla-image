"""Validação isolada da Peça 3 — detetor de reversão (Fase 2, Task 2).

Corre o detetor sobre research_btc (class='crypto', thr 0.50), mede se
deteta a ENTRADA nas reversões conhecidas (BTC 2018, BTC 2022) e — o
controlo NEGATIVO crítico — quantas vezes dispara na série completa.
Correções de 30-40% que não foram fim de ciclo NÃO devem disparar.

Leitura de DB: psycopg DIRETO (não pg_database). Núcleo assess_reversals
puro (testável sem DB).

Uso in-pod:
    PYTHONPATH=/app:/tmp/research python /tmp/research/validate_peca3.py
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

from reversal_detector import compute_reversal, reversal_entries  # noqa: E402

# Reversões conhecidas de fim de ciclo (janela = ano do crash).
KNOWN = {
    "BTC 2018 (pico dez/2017 ~19.7k → fundo ~3.2k, -84%)":
        (date(2018, 1, 1), date(2018, 12, 31)),
    "BTC 2022 (pico nov/2021 ~69k → fundo ~16k, -77%)":
        (date(2022, 1, 1), date(2022, 12, 31)),
}
# Controlo negativo: <=4 disparos totais = bom; >=10 = threshold baixo/ruidoso.
GOOD_MAX = 4
BAD_MIN = 10


def assess_reversals(entries: list[dict]) -> dict:
    """Puro: dado o conjunto de entradas em reversão, deteta as conhecidas
    e conta o total (controlo negativo)."""
    detected = {}
    for label, (lo, hi) in KNOWN.items():
        hits = [e for e in entries
                if lo <= date.fromisoformat(e["ts"][:10]) <= hi]
        detected[label] = hits[0] if hits else None
    total = len(entries)
    all_known_detected = all(v is not None for v in detected.values())
    if not all_known_detected:
        verdict = "FALHA (reversao conhecida NAO detetada)"
    elif total <= GOOD_MAX:
        verdict = "PASSA (deteta as 2 reais E fica quieta nas correcoes)"
    elif total >= BAD_MIN:
        verdict = "FALHA (dispara demais — threshold baixo/ruidoso)"
    else:
        verdict = "MARGINAL (5-9 disparos — Jose decide)"
    return {"detected": detected, "total_entries": total,
            "all_entries": entries, "verdict": verdict}


def report(a: dict) -> None:
    print("\nPeça 3 — reversão BTC (class=crypto, thr=0.50)\n")
    print("REVERSÕES CONHECIDAS (deteta a entrada?):")
    for label, hit in a["detected"].items():
        if hit:
            print(f"  {label}")
            print(f"    → ENTRADA {hit['ts']} (drawdown {hit['drawdown']:.2f}, "
                  f"preço {hit['price']:.0f}, pico90 {hit['peak_90d']:.0f})")
        else:
            print(f"  {label}\n    → NAO detetada")
    print(f"\nCONTROLO NEGATIVO — disparos totais na série: "
          f"{a['total_entries']}")
    for e in a["all_entries"]:
        print(f"    {e['ts']}  drawdown {e['drawdown']:.2f}  preço {e['price']:.0f}")
    print(f"\nVEREDICTO: {a['verdict']}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=2014)
    args = ap.parse_args()
    from validate_peca1 import load_series
    dates, closes = load_series("research_btc", args.start)
    print(f"research_btc: {len(closes)} barras {dates[0]}..{dates[-1]}",
          flush=True)
    rows = compute_reversal(dates, closes, "crypto")
    entries = reversal_entries(rows)
    a = assess_reversals(entries)
    report(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
