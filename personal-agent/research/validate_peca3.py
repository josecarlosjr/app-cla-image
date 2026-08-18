"""Validação isolada da Peça 3 — detetor de reversão (Fase 2, Task 2).

Corre o detetor sobre research_btc (class='crypto', thr 0.50), mede se
deteta a ENTRADA nas reversões conhecidas (BTC 2018, BTC 2022) e — o
controlo NEGATIVO — quantas ENTRADAS DISTINTAS há na série completa.

Contagem com RE-ARME (hysteresis): uma queda protraída faz o drawdown
oscilar à volta de 0.50 (bounces, ou o pico de 90d a envelhecer),
gerando várias transições False→True para a MESMA queda. Contamos uma
entrada e só re-armamos quando o preço RECUPERA (drawdown < REARM=0.20).
Isto NÃO muda o detetor (threshold, pico-90d, método) — só a contagem.

Leitura de DB: psycopg DIRETO (não pg_database). Núcleos puros
(distinct_entries, assess_reversals) testáveis sem DB.

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

from reversal_detector import compute_reversal, CLASS_THRESHOLD  # noqa: E402

REARM = 0.20   # re-arma quando o drawdown recupera abaixo disto

# Reversões conhecidas de fim de ciclo (janela = ano do crash).
KNOWN = {
    "BTC 2018 (pico dez/2017 ~19.7k → fundo ~3.2k, -84%)":
        (date(2018, 1, 1), date(2018, 12, 31)),
    "BTC 2022 (pico nov/2021 ~69k → fundo ~16k, -77%)":
        (date(2022, 1, 1), date(2022, 12, 31)),
}
# Veredicto: PASSA se deteta as 2 alvo E o total de entradas DISTINTAS < 8.
DISTINCT_MAX = 8


def distinct_entries(rows: list[dict], thr: float,
                     rearm: float = REARM) -> list[dict]:
    """Entradas DISTINTAS em reversão, com re-arme (Schmitt trigger).

    Dispara quando o drawdown cruza ``thr`` estando ARMADO; depois fica
    disparado (não conta de novo) até o drawdown recuperar abaixo de
    ``rearm`` — só então re-arma. Uma queda que oscila acima de ``rearm``
    conta UMA vez. Só uma recuperação genuína permite nova entrada."""
    entries: list[dict] = []
    armed = True
    for r in rows:
        dd = r["drawdown"]
        if armed and dd >= thr:
            entries.append({
                "ts": r["ts"], "drawdown": r["drawdown"],
                "price": r["price"], "peak_90d": r["peak_90d"],
            })
            armed = False
        elif (not armed) and dd < rearm:
            armed = True
    return entries


def assess_reversals(entries: list[dict]) -> dict:
    """Puro: deteta as reversões conhecidas e conta as entradas distintas."""
    detected = {}
    for label, (lo, hi) in KNOWN.items():
        hits = [e for e in entries
                if lo <= date.fromisoformat(e["ts"][:10]) <= hi]
        detected[label] = hits[0] if hits else None
    total = len(entries)
    all_known = all(v is not None for v in detected.values())
    if not all_known:
        verdict = "FALHA (reversao conhecida NAO detetada)"
    elif total < DISTINCT_MAX:
        verdict = ("PASSA (deteta as 2 alvo E poucas entradas distintas — "
                   "as quedas genuinas 2020/2021 nao sao falsos positivos; "
                   "o 'era bolha?' e da Peca 2)")
    else:
        verdict = (f"MARGINAL ({total} entradas distintas >= {DISTINCT_MAX} — "
                   "Jose decide)")
    return {"detected": detected, "total_entries": total,
            "all_entries": entries, "verdict": verdict}


def report(a: dict, thr: float) -> None:
    print(f"\nPeça 3 — reversão BTC (class=crypto, thr={thr}, re-arme<{REARM})\n")
    print("REVERSÕES CONHECIDAS (deteta a entrada?):")
    for label, hit in a["detected"].items():
        if hit:
            print(f"  {label}")
            print(f"    → ENTRADA {hit['ts']} (drawdown {hit['drawdown']:.2f}, "
                  f"preço {hit['price']:.0f}, pico90 {hit['peak_90d']:.0f})")
        else:
            print(f"  {label}\n    → NAO detetada")
    print(f"\nCONTROLO NEGATIVO — ENTRADAS DISTINTAS na série: "
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
    thr = CLASS_THRESHOLD["crypto"]
    rows = compute_reversal(dates, closes, "crypto")
    entries = distinct_entries(rows, thr)
    a = assess_reversals(entries)
    report(a, thr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
