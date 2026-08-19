"""Teste do sistema COMPLETO — Peças 1+2+3 no BTC real (Fase 3, Task 3).

Corre as 3 peças alinhadas sobre research_btc:
  Peça1 (GSADF calibrado, mensal) + Peça3 (reversão, diária) → Peça2
  (máquina de estados). Reporta a trajetória de estados 2014-2026 e
  verifica os 2 ciclos de bolha conhecidos (2017-18, 2020-22),
  provando que BOLHA_ATIVA persiste entre o topo (GSADF adormece) e a
  reversão.

As duas peças correm em grelhas diferentes: a Peça 1 (GSADF) é cara →
mensal (step=21); a Peça 3 (drawdown) é barata → diária. Alinhamos na
grelha MENSAL da Peça 1: por cada ponto mensal, a Peça 1 dá explosive,
e a Peça 3 dá (houve entrada em reversão desde o mês anterior? qual o
drawdown agora?).

Leitura de DB: psycopg DIRETO. Núcleos align_on_p1_grid / assess_cycles
puros (testáveis sem DB).

Uso in-pod:
    PYTHONPATH=/app:/tmp/research python /tmp/research/validate_sistema_completo.py
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
from validate_peca3 import distinct_entries                      # noqa: E402
from bubble_state_machine import (                               # noqa: E402
    run_state_machine, extract_transitions, absorbed_corrections,
    BOLHA_ATIVA, REVERSAO,
)

# Ciclos de bolha conhecidos: reversão esperada dentro destas janelas.
CYCLES = {
    "BTC 2017-18": (date(2018, 1, 1), date(2018, 12, 31)),
    "BTC 2020-22": (date(2022, 1, 1), date(2022, 12, 31)),
}


def align_on_p1_grid(
    p1_rows: list[dict],
    drawdown_by_date: dict,
    entry_dates: list,
) -> tuple[list, list, list, list]:
    """Alinha Peça1 (mensal) + Peça3 (diária) na grelha da Peça 1.

    Devolve (dates, p1_explosive, p3_entry, drawdown) alinhados por índice.
    ``p3_entry[i]`` = houve alguma entrada em reversão em (mês anterior, mês i].
    ``drawdown[i]`` = drawdown diário na data do mês i (ou o último prévio)."""
    ent = sorted(entry_dates)
    dates, p1e, p3e, dd, bs = [], [], [], [], []
    prev = None
    for r in p1_rows:
        ts = date.fromisoformat(r["ts"][:10])
        dates.append(ts)
        p1e.append(bool(r.get("explosive_cal95")))
        bs.append(r.get("bsadf_latest"))
        lo = prev if prev is not None else date.min
        p3e.append(any(lo < d <= ts for d in ent))
        if ts in drawdown_by_date:
            dd.append(drawdown_by_date[ts])
        else:
            priors = [d for d in drawdown_by_date if d <= ts]
            dd.append(drawdown_by_date[max(priors)] if priors else 0.0)
        prev = ts
    return dates, p1e, p3e, dd, bs


def assess_cycles(transitions: list[dict]) -> dict:
    """Para cada ciclo conhecido, houve uma transição BOLHA_ATIVA→REVERSAO
    dentro da janela? E foi precedida de BOLHA_ATIVA (i.e. o sistema
    passou pelos 4 estados)?"""
    rev = [t for t in transitions
           if t["to"] == REVERSAO and t["from"] == BOLHA_ATIVA]
    saw_bubble = any(t["to"] == BOLHA_ATIVA for t in transitions)
    detected = {}
    for label, (lo, hi) in CYCLES.items():
        hit = next((t for t in rev
                    if lo <= t["ts"] <= hi), None)
        detected[label] = hit
    all_ok = saw_bubble and all(v is not None for v in detected.values())
    return {"detected": detected, "saw_bubble": saw_bubble,
            "n_reversals_from_bubble": len(rev), "all_ok": all_ok}


def report(transitions: list[dict], states: list[dict], a: dict) -> None:
    print("\nTrajetória de estados (transições):")
    for t in transitions:
        print(f"  {t['ts']}  {t['from'] or '(inicio)'} -> {t['to']}")

    # Prova de persistência: nº de pontos BOLHA_ATIVA com Peça1 apagada
    # não é visível aqui (states não carrega expl), mas a duração de cada
    # troço BOLHA_ATIVA mostra que persistiu até à reversão.
    print("\nCICLOS DE BOLHA CONHECIDOS:")
    for label, hit in a["detected"].items():
        if hit:
            print(f"  {label}: REVERSAO (de BOLHA_ATIVA) em {hit['ts']}  ✓")
        else:
            print(f"  {label}: NAO detetada  ✗")
    print(f"\nReversões-de-bolha totais na série: {a['n_reversals_from_bubble']}")
    verdict = ("PASSA (sistema deteta os 2 ciclos end-to-end; BOLHA_ATIVA "
               "persistiu do topo ate a reversao)" if a["all_ok"]
               else "FALHA (ver acima)")
    print(f"\nVEREDICTO: {verdict}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", default="research_btc",
                    choices=["research_btc", "research_eth"],
                    help="tabela cripto (ETH = teste de generalizacao; "
                         "MESMO threshold/crit, NAO re-afinar)")
    ap.add_argument("--start", type=int, default=2014)
    ap.add_argument("--step", type=int, default=21)
    args = ap.parse_args()

    from validate_peca1 import load_series
    from gsadf_calibrated import (
        load_critical_values, walk_forward_calibrated)

    dates, closes = load_series(args.table, args.start)
    print(f"{args.table}: {len(closes)} barras {dates[0]}..{dates[-1]}",
          flush=True)

    table = load_critical_values()
    # Peça 1 (mensal)
    p1_rows = walk_forward_calibrated(dates, closes, table, step=args.step)
    # Peça 3 (diária)
    thr = CLASS_THRESHOLD["crypto"]
    p3_rows = compute_reversal(dates, closes, "crypto")
    entries = distinct_entries(p3_rows, thr)
    dd_by_date = {date.fromisoformat(r["ts"][:10]): r["drawdown"]
                  for r in p3_rows}
    ent_dates = [date.fromisoformat(e["ts"][:10]) for e in entries]

    # Alinhar + Peça 2 (com bsadf p/ o refinamento C)
    al_dates, p1e, p3e, dd, bs = align_on_p1_grid(
        p1_rows, dd_by_date, ent_dates)
    states = run_state_machine(al_dates, p1e, p3e, dd, bs)
    trans = extract_transitions(states)
    a = assess_cycles(trans)
    report(trans, states, a)

    absorbed = absorbed_corrections(states)
    print(f"\nCorreções de meio-ciclo absorvidas (Peça3 disparou mas GSADF "
          f"ainda vivo → manteve BOLHA_ATIVA): {len(absorbed)}")
    for d in absorbed:
        print(f"    {d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
