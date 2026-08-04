"""Medição do gate GSADF — Onda 13 Fase A (research).

Lê o CSV do gsadf_walkforward e aplica os CRITÉRIOS FIXOS do gate. Não
afina nada. Fonte de verdade = bsadf_latest > 1.49 (o mesmo limiar do
detector), recalculado do CSV para não depender da coluna `explosive`.

CRITÉRIOS FIXOS (não mexer):
  1. bsadf cruza 1.49 antes de cada crash (numa janela de até 24 meses
     antes do pico).
  2. lead time >= 2 MESES (60 dias) entre o 1º cruzamento SUSTENTADO e o
     pico. "Sustentado" = corrida de >= 2 pontos consecutivos do
     walk-forward acima de 1.49 (evita contar um spike isolado).
  3. <= 3 falsos positivos TOTAIS (cruzamentos ascendentes de 1.49) nos
     períodos calmos, somados.

VEREDICTO: PASSA sse os 4 crashes detetados com lead>=60d E FP_total<=3.

Uso:
    python research/measure_gsadf_gate.py --csv /tmp/gspc_gsadf_wf.csv
"""
from __future__ import annotations

import argparse
import csv
from datetime import date

THRESH = 1.49
PRE_WINDOW_MONTHS = 24     # janela pré-crash onde procuramos o sinal
MIN_LEAD_DAYS = 60         # >= 2 meses
MIN_SUSTAIN = 2            # pontos consecutivos acima = "sustentado"
MAX_FP = 3

# Picos dos crashes conhecidos (datas fixas do brief).
CRASHES = {
    "1987 Black Monday": date(1987, 10, 5),
    "2000 Dotcom":       date(2000, 3, 24),
    "2008 GFC":          date(2008, 9, 15),
    "2020 COVID":        date(2020, 2, 19),
}

# Períodos deliberadamente calmos (sem crash maior a seguir).
CALM = {
    "1993-1996": (date(1993, 1, 1), date(1996, 12, 31)),
    "2004-2006": (date(2004, 1, 1), date(2006, 12, 31)),
    "2013-2016": (date(2013, 1, 1), date(2016, 12, 31)),
}


def _parse(csv_path: str) -> list[dict]:
    out = []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            out.append({
                "ts": date.fromisoformat(row["ts"][:10]),
                "bsadf": float(row["bsadf_latest"]),
            })
    out.sort(key=lambda r: r["ts"])
    return out


def _months_before(peak: date, months: int) -> date:
    y, m = peak.year, peak.month - months
    while m <= 0:
        m += 12
        y -= 1
    return date(y, m, min(peak.day, 28))


def _first_sustained_crossing(rows: list[dict]) -> date | None:
    """1ª data que inicia uma corrida de >= MIN_SUSTAIN pontos com
    bsadf > THRESH. rows já ordenados por ts."""
    above = [r["bsadf"] > THRESH for r in rows]
    for i in range(len(rows) - MIN_SUSTAIN + 1):
        if all(above[i:i + MIN_SUSTAIN]):
            return rows[i]["ts"]
    return None


def _count_upcrossings(rows: list[dict]) -> int:
    """Nº de transições not-above -> above (cruzamentos ascendentes)."""
    n = 0
    prev = False
    for r in rows:
        cur = r["bsadf"] > THRESH
        if cur and not prev:
            n += 1
        prev = cur
    return n


def measure(rows: list[dict]) -> None:
    print(f"Gate GSADF — {len(rows)} janelas {rows[0]['ts']}..{rows[-1]['ts']}, "
          f"limiar={THRESH}\n")

    # --- Critérios 1+2: deteção + lead time por crash ---
    print("CRASHES (deteção + lead time):")
    all_detected = True
    for name, peak in CRASHES.items():
        lo = _months_before(peak, PRE_WINDOW_MONTHS)
        pre = [r for r in rows if lo <= r["ts"] <= peak]
        if not pre:
            print(f"  {name:20} SEM DADOS na janela pré-crash "
                  f"[{lo}..{peak}]")
            all_detected = False
            continue
        cross = _first_sustained_crossing(pre)
        if cross is None:
            maxb = max(r["bsadf"] for r in pre)
            print(f"  {name:20} NÃO detetado (max bsadf {maxb:.2f} < {THRESH})")
            all_detected = False
            continue
        lead = (peak - cross).days
        ok = lead >= MIN_LEAD_DAYS
        all_detected = all_detected and ok
        flag = "OK" if ok else f"lead<{MIN_LEAD_DAYS}d"
        print(f"  {name:20} detetado {cross} → lead {lead:4d} dias  [{flag}]")

    # --- Critério 3: falsos positivos nos períodos calmos ---
    print("\nPERÍODOS CALMOS (cruzamentos ascendentes de 1.49 = FP):")
    total_fp = 0
    for name, (a, b) in CALM.items():
        win = [r for r in rows if a <= r["ts"] <= b]
        fp = _count_upcrossings(win)
        total_fp += fp
        print(f"  {name:12} {fp} cruzamento(s) em {len(win)} janelas")

    # --- Veredicto ---
    print(f"\nCritério 1+2 (4 crashes detetados, lead>=60d): "
          f"{'OK' if all_detected else 'FALHA'}")
    print(f"Critério 3 (FP total <= {MAX_FP}): "
          f"{total_fp} FP → {'OK' if total_fp <= MAX_FP else 'FALHA'}")
    verdict = all_detected and total_fp <= MAX_FP
    print(f"\nVEREDICTO: {'PASSA' if verdict else 'FALHA'}")
    if not verdict:
        print("(FALHA é resultado válido — diz que o GSADF isolado não "
              "serve como gatilho, tal como o LPPL.)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    args = ap.parse_args()
    rows = _parse(args.csv)
    if not rows:
        print("CSV vazio")
        return 1
    measure(rows)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
