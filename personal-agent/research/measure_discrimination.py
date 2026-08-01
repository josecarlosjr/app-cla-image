"""Fase 3 — medição da discriminação do LPPL walk-forward.

Lê o CSV produzido por lppl_walkforward.py e mede, contra crashes
conhecidos e períodos calmos:
  - true positive : bubble_prob subiu acima do limiar nos 6-18 meses
    ANTES de cada crash? lead time?
  - true negative : bubble_prob ficou baixo nos períodos calmos?
  - falsos positivos: janelas com prob alto FORA das janelas pré-crash.

Não afina nada. Só mede sobre a saída do harness. Limiar configurável
(default 0.7, o mesmo que quant_detectors.main usa para "bubbly").

Uso:
    python research/measure_discrimination.py --csv /tmp/gspc_wf.csv --threshold 0.7
"""
from __future__ import annotations

import argparse
import csv
from datetime import date


# Crashes conhecidos (mês do pico/início da queda).
CRASHES = {
    "1987-Black Monday": date(1987, 10, 1),
    "2000-Dotcom":       date(2000, 3, 1),
    "2008-GFC":          date(2008, 9, 1),
    "2020-COVID":        date(2020, 2, 1),
}

# Períodos deliberadamente calmos (sem crash maior a seguir).
CALM = {
    "1993-1996": (date(1993, 1, 1), date(1996, 12, 31)),
    "2004-2006": (date(2004, 1, 1), date(2006, 12, 31)),
    "2013-2016": (date(2013, 1, 1), date(2016, 12, 31)),
}

# Janela de antecipação válida antes de um crash (meses).
LEAD_MIN_M, LEAD_MAX_M = 6, 18


def _parse(csv_path: str) -> list[dict]:
    out = []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            out.append({
                "as_of": date.fromisoformat(row["as_of"][:10]),
                "bubble_prob": float(row["bubble_prob"]),
            })
    out.sort(key=lambda r: r["as_of"])
    return out


def _months_between(a: date, b: date) -> float:
    return (b.year - a.year) * 12 + (b.month - a.month)


def measure(rows: list[dict], threshold: float) -> None:
    print(f"Discriminação LPPL — {len(rows)} pontos "
          f"{rows[0]['as_of']}..{rows[-1]['as_of']}, limiar={threshold}\n")

    # --- True positives: sinal alto na janela [6,18]m antes de cada crash ---
    print("CRASHES (sinal alto 6-18m antes = acerto):")
    hits = 0
    for name, peak in CRASHES.items():
        pre = [r for r in rows
               if LEAD_MIN_M <= _months_between(r["as_of"], peak) <= LEAD_MAX_M]
        if not pre:
            print(f"  {name:20} sem dados na janela pré-crash")
            continue
        fired = [r for r in pre if r["bubble_prob"] > threshold]
        if fired:
            hits += 1
            first = min(fired, key=lambda r: r["as_of"])
            lead = _months_between(first["as_of"], peak)
            maxp = max(r["bubble_prob"] for r in pre)
            print(f"  {name:20} ACENDEU (lead {lead:.0f}m, "
                  f"{len(fired)}/{len(pre)} janelas, max prob {maxp:.2f})")
        else:
            maxp = max(r["bubble_prob"] for r in pre)
            print(f"  {name:20} NÃO acendeu (max prob {maxp:.2f})")

    # --- False positives: sinal alto nos períodos calmos ---
    print("\nPERÍODOS CALMOS (sinal alto = falso positivo):")
    total_calm, total_fp = 0, 0
    for name, (a, b) in CALM.items():
        win = [r for r in rows if a <= r["as_of"] <= b]
        fp = [r for r in win if r["bubble_prob"] > threshold]
        total_calm += len(win)
        total_fp += len(fp)
        pct = 100 * len(fp) / len(win) if win else 0
        print(f"  {name:12} {len(fp):3}/{len(win):3} janelas altas ({pct:.0f}% falsos +)")

    # --- Baseline global de falsos positivos ---
    all_high = sum(1 for r in rows if r["bubble_prob"] > threshold)
    print(f"\nBaseline global: {all_high}/{len(rows)} "
          f"({100*all_high/len(rows):.0f}%) de TODAS as janelas com prob>{threshold}")
    print(f"Crashes acertados: {hits}/{len(CRASHES)}")
    print(f"Falsos positivos em períodos calmos: {total_fp}/{total_calm} "
          f"({100*total_fp/total_calm:.0f}%)" if total_calm else "")

    print("\nLeitura: um sinal útil isolado acerta os 4 crashes E fica baixo "
          "nos calmos. Se o baseline global de 'prob alto' já é grande, o "
          "sinal não discrimina — acende quase sempre.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--threshold", type=float, default=0.7)
    args = ap.parse_args()
    rows = _parse(args.csv)
    measure(rows, args.threshold)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
