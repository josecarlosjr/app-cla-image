"""TESTE B — o limiar calibrado FICA QUIETO numa subida saudável?

Teste decisivo e barato antes da validação completa. Um limiar baixo
demais acende em qualquer subida (bolhas trivialmente); o que separa é
ficar QUIETO numa subida NORMAL. S&P 2013-2016 subiu bem, sem bolha.

Corre o GSADF CALIBRADO (crit p95 do JSON, interpolado a n=252) em
walk-forward sobre S&P 2013-2016 e reporta a taxa de acendimento.

CRITÉRIO FIXO (não mexer):
  - acende em > 20% das janelas → limiar baixo demais, discrimina nada:
    FALHA. Repensar o limiar ANTES de validar contra bolhas.
  - 0-1 acendimentos (quieto) → limiar promete: avança p/ validação.
  - entre 1 e 20% → MARGINAL, reportar (Jose decide).

Compara sempre com o fixo antigo (1.49) lado a lado.

Núcleo `assess_calm` puro (testável sem DB). Shell = validate_peca1.load_series.

Uso in-pod:
    python test_b_calm.py --json gsadf_critical_values.json --step 21
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

from quant_detectors import WINDOW_DAYS                    # noqa: E402
from gsadf_calibrated import (                             # noqa: E402
    load_critical_values, interp_crit, walk_forward_calibrated,
)

CALM_LO = date(2013, 1, 1)
CALM_HI = date(2016, 12, 31)
FAIL_RATE = 0.20   # > 20% acesos = limiar baixo demais
QUIET_MAX = 1      # <= 1 aceso = quieto/promete


def assess_calm(rows: list[dict], lo: date = CALM_LO,
                hi: date = CALM_HI) -> dict:
    """Puro: dado o walk-forward calibrado, taxa de acendimento no calmo
    sob o limiar calibrado (explosive_cal95) e o fixo (explosive)."""
    win = [r for r in rows
           if lo <= date.fromisoformat(r["ts"][:10]) <= hi]
    n = len(win)
    fire_cal = sum(1 for r in win if r.get("explosive_cal95"))
    fire_fix = sum(1 for r in win if r.get("explosive"))
    rate_cal = fire_cal / n if n else 0.0
    if n == 0:
        verdict = "SEM DADOS"
    elif rate_cal > FAIL_RATE:
        verdict = "FALHA (limiar baixo demais — acende no calmo)"
    elif fire_cal <= QUIET_MAX:
        verdict = "PROMETE (quieto no calmo — avanca p/ validacao)"
    else:
        verdict = "MARGINAL (entre 1 e 20% — Jose decide)"
    return {
        "n_windows": n, "fire_cal": fire_cal, "fire_fix": fire_fix,
        "rate_cal": rate_cal, "verdict": verdict,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=os.path.join(
        _HERE, "gsadf_critical_values.json"))
    ap.add_argument("--step", type=int, default=21)
    args = ap.parse_args()

    from validate_peca1 import load_series
    tbl = load_critical_values(args.json)
    crit95 = interp_crit(WINDOW_DAYS, tbl, "p95")

    # Carrega desde 2012 para haver janela de 252 antes de 2013-01.
    dates, closes = load_series("research_gspc", 2012)
    print(f"research_gspc: {len(closes)} barras {dates[0]}..{dates[-1]}",
          flush=True)
    rows = walk_forward_calibrated(dates, closes, tbl, step=args.step)
    r = assess_calm(rows)

    print(f"\nTESTE B — S&P {CALM_LO.year}-{CALM_HI.year} (subida saudavel)")
    print(f"  crit_95 calibrado (n={WINDOW_DAYS}) = {crit95:.3f}   "
          f"(fixo antigo = 1.49)")
    print(f"  janelas no periodo: {r['n_windows']}")
    print(f"  acendimentos CALIBRADO (>{crit95:.2f}): {r['fire_cal']} "
          f"({100*r['rate_cal']:.0f}%)")
    print(f"  acendimentos FIXO (>1.49):        {r['fire_fix']}")
    print(f"\n  VEREDICTO: {r['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
