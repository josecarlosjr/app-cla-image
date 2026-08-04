"""Validação de mecânica (sem rede) — Onda 13 Fase A.

Duas provas focadas, deterministas, offline:

(A) walk_forward_gsadf corre gsadf() as-is sobre um AR-explosivo, com
    ASSERT de zero-lookahead em cada janela, e produz o schema certo
    (ts,bsadf_latest,gsadf_max,explosive). O AR-explosivo acende (Sprint B).

(B) measure_gsadf_gate lê um CSV datado sintético — bsadf alto SUSTENTADO
    nos meses antes de cada crash, baixo nos calmos, com 2 spikes isolados
    em período calmo — e produz um veredicto. Prova a lógica de deteção /
    lead time / contagem de FP sem correr GSADF.

Isto NÃO é o gate: é a prova de que o código corre. O gate real é o
^GSPC histórico in-pod (comandos no fim do relatório).
"""
from __future__ import annotations

import csv
import os
import sys
from datetime import date, timedelta

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for p in (_PARENT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from gsadf_walkforward import walk_forward_gsadf, to_csv  # noqa: E402
import measure_gsadf_gate as mg                            # noqa: E402

SCRATCH = "/tmp/claude-0/-home-user/6726d0c2-043f-5294-b94d-d992d7babf9f/scratchpad"


# ---------------------------------------------------------------------------
# (A) harness sobre AR-explosivo
# ---------------------------------------------------------------------------

def part_a() -> None:
    print("=== (A) walk_forward_gsadf sobre AR-explosivo ===")
    rng = np.random.default_rng(7)
    n = 900
    y = np.zeros(n)
    y[0] = 7.0
    boom_start = n - 150
    for t in range(1, n):
        rho = 1.01 if t >= boom_start else 1.0   # explosivo no fim
        y[t] = rho * y[t - 1] + rng.normal(0, 0.02)
    closes = np.exp(y)                           # harness faz np.log de volta
    d0 = date(2000, 1, 3)
    dates = [d0 + timedelta(days=i) for i in range(n)]

    rows = walk_forward_gsadf(dates, closes, step=21, window=252)
    # schema
    assert rows, "0 janelas"
    assert set(rows[0].keys()) == {"ts", "bsadf_latest", "gsadf_max",
                                   "explosive"}, rows[0].keys()
    n_expl = sum(1 for r in rows if r["explosive"])
    print(f"  {len(rows)} janelas, schema OK, assert zero-lookahead passou "
          f"em todas, {n_expl} explosive (AR-explosivo acende).")
    out = os.path.join(SCRATCH, "validate_gsadf_wf.csv")
    to_csv(rows, out)
    print(f"  CSV escrito -> {out}")


# ---------------------------------------------------------------------------
# (B) measure sobre CSV datado sintético
# ---------------------------------------------------------------------------

def part_b() -> None:
    print("\n=== (B) measure_gsadf_gate sobre CSV datado sintético ===")
    # Grelha mensal 1985..2021.
    rows = []
    d = date(1985, 1, 15)
    while d <= date(2021, 6, 15):
        rows.append({"ts": d, "bsadf": -1.0})
        # avança ~1 mês
        y, m = d.year, d.month + 1
        if m > 12:
            m = 1
            y += 1
        d = date(y, m, 15)

    def set_high(target: date, k: int, val: float = 2.5):
        """Põe os k pontos ANTES de target (inclusive o mais próximo) altos."""
        idx = [i for i, r in enumerate(rows) if r["ts"] <= target]
        for i in idx[-k:]:
            rows[i]["bsadf"] = val

    # Sinal sustentado (3 meses) antes de cada crash → lead ~2-4 meses.
    for peak in mg.CRASHES.values():
        # aponta para ~3 meses antes do pico, sustentado 3 pontos
        pre = date(peak.year, peak.month, 1) - timedelta(days=75)
        set_high(pre, 3, 2.5)

    # 2 spikes isolados em período calmo (FP): contam como 2 cruzamentos.
    for fp_date in (date(1994, 6, 15), date(2005, 6, 15)):
        for i, r in enumerate(rows):
            if r["ts"] == fp_date:
                r["bsadf"] = 2.0

    # escreve CSV e corre measure
    out = os.path.join(SCRATCH, "validate_gsadf_gate.csv")
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts", "bsadf_latest", "gsadf_max", "explosive"])
        for r in rows:
            w.writerow([r["ts"].isoformat(), r["bsadf"], r["bsadf"],
                        r["bsadf"] > mg.THRESH])
    parsed = mg._parse(out)
    mg.measure(parsed)


if __name__ == "__main__":
    part_a()
    part_b()
