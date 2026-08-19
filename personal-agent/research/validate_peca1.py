"""Validação isolada da Peça 1 — GSADF calibrado (Task 3).

Corre o GSADF CALIBRADO (limiar Monte Carlo) em walk-forward sobre
research_gspc e research_btc, e mede se acende DURANTE as fases de subida
de bolhas conhecidas de PREÇO, ficando quieto nos períodos calmos.
Compara com o limiar fixo antigo (1.49).

CRITÉRIO DA PEÇA 1 (não é acender no topo — isso é a Peça 2): acender
durante o REGIME de subida explosiva, de forma diferenciada (bolha >>
calmo). Se não diferenciar, é resultado válido.

Leitura de DB: psycopg DIRETO (NÃO pg_database — pipeline mode rebenta
locks). DSN de DATABASE_URL ou o host do cluster.

O núcleo `measure_by_regime` é puro (testável sem DB).
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import date

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for p in (_PARENT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from gsadf_calibrated import (  # noqa: E402
    load_critical_values, walk_forward_calibrated,
)

_TABLES = {"research_gspc", "research_btc", "research_eth"}  # whitelist (anti-injection)

# Bolhas de PREÇO conhecidas: (label, tabela, pico). Run-up = [pico-12m, pico].
BUBBLES = [
    ("S&P 2000",  "research_gspc", date(2000, 3, 24)),
    ("BTC 2017",  "research_btc",  date(2017, 12, 17)),
    ("BTC 2021",  "research_btc",  date(2021, 11, 10)),
]
RUNUP_MONTHS = 12

# Períodos calmos: (label, tabela, inicio, fim).
CALM = [
    ("S&P 1993-96", "research_gspc", date(1993, 1, 1), date(1996, 12, 31)),
    ("S&P 2004-06", "research_gspc", date(2004, 1, 1), date(2006, 12, 31)),
    ("S&P 2013-16", "research_gspc", date(2013, 1, 1), date(2016, 12, 31)),
    ("BTC 2019",    "research_btc",  date(2019, 1, 1), date(2019, 12, 31)),
]


def _months_before(peak: date, months: int) -> date:
    y, m = peak.year, peak.month - months
    while m <= 0:
        m += 12
        y -= 1
    return date(y, m, min(peak.day, 28))


# ---------------------------------------------------------------------------
# DB shell — psycopg direto
# ---------------------------------------------------------------------------

def load_series(table: str, start_year: int) -> tuple[list, np.ndarray]:
    if table not in _TABLES:
        raise ValueError(f"tabela não permitida: {table}")
    import psycopg
    dsn = os.environ.get("DATABASE_URL") or (
        "host=postgres.personal-agent.svc.cluster.local "
        "user=pia dbname=agent"
    )
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT ts, close FROM {table} "
            f"WHERE ts >= %s ORDER BY ts ASC",
            (date(start_year, 1, 1),),
        )
        rows = cur.fetchall()
    dates = [r[0].date() if hasattr(r[0], "date") else r[0] for r in rows]
    closes = np.array([float(r[1]) for r in rows], dtype=float)
    return dates, closes


# ---------------------------------------------------------------------------
# Núcleo puro de medição
# ---------------------------------------------------------------------------

def _fire_rate(rows: list[dict], lo: date, hi: date, field: str) -> tuple[int, int]:
    """(n_acesos, n_janelas) no intervalo [lo,hi] para o campo booleano."""
    win = [r for r in rows if lo <= date.fromisoformat(r["ts"][:10]) <= hi]
    fired = sum(1 for r in win if r[field])
    return fired, len(win)


def measure_by_regime(rows_by_table: dict[str, list[dict]]) -> dict:
    """Para cada bolha (run-up) e cada calmo, taxa de acendimento sob o
    limiar fixo (>1.49) e o calibrado (>crit95). rows_by_table:
    {tabela: walk_forward_calibrated(...)}."""
    out = {"bubbles": [], "calm": []}
    for label, table, peak in BUBBLES:
        rows = rows_by_table.get(table, [])
        lo = _months_before(peak, RUNUP_MONTHS)
        f_fix, n = _fire_rate(rows, lo, peak, "explosive")
        f_cal, _ = _fire_rate(rows, lo, peak, "explosive_cal95")
        out["bubbles"].append({
            "label": label, "window": f"{lo}..{peak}", "n_windows": n,
            "fixed_rate": (f_fix / n if n else 0.0),
            "calib_rate": (f_cal / n if n else 0.0),
        })
    for label, table, lo, hi in CALM:
        rows = rows_by_table.get(table, [])
        f_fix, n = _fire_rate(rows, lo, hi, "explosive")
        f_cal, _ = _fire_rate(rows, lo, hi, "explosive_cal95")
        out["calm"].append({
            "label": label, "window": f"{lo}..{hi}", "n_windows": n,
            "fixed_rate": (f_fix / n if n else 0.0),
            "calib_rate": (f_cal / n if n else 0.0),
        })
    return out


def report(m: dict, crit95: float) -> None:
    print(f"\nGSADF calibrado (crit95={crit95:.3f}) vs fixo (1.49)\n")
    print(f"{'regime':<14} {'janelas':>7} {'fixo %':>8} {'calib %':>8}")
    print("-" * 42)
    print("BOLHAS (subida — MAIOR é melhor):")
    for b in m["bubbles"]:
        print(f"  {b['label']:<12} {b['n_windows']:>7} "
              f"{100*b['fixed_rate']:>7.0f}% {100*b['calib_rate']:>7.0f}%")
    print("CALMOS (MENOR é melhor):")
    for c in m["calm"]:
        print(f"  {c['label']:<12} {c['n_windows']:>7} "
              f"{100*c['fixed_rate']:>7.0f}% {100*c['calib_rate']:>7.0f}%")
    # Discriminação = média(bolha) - média(calmo), por limiar.
    for key, name in (("fixed_rate", "fixo"), ("calib_rate", "calibrado")):
        mb = np.mean([b[key] for b in m["bubbles"]])
        mc = np.mean([c[key] for c in m["calm"]])
        print(f"\n  {name:<10}: bolha_media={100*mb:.0f}%  calmo_media={100*mc:.0f}%"
              f"  gap={100*(mb-mc):+.0f}pp")
    print("\nVEREDICTO: o calibrado discrimina melhor sse gap(calibrado) > "
          "gap(fixo) E bolhas acendem materialmente. Senao, Peça 1 fraca.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None, help="critical values JSON")
    ap.add_argument("--start", type=int, default=1990,
                    help="ano inicial p/ S&P (BTC comeca 2014 de qq forma)")
    ap.add_argument("--step", type=int, default=21)
    args = ap.parse_args()

    table = load_critical_values(args.json) if args.json else load_critical_values()
    from gsadf_calibrated import interp_crit
    from quant_detectors import WINDOW_DAYS
    crit95 = interp_crit(WINDOW_DAYS, table, "p95")

    rows_by_table = {}
    for tbl in _TABLES:
        start = args.start if tbl == "research_gspc" else 2014
        dates, closes = load_series(tbl, start)
        print(f"{tbl}: {len(closes)} barras {dates[0]}..{dates[-1]}", flush=True)
        rows_by_table[tbl] = walk_forward_calibrated(
            dates, closes, table, step=args.step)
    m = measure_by_regime(rows_by_table)
    report(m, crit95)
    return 0


if __name__ == "__main__":
    sys.exit(main())
