"""Monte Carlo dos valores críticos do GSADF — Onda 13 Peça 1 (research).

Sob a hipótese nula (random walk sem bolha = raiz unitária), simula a
distribuição do ``bsadf_latest`` que o walk-forward usa como estatística
de deteção em tempo real. O valor crítico = percentil 95/99 dessa
distribuição nula, POR tamanho de janela n.

REGRA DE INTEGRIDADE: o limiar sai da distribuição nula simulada, NÃO de
escolher o valor que faz as bolhas conhecidas acender. Importa
``quant_detectors.gsadf`` as-is.

Estatística calibrada: ``bsadf_latest`` (BSADF no ponto mais recente) —
é EXATAMENTE o que gsadf_walkforward compara com o limiar. (A crítica de
sup-GSADF de PSY é para "houve bolha algalgures na janela"; aqui queremos
"há bolha AGORA", que é o bsadf_latest.)

CUSTO: gsadf é ~O(n^2.4). Medido no sandbox: n=100 0.18s, n=250 1.9s,
n=500 8.9s por sim. n>=1000 é impraticável com esta implementação
(n=2000 ~248s/sim → dias). Uma GSADF vetorizada seria precisa para n
grande — proposta separada, fora desta fase.

Reprodutível: cada sim usa seed derivado (SEED, n, sim). JSON guarda
SEED, N_SIM, estatística e o limiar fixo antigo (1.49) para comparação.

Uso:
    python research/gsadf_montecarlo.py --sizes 100 250 500 --nsim 500 \\
        --out research/gsadf_critical_values.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from quant_detectors import gsadf  # noqa: E402  (as-is)

OLD_FIXED = 1.49  # limiar fixo antigo (PSY tabela), para comparação


def null_bsadf(n: int, seed_key: tuple) -> float:
    """1 sim: random walk (H0), devolve bsadf_latest. A estatística ADF é
    invariante à escala, portanto sigma é irrelevante — RW de variância
    unitária."""
    rng = np.random.default_rng(seed_key)
    rw = np.cumsum(rng.standard_normal(n))
    return float(gsadf(rw).get("bsadf_latest", 0.0))


def run(sizes: list[int], n_sim: int, seed: int, out_path: str) -> None:
    meta = {
        "statistic": "bsadf_latest",
        "null_hypothesis": "random walk (unit root, no bubble)",
        "n_sim": n_sim,
        "seed": seed,
        "old_fixed_threshold": OLD_FIXED,
        "gsadf_source": "quant_detectors.gsadf (as-is, r0=30)",
        "note": "crit = percentil da distribuicao nula de bsadf_latest por n",
    }
    crit = {}
    t_start = time.time()
    for si, n in enumerate(sizes):
        t0 = time.time()
        samples = np.empty(n_sim)
        for k in range(n_sim):
            samples[k] = null_bsadf(n, (seed, n, k))
        p95 = float(np.percentile(samples, 95))
        p99 = float(np.percentile(samples, 99))
        crit[str(n)] = {
            "p95": round(p95, 4),
            "p99": round(p99, 4),
            "mean": round(float(samples.mean()), 4),
            "median": round(float(np.median(samples)), 4),
        }
        dt = time.time() - t0
        print(f"n={n:5d}: p95={p95:.3f} p99={p99:.3f} "
              f"(mean={samples.mean():.3f}) [{dt:.0f}s, {dt/n_sim:.3f}s/sim]",
              flush=True)
    meta["total_seconds"] = round(time.time() - t_start, 1)
    payload = {"meta": meta, "critical_values": crit}
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\nJSON -> {out_path}  (total {meta['total_seconds']:.0f}s)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[100, 250, 500])
    ap.add_argument("--nsim", type=int, default=500)
    ap.add_argument("--seed", type=int, default=12345)
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "gsadf_critical_values.json"))
    args = ap.parse_args()
    run(args.sizes, args.nsim, args.seed, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
