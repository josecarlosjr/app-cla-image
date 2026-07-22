"""One-shot BIS credit-to-GDP backfill (Onda 12 Sprint C1, Camada B).

Idempotent full-history fetch dos 28 indicadores em
``bis_fetcher.SUPPORTED_INDICATORS``. Manual invocation, não escalonado
— o CronJob (Fase 2e) usa ``jobs/bis_fetcher.py`` com o schedule
semanal.

Design invariants
-----------------
- **Zero import de ``macro_backfill``.** As duas backfills (macro-FRED
  e BIS) coabitam sem se conhecer, mesmo princípio das camadas
  independentes que ratificaste na Fase 1B. Helpers de report duplicados
  a propósito.
- Itera ``bis_fetcher.SUPPORTED_INDICATORS`` (não ``mr.INDICATORS``).
  Contrato estabelecido em Fase 2a; se algum dia se adicionar um
  indicador BIS ao catálogo mas não ao fetcher, este script fica
  automaticamente coerente com o que ``run()`` realmente processa.
- Delega o fetch a ``bis_fetcher.run()``. Backfill orquestra +
  reporta; toda a lógica de rede / parse / upsert vive no fetcher.
- Idempotente por semântica do ``on_conflict='update_on_change'``
  (definido no catálogo em Fase 2a). Correr 2× no mesmo publication
  cycle da BIS → 0 inserts + 0 updates.

Invocação
---------
Dentro do cluster::

    kubectl -n personal-agent exec -it deploy/personal-agent-api -- \\
        sh -c 'cd /app/personal-agent && python jobs/bis_backfill.py'

Localmente contra copy da DB::

    DB_PATH=/path/to/agent.db python jobs/bis_backfill.py

Override do start period (default ``"1980"``)::

    python jobs/bis_backfill.py --start-period 2000

Guardrails
----------
1. Pre-flight imprime a contagem existente por indicador + first/last ts.
   Se qualquer indicador já tem rows, dorme ``WARM_UP_S`` segundos antes
   de arrancar — janela para ``Ctrl+C`` se o operador está a apontar para
   a DB errada.
2. Idempotência: ``update_on_change`` no catálogo garante que uma re-run
   dentro do mesmo publication cycle não gera writes. Uma re-run após a
   BIS publicar um novo trimestre gera N updates (esperado, não bug).
3. Exit code: ``0`` se todos os 28 ok, ``1`` se algum falhou. O CronJob
   usa ``backoffLimit=1``; o backfill é manual e o operador re-corre
   após ver o report.

Reports
-------
Ao fim, o script imprime um report humanamente-legível no stdout
(útil para o operador que corre ``kubectl exec``) e emite um único
``log_event("bis_backfill_summary")`` estruturado com per-indicator
breakdown.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from datetime import datetime, timezone

# Bootstrap sibling imports (mesmo padrão de macro_backfill/macro_fetcher —
# funciona sob ``python jobs/bis_backfill.py`` e ``python -m jobs.bis_backfill``).
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_SELF_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import macro_repository as mr                         # noqa: E402
from log_config import setup_logging, log_event       # noqa: E402
from jobs import bis_fetcher                          # noqa: E402

setup_logging()

WARM_UP_S = 3   # operator-abort window before the fetch starts


def _preflight(stream=None) -> dict[str, int]:
    """Print per-indicator baseline (row count + first/last ts if any).

    Devolve ``{indicator: row_count}`` para o caller poder logar / decidir.
    Se qualquer indicador já tem rows, imprime aviso de idempotência e
    dorme ``WARM_UP_S`` segundos (Ctrl+C aborta com exit 130 = SIGINT).
    """
    if stream is None:
        stream = sys.stdout
    counts: dict[str, int] = {}
    ranges: dict[str, dict | None] = {}
    for ind in bis_fetcher.SUPPORTED_INDICATORS:
        rng = mr.get_ts_range(ind)
        counts[ind] = rng["count"] if rng else 0
        ranges[ind] = rng

    total_existing = sum(counts.values())
    print(
        f"BIS backfill preflight — {len(bis_fetcher.SUPPORTED_INDICATORS)} "
        f"indicators, {total_existing} existing rows",
        file=stream, flush=True,
    )
    for ind in bis_fetcher.SUPPORTED_INDICATORS:
        n = counts[ind]
        rng = ranges[ind]
        if rng and n > 0:
            print(
                f"  {ind:24}: {n:5} rows  "
                f"first_ts={rng['first_ts']}  last_ts={rng['last_ts']}",
                file=stream, flush=True,
            )
        else:
            print(f"  {ind:24}: {n:5} rows", file=stream, flush=True)

    if total_existing > 0:
        print(
            f"\nIdempotent (update_on_change semantica). "
            f"Proceeding in {WARM_UP_S}s (Ctrl+C to abort).",
            file=stream, flush=True,
        )
    try:
        time.sleep(WARM_UP_S)
    except KeyboardInterrupt:
        print("\nAborted before fetch started.", file=stream, flush=True)
        sys.exit(130)   # 128 + SIGINT
    return counts


def _format_report(summary: dict) -> str:
    """Human-readable report para stdout do operador. Espelha o formato
    do report homónimo em ``macro_backfill`` mas construído aqui — as
    duas camadas ficam independentes por design."""
    n_total = summary["n_ok"] + summary["n_error"]
    lines = [
        "BIS backfill summary:",
        f"  Indicators: {n_total}  "
        f"({summary['n_ok']} ok, {summary['n_error']} error)",
        f"  Rows inserted: {summary['total_inserted']}",
        f"  Rows updated:  {summary['total_updated']}",
        f"  Duration: {summary['duration_ms']}ms",
        "",
        "Per indicator:",
    ]
    for r in summary["results"]:
        if r["error"]:
            lines.append(f"  {r['indicator']:24}: FAILED — {r['error']}")
        else:
            lines.append(
                f"  {r['indicator']:24}: {r['n_obs']:5} obs, "
                f"{r['n_inserted']:4} ins, {r['n_updated']:4} upd"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None, stream=None) -> int:
    """Backfill entry point. Returns 0 if all ok, 1 if any failed."""
    parser = argparse.ArgumentParser(
        description="BIS credit-to-GDP backfill (macro_repository)",
    )
    parser.add_argument(
        "--start-period", type=str, default=None,
        help=(
            f"Override START_PERIOD (default: {bis_fetcher.START_PERIOD}). "
            "Format: 'YYYY' or 'YYYY-Qn'."
        ),
    )
    args = parser.parse_args(argv)

    if stream is None:
        stream = sys.stdout

    start_period = args.start_period or bis_fetcher.START_PERIOD

    log_event(
        "bis_backfill_start",
        n_indicators=len(bis_fetcher.SUPPORTED_INDICATORS),
        start_period=start_period,
    )

    _preflight(stream=stream)

    t0 = datetime.now(timezone.utc)
    ok, err, results = asyncio.run(
        bis_fetcher.run(start_period=args.start_period)
    )
    t1 = datetime.now(timezone.utc)

    total_inserted = sum(r["n_inserted"] for r in results)
    total_updated = sum(r["n_updated"] for r in results)
    duration_ms = int((t1 - t0).total_seconds() * 1000)

    summary = {
        "n_ok": ok,
        "n_error": err,
        "total_inserted": total_inserted,
        "total_updated": total_updated,
        "duration_ms": duration_ms,
        "results": results,
    }

    report = _format_report(summary)
    print("", file=stream)
    print(report, file=stream, flush=True)

    log_event(
        "bis_backfill_summary",
        n_ok=ok,
        n_error=err,
        total_inserted=total_inserted,
        total_updated=total_updated,
        duration_ms=duration_ms,
        by_indicator={
            r["indicator"]: {
                "ok": r["ok"],
                "n_obs": r["n_obs"],
                "n_inserted": r["n_inserted"],
                "n_updated": r["n_updated"],
                "error": r["error"],
            }
            for r in results
        },
    )

    return 0 if err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
