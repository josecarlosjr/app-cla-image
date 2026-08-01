"""Fase 1 — ingestão de ^GSPC (S&P 500 índice) com história máxima.

Puxa ^GSPC period="max" (yfinance: 1927->) para quant_bars, ticker
interno "^GSPC" — NÃO colide com "SPY" (o ETF, série diferente, só
desde 1993). Reutiliza pg_database.upsert_bars.

Seguro para produção: quant_detectors.WATCHLIST é separado (SPY, QQQ,
...), portanto ^GSPC entra em quant_bars mas NÃO é fitado pelos
detectores da cron 15. É dado para o estudo walk-forward, não um novo
alvo de produção.

Correr in-pod (o sandbox bloqueia Yahoo):
    kubectl -n personal-agent exec -it deploy/personal-agent-api -- \\
        sh -c 'cd /app/personal-agent && python research/ingest_gspc.py'

Depois confirmar (CHECKPOINT da Fase 1):
    kubectl exec -n personal-agent postgres-0 -- psql -U postgres -d agent \\
      -c "SELECT ticker, min(ts), max(ts), count(*) FROM quant_bars \\
          WHERE ticker='^GSPC' GROUP BY ticker;"
"""
from __future__ import annotations

import os
import sys

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

TICKER = "^GSPC"


def main() -> int:
    import pandas as pd
    import yfinance as yf
    from pg_database import upsert_bars

    print(f"Fetching {TICKER} period=max from yfinance...")
    df = yf.download(TICKER, period="max", auto_adjust=False,
                     progress=False, threads=False)
    if df is None or df.empty:
        print("ERRO: yfinance devolveu vazio para ^GSPC")
        return 1
    if isinstance(df.columns, pd.MultiIndex):
        df.columns = df.columns.get_level_values(0)

    rows: list[tuple] = []
    for idx, r in df.iterrows():
        ts = idx.to_pydatetime()
        if ts.tzinfo is None:
            from datetime import timezone
            ts = ts.replace(tzinfo=timezone.utc)
        close = r.get("Close")
        if pd.isna(close):
            continue
        rows.append((
            TICKER, ts.isoformat(),
            float(r["Open"]) if pd.notna(r.get("Open")) else None,
            float(r["High"]) if pd.notna(r.get("High")) else None,
            float(r["Low"]) if pd.notna(r.get("Low")) else None,
            float(close),
            int(r["Volume"]) if pd.notna(r.get("Volume")) else None,
        ))

    n = upsert_bars(rows)
    print(f"{TICKER}: upserted {n} bars "
          f"[{df.index.min().date()}..{df.index.max().date()}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
