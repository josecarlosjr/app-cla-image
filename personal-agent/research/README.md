# Onda 13 Sprint 1 — Gate walk-forward do LPPL

Estudo cego e empírico: **o `quant_detectors.fit_lppl` (as-is) discrimina
bolhas históricas de tendências normais?** Um "não discrimina" é resposta
válida, não falha.

**Regra de integridade:** zero afinação. Todo o código aqui importa
`fit_lppl` tal como está no `quant_detectors.py`. Só mede. Não toca
`bubble_scoring.py`, `bubble_orchestrator.py` nem os alertas.

## Ficheiros

| Ficheiro | Fase | Corre onde |
|---|---|---|
| `ingest_gspc.py` | 1 — ingestão ^GSPC max → quant_bars | **in-pod** (Yahoo bloqueado no sandbox) |
| `lppl_walkforward.py` | 2 — harness walk-forward (núcleo puro + shell DB) | local (sintético) OU in-pod (^GSPC real) |
| `measure_discrimination.py` | 3 — matriz crashes vs. calmos | local, sobre o CSV do harness |
| `lppl_characterization.py` | evidência — fit_lppl em séries controladas | local |

## Achados sintéticos (corridos localmente, reprodutíveis)

`fit_lppl` sobre 5 famílias × 120 seeds, `bubble_prob = R²` penalizado:

| família | mean prob | %>0.7 |
|---|---|---|
| gbm_flat (ruído) | 0.52 | 37% |
| gbm_drift (bull normal) | 0.68 | 63% |
| exp_trend (não-bolha) | **0.99** | **100%** |
| linear (não-bolha) | **0.97** | **100%** |
| LPPL (controlo +) | 0.91 | 100% |

Walk-forward sobre série de 56 anos **sem nenhuma bolha**: **43% das
janelas mensais** disparam `prob>0.7` (falsos positivos).

**Conclusão sintética:** tendências exponenciais/lineares pontuam MAIS que
uma bolha LPPL real. `bubble_prob=R²` mede ajuste-a-tendência, não
assinatura de bolha. O estimador não discrimina isolado.

## Gate histórico real (por correr in-pod)

```bash
# Fase 1
kubectl -n personal-agent exec -it deploy/personal-agent-api -- \
  sh -c 'cd /app/personal-agent && python research/ingest_gspc.py'
kubectl exec -n personal-agent postgres-0 -- psql -U postgres -d agent \
  -c "SELECT ticker,min(ts),max(ts),count(*) FROM quant_bars WHERE ticker='^GSPC' GROUP BY ticker;"

# Fase 2
kubectl -n personal-agent exec -it deploy/personal-agent-api -- \
  sh -c 'cd /app/personal-agent && python research/lppl_walkforward.py --ticker "^GSPC" --step 21 --out /tmp/gspc_wf.csv'

# Fase 3 (partilhar /tmp/gspc_wf.csv de volta OU correr localmente)
python research/measure_discrimination.py --csv /tmp/gspc_wf.csv --threshold 0.7
```

O sintético prevê alta taxa de falsos positivos no real; o gate histórico
acrescenta o que o sintético não mede: os 4 crashes reais são precedidos
de prob a subir (true positives) e com que lead time.
