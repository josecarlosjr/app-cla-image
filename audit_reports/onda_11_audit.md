# Auditoria Onda 11 — Backtesting · System Snapshots · Outcome Labelling · Quality Metrics

**Data:** 2026-05-26
**Executor:** Claude Code (commit `9254d81`)
**Versão do sistema auditado:** `app-cla-image` @ branch `claude/fix-graph-entities-table-e2gqJ` (`9254d81`)
**Referência:** `audit_reports/PIA_Wave_Audit_Plan.md` § Onda 11
**Modo de execução:** código auditado localmente; o teste de leakage foi **executado** (PASS). As métricas foram **recolhidas contra produção** em 2026-05-26 (`onda_11_metrics.py` sobre cópia atómica do `agent.db`, 15 MB) — secções 3/4/6 preenchidas com dados reais.

---

## 1. Resumo Executivo (3 frases)

- **O que funciona:** o replay é **leakage-safe por construção** — as três leituras de janela filtram por *timestamp de armazenamento* (`fetched_at`, `timestamp`, `detected_at`), e o **teste de leakage crítico passa** (executado, não assumido); os snapshots cobrem os 4 componentes e a falha de cada um é isolada (P5).
- **O que falha / preocupa:** os dados reais confirmam o pior cenário — **0 outcomes rotulados** (ratio 0:305 patterns) porque **não há UI para marcar outcomes** (só API), logo **todas as métricas de precisão downstream são estatisticamente vácuas** (o maior risco do sistema); os snapshots têm só **21d de span / 7 captures por tipo** (sem cron); e o "backtest" é um *replay de artefactos armazenados*, não uma re-simulação do detector.
- **Próxima ação:** a infra é sólida e leakage-safe (determinismo confirmado em 15 113 artigos reais), mas está a ser **alimentada a vazio**. Aprovação condicionada a 3 bloqueadores: **cron de snapshots**, **UI de outcomes + backfill ≥100**, e **re-auditoria** depois disso (secção 9).

---

## 2. Checklist de Código

| # | Item | Status | Evidência |
|---|---|---|---|
| 1 | `system_snapshots` cobre todos os componentes (trends, cross_pillar, supply_chain, graph) | ✅ PASS | `backtest.py:33` `SNAPSHOT_TYPES`; captura dos 4 em `backtest.py:40-83` |
| 2 | Replay **estritamente** sem leakage do futuro | ✅ PASS (testado) | `get_articles_in_window` filtra `fetched_at` (`database.py:1404`), `get_patterns_in_window` filtra `timestamp` (`database.py:1421`), `get_chains_in_window` filtra `detected_at` (`database.py:1432`). Teste de unidade **executado, PASS** (`audit_scripts/onda_11_leakage_test.py`) |
| 3 | `event_outcomes` tem `UNIQUE(event_type, event_id)` | ✅ PASS | schema `event_outcomes … UNIQUE (event_type, event_id)`; `upsert_outcome` faz update-or-insert respeitando-o (`database.py:1246-1273`) |
| 4 | Há UI para marcar outcomes facilmente, ou só via API? | ❌ FAIL | Só API: `POST /api/outcomes/{type}/{id}` (`api.py:594`). `Backtesting.tsx` **mostra** precisão (TP/FP, linhas 231-232) mas **não tem controlo para marcar** — linha 242 é só um aviso. Sem atalhos de teclado. |

### Princípios transversais (P1–P6)

| P | Princípio | Status | Evidência / nota |
|---|---|---|---|
| P1 | Determinismo | ✅ / ⚠️ | `replay_window` é puro (sem LLM, sem random) → determinístico com bounds fixos. **Mas** `run_backtest(days_back=N)` desliza a janela com `now` e embute `get_quality_metrics` relativo a `now` (`backtest.py:182-196`) → não reprodutível no tempo. Para o teste de determinismo usar `replay_window` com ISO fixo. |
| P2 | Idempotência | ✅ / ⚠️ | `articles.url` PK e `event_outcomes` UNIQUE+upsert → idempotentes. **Mas** `capture_snapshots` documenta-se "Idempotent" (`backtest.py:41`) enquanto `insert_snapshot` faz **append** de uma nova linha a cada chamada (`database.py:1174`) → chamar 2× no mesmo instante duplica. Para série temporal é aceitável, mas a afirmação está errada. |
| P3 | Observabilidade | ❌ FAIL | Apenas `logger.info`/`warning` em texto (`backtest.py:82`). Sem log estruturado JSON com `wave_id`/`duration_ms`/`input_count`/`output_count`, sem contadores por execução. |
| P4 | Custo medido | N/A | Onda 11 (replay/snapshots/outcomes) não chama LLM. (O custo de `detect_chains`/`analyze` invocados em `capture_snapshots` pertence às Ondas 6/9.) |
| P5 | Falha controlada | ✅ PASS | `capture_snapshots` isola cada tipo em try/except (`backtest.py:44-80`); endpoints em try/except→500 (`api.py:553,576`); `sqlite-vec` ausente → fallback brute-force **observado** ao correr os scripts. |
| P6 | Migração de schema | ⚠️ | Migrações aditivas hand-rolled (`_ensure_late_added_tables` `database.py:254`, `_migrate_embeddings_schema` `database.py:286`), sem Alembic e **sem rollback**. O plano P6 pede rollback testado. |

---

## 3. Resultados dos Testes SQL

Queries embutidas em `audit_scripts/onda_11_metrics.py` (sabor **SQLite** — Onda 11 vive toda no `agent.db`). Validadas contra o schema (sem erros); **valores pendentes** de correr contra produção.

| Teste | O que mede | Resultado (produção, 2026-05-26) |
|---|---|---|
| T11.1 | volume de outcomes por `(event_type, outcome)`; gate ≥30 TP+FP | ❌ **0 outcomes** (total). Gate falha por completo. |
| T11.2 | determinismo: `replay_window` 2× → idêntico | ✅ **PASS em dados reais** — idêntico; 30 ticks, 15 113 artigos, 305 patterns, 18 chains |
| T11.3 | completude de snapshots: 4 tipos, `span_days` | ⚠️ 4/4 tipos presentes, mas **span 21,0d** (7 captures/tipo) — alvo ≥90d ❌ |
| T11.4 | precisão por `event_type` (SQL vs função) | ❌ **N/A** — 0 outcomes ⇒ `{}` em ambos (match trivial) |

> Nota T11.4: `get_quality_metrics` filtra por `marked_at` (quando foi **rotulado**), não por `event_timestamp` (quando o evento **ocorreu**) — `database.py:1313`. A precisão reportada é sobre rótulos recentes, não eventos recentes.

---

## 4. Métricas Mensuradas

| Métrica | Valor actual (produção) | Target | Status |
|---|---|---|---|
| **Leakage test** | **PASS** | PASS | ✅ executado |
| Determinismo do replay | idêntico (30 ticks, 15 113 artigos) | idêntico em re-runs | ✅ PASS (dados reais) |
| Outcomes labelled total | **0** | >300 (mín. estatístico) | ❌ FAIL |
| Outcomes por `event_type` | **0** | ≥30 | ❌ FAIL |
| Snapshot coverage (span_days) | **21,0d** (4 tipos, 7 captures/tipo) | ≥90 dias | ❌ FAIL |
| Precisão por `event_type` | N/A (0 outcomes) | report (mede, não target) | ❌ sem dados |
| Duplicados (artigos / outcomes) | 0 / 0 | 0 | ✅ PASS |
| Patterns / chains observados (30d) | 305 / 18 | — | ℹ️ contexto |

---

## 5. Backtests Históricos

**N/A para a Onda 11.** O backtest contra bolhas históricas (dotcom/GFC/cripto) pertence à **Onda 12** (Test 12.1) e converge com o backtest da Onda 13 (motor de scoring). Esta onda valida a *infra* de replay/snapshots/outcomes, não previsões financeiras.

---

## 6. Critérios de Aceitação

- [x] **Leakage test passa** (binário) — ✅ **EXECUTADO, PASS**.
- [x] Backtest determinístico em re-runs — ✅ **PASS em dados reais** (15 113 artigos, idêntico; usar bounds ISO fixos, não `run_backtest(days_back)`).
- [ ] ≥30 outcomes por `event_type` principal — ❌ **FAIL: 0 outcomes** no total.
- [ ] Snapshots cobrindo ≥90 dias — ❌ **FAIL: 21,0d** (sem cron; 7 captures/tipo).

---

## 7. Red Flags Identificadas

1. **Sem UI de marcação de outcomes** (`Backtesting.tsx` só mostra, não marca) → fricção alta → provável **<30 outcomes** → métricas de precisão de TODAS as ondas downstream ficam estatisticamente vazias. *Este é o maior risco da onda* (o plano avisa explicitamente).
2. **Replay ≠ re-simulação.** `replay_window` relê artefactos já armazenados filtrados por timestamp; não re-executa o detector. A docstring (`backtest.py:9-12`) diz "simulates what the pattern detector would have seen" — overclaim. Mede "artefactos ao longo do tempo".
3. **`capture_snapshots` não é idempotente** apesar da docstring (`backtest.py:41`) — `insert_snapshot` faz append (`database.py:1174`).
4. **`run_backtest` não-determinístico no tempo** — janela desliza com `now` + quality metrics relativos a `now`.
5. **Precisão por `marked_at`, não `event_timestamp`** — pode enviesar a janela de qualidade.
6. **Observabilidade fraca (P3)** — logs em texto, sem `wave_id`/`duration_ms`/contadores estruturados.
7. **Bug no script `--db`** — `onda_11_metrics.py` usa só `dirname(--db)` e ignora o filename → aponta sempre para `<dir>/agent.db`. Workaround usado nesta recolha: renomear o snapshot para `agent.db` + `DATA_DIR=/tmp`. Fix proposto: tornar `database.DB_PATH` configurável via env `DB_PATH`.
8. **Sem cron para `capture_snapshots`** — os snapshots dependem de chamada manual à API. Span real de **21d com apenas 7 captures/tipo** (deveria ser ~84 com cron de 6h). Evidência: T11.3.
9. **Ratio outcomes:patterns = 0:305 (últimos 30 dias)** — zero ground truth. Sem isto, **nenhuma quality metric downstream é estatisticamente válida**. Confirmação data-driven do red flag #1 — é o bloqueador central da onda.

---

## 8. Optimizações Sugeridas (priorizadas — uma por PR)

1. **[ALTA]** **UI de marcação de outcomes** com atalhos (T=TP, F=FP, U=unclear) em `Backtesting.tsx`. Ataca o ratio 0:305 (red flags #1/#9) — sem isto, nada a jusante tem ground truth.
2. **[ALTA]** **CronJob `snapshots-capture`** (`schedule: 0 */6 * * *`) a chamar `POST /api/snapshots/capture`. Sem cron o span nunca chega a 90d (red flag #8).
3. **[ALTA]** **Endpoint `GET /api/events/unlabelled?type=&limit=`** — devolve eventos sem outcome marcado, ordenados por `timestamp desc`, para alimentar a UI de backfill.
4. **[ALTA · esforço baixo]** `get_quality_metrics`: reportar `n` + IC de Wilson (`0.72 ± 0.08`) e opção de filtrar por `event_timestamp`. Honestidade estatística (red flag #5).
5. **[MÉDIA · esforço baixo]** **Fix do bug `--db`** em `onda_11_metrics.py` (tornar `DB_PATH` configurável via env). (red flag #7)
6. **[MÉDIA · esforço baixo]** Corrigir docstring de `capture_snapshots` (append, não idempotente) **ou** dedup por `(snapshot_type, bucket)`. (red flag #3)
7. **[MÉDIA · esforço baixo]** `run_backtest`: janela ISO fixa para reprodutibilidade; separar quality relativo-a-`now`. (red flag #4)
8. **[MÉDIA · esforço médio]** Observabilidade P3: log estruturado (`wave_id`, `duration_ms`, `input/output_count`) + tabela de execuções. (red flag #6)
9. **[BAIXA · esforço alto]** Documentar/renomear o replay como "stored-artifact replay", ou oferecer re-computação real do detector. (red flag #2)

---

## 9. Decisão

- [ ] Onda APROVADA — manter em produção
- [x] **Onda APROVADA COM CONDIÇÕES** (3 condições bloqueantes abaixo)
- [ ] Onda REPROVADA — desactivar até refactor

**Condições bloqueantes** (todas obrigatórias antes de aprovar):
1. **Cron de snapshots em produção** (`0 */6 * * *` → `POST /api/snapshots/capture`) — para o span atingir ≥90d.
2. **UI de outcomes funcional + backfill de ≥100 outcomes** — sai do ratio 0:305 e dá ground truth mínimo.
3. **Re-run da auditoria** depois de 1 e 2, para confirmar os critérios T11.1/T11.3/T11.4 com dados.

**Justificação:** a infra é tecnicamente sólida e leakage-safe (teste crítico PASS, determinismo confirmado em 15 113 artigos reais). Mas a Onda 11 é *a fonte de ground truth* de todas as ondas, e os dados reais mostram-na a ser **alimentada a vazio**: 0 outcomes, 21d de snapshots sem cron. Sem as 3 condições acima, as métricas de qualidade do sistema inteiro são estatisticamente vácuas.

---

## 10. Anexos

- `audit_scripts/onda_11_leakage_test.py` — teste de leakage (executável, **PASS**).
- `audit_scripts/onda_11_metrics.py` — recolha de métricas (re-executável; correr contra produção).
- **Como correr** (in-cluster, `DATA_DIR=/data` por omissão):
  ```bash
  python audit_scripts/onda_11_metrics.py
  # ou apontar para uma cópia:
  python audit_scripts/onda_11_metrics.py --db /caminho/agent.db
  ```
  Colar de volta o bloco JSON final para eu preencher as secções ⏳ e fechar a decisão.
