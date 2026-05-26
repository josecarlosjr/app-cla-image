# PIA — Plano de Verificação e Optimização das Ondas 1 → 12

**Documento de auditoria executável.** Entrega-se este documento ao Claude Code com a instrução: *"Executa este plano contra o repositório do PIA. Para cada onda, produz um relatório seguindo o template no Apêndice C, com evidências (paths de ficheiros, números reais, queries SQL executadas)."*

**Objectivo:** transformar 11 ondas "shipped" em 12 ondas **validadas, medidas e confiáveis** — antes de qualquer alocação de capital real baseada em outputs do sistema.

**Princípio-guia:** *"Tu não consegues melhorar o que não consegues medir; e não deves confiar no que não foi adversarialmente testado."*

---

## Como usar este documento

1. **Sessão por onda.** Cada onda é uma sessão independente do Claude Code. Não tentar fazer tudo numa thread — cada relatório precisa de espaço próprio.
2. **Ordem recomendada:** começar pela **Onda 11** (backtesting). Sem ela validada, todas as outras auditorias ficam sem ground truth para comparar.
3. **Para cada onda, o Claude Code deve produzir:**
   - Um ficheiro `audit_reports/onda_N_audit.md` com o template do Apêndice C preenchido
   - Um script `audit_scripts/onda_N_metrics.py` que recolhe as métricas automaticamente (re-executável)
   - Pull request com as optimizações sugeridas, **uma optimização por PR** (nunca PR gigante)
4. **Regra de ouro:** se uma verificação não pode ser medida com um número, **a verificação está mal definida**. Refinar até virar número.

---

## Princípios Gerais (aplicam-se a TODAS as ondas)

Antes de auditar onda específica, o Claude Code deve verificar estes pontos transversais:

### P1. Determinismo
- Dado o mesmo input, a mesma onda produz o mesmo output? Se há randomness (LLM temperature, sampling), está controlado com seed?
- Teste: re-executar a mesma análise 3 vezes consecutivas. Variância >5% nos outputs = problema.

### P2. Idempotência
- Reprocessar o mesmo artigo duas vezes resulta em estado consistente? Ou cria duplicados?
- Teste: SQL `SELECT COUNT(*), url FROM articles GROUP BY url HAVING COUNT(*) > 1`. Deve retornar zero.

### P3. Observabilidade
- A onda tem logs estruturados (JSON) com `wave_id`, `duration_ms`, `input_count`, `output_count`?
- Há métricas Prometheus/StatsD expostas, ou pelo menos contadores em tabela?
- Teste: grep nos logs por "wave_N" — deve haver registo de cada execução.

### P4. Custo medido
- Cada chamada LLM tem o custo registado (tokens × preço)?
- Há uma tabela `llm_costs` ou similar para auditoria mensal?
- Teste: confrontar a estimativa de $10/mês com factura real da Anthropic do último mês. Divergência >20% = problema.

### P5. Falha controlada
- O que acontece quando um upstream falha (RSS down, Anthropic API down, sqlite-vec corrupto)?
- Há circuit breakers? Retry com backoff exponencial? Dead letter queue?
- Teste: bloquear `api.anthropic.com` via /etc/hosts e ver se o sistema degrada graciosamente ou crasha.

### P6. Schema migration safety
- Há migrações Alembic ou equivalente? Rollback testado?
- Teste: criar branch de teste, aplicar migration, fazer rollback, verificar dados intactos.

---

## ONDA 1-3 — RSS Ingestion · Pattern Matching · Digest

### 🎯 Objectivo da auditoria
Garantir que a base do sistema (entrada de dados) está **completa, deduplicada e fresca**. Sem isto, todas as ondas superiores constroem em areia movediça.

### 📋 Checklist de auditoria de código

- [ ] `feeds.py` — circuit breaker está configurado para todos os 70 feeds? Threshold de falhas?
- [ ] `feeds.py` — rotating logs estão a rodar (não a encher disco)? Verificar política de retenção.
- [ ] Cache de 8000 entries — qual a política de eviction? LRU? TTL? Verificar `feeds.py` ou config equivalente.
- [ ] `enrichment.py` — URL canonicalisation está a remover `utm_*`, `fbclid`, `gclid`, `mc_*`, `ref=` e fragments?
- [ ] `pattern_matcher.py` — `MIN_SOURCES_FOR_STRONG = 3` está realmente aplicado em todos os paths?
- [ ] `digest.py` — geração de manhã (9h) e noite (21h) tem timezone explícito (UTC vs Europe/Lisbon)?

### 🧪 Testes a executar

```sql
-- T1.1: Health check dos feeds (últimos 7 dias)
SELECT 
  source_domain,
  COUNT(*) as articles_count,
  MAX(fetched_at) as last_fetch,
  julianday('now') - julianday(MAX(fetched_at)) as days_since_last
FROM articles
WHERE fetched_at > datetime('now', '-7 days')
GROUP BY source_domain
ORDER BY days_since_last DESC;
-- ALERTA: qualquer feed com days_since_last > 2 está provavelmente quebrado

-- T1.2: Detectar duplicação por URL canonical
SELECT COUNT(*) total, COUNT(DISTINCT url) unique_urls,
       (COUNT(*) - COUNT(DISTINCT url)) as duplicates
FROM articles;
-- ALERTA: duplicates > 0 = canonicalisation com bug

-- T1.3: Distribuição de relevance_score
SELECT 
  CASE 
    WHEN relevance_score < 20 THEN '0-20'
    WHEN relevance_score < 40 THEN '20-40'
    WHEN relevance_score < 60 THEN '40-60'
    WHEN relevance_score < 80 THEN '60-80'
    ELSE '80-100'
  END as bucket,
  COUNT(*) as n
FROM articles
WHERE fetched_at > datetime('now', '-30 days')
GROUP BY bucket;
-- INSIGHT: se >70% dos artigos estão em <40, o threshold de relevância está alto demais

-- T1.4: Eficiência do pattern matcher
SELECT 
  confidence,
  COUNT(*) as n_patterns,
  AVG(json_array_length(articles_json)) as avg_articles_per_pattern
FROM patterns
WHERE created_at > datetime('now', '-30 days')
GROUP BY confidence;
-- INSIGHT: padrões ALTA com poucos artigos = falsos positivos potenciais
```

### 📊 Métricas a coletar (criar `audit_scripts/onda_1_3_metrics.py`)

| Métrica | Como medir | Target |
|---|---|---|
| Feed availability rate (30d) | feeds com fetch nos últimos 2 dias / total feeds | >95% |
| Article dedup rate | (artigos rejeitados por URL dup) / artigos brutos | <5% |
| Avg time RSS→DB | timestamp diff entre publish_date e fetched_at | <2h |
| Pattern precision proxy | % patterns ALTA confirmados via outcomes (Onda 11) | >60% (medir, não assumir) |
| Digest token cost/day | tokens consumidos em digest.py | medir baseline |

### ✅ Critérios de aceitação

- Zero feeds em estado "morto" (>7 dias sem fetch) sem alerta documentado
- Zero duplicados na tabela `articles` por URL canonical
- Pattern matcher gera pelo menos 1 pattern ALTA por semana (se gera zero, threshold alto demais; se gera >5/dia, threshold baixo demais)
- Digests geram em <60 segundos e custo estável (variância <30% mês a mês)

### ⚡ Optimizações a considerar

1. **Feed prioritisation:** feeds que historicamente geram patterns confirmados merecem fetch mais frequente. Implementar `feed_value_score` = (TP patterns derivados) / (custo LLM gerado).
2. **Pattern matcher cache:** se o mesmo cluster de artigos foi avaliado nos últimos 6h, não chamar Sonnet de novo.
3. **Digest deduplication:** não incluir no digest da noite items que já estavam no digest da manhã, a menos que tenham nova evidência.

### 🚨 Red flags

- Um único feed responsável por >20% dos artigos (concentração de fonte)
- Patterns ALTA com sources de mesmo domínio root (não são independentes)
- Digest token cost a crescer >10% mês/mês sem aumento proporcional de artigos

---

## ONDA 4 — Static Supply-Chain Knowledge Graph

### 🎯 Objectivo da auditoria
Validar que o grafo estático (24 nós, 36 edges) representa adequadamente as cadeias críticas, e que as menções nos artigos estão a ser correctamente associadas aos nós.

### 📋 Checklist de auditoria de código

- [ ] `supply_chain_nodes` tem 24 nós? Listá-los e validar cobertura: minerais críticos (Li, Co, Ni, Cu, Ga, Ge, Ta), componentes (chips lógicos, memória, baterias, painéis), produtos finais.
- [ ] `supply_chain_edges` tem 36 edges? Validar consistência (não há orfãos, não há ciclos não-intencionais).
- [ ] `supply_chain_analyzer.py` — método de matching artigo→nó: substring? Fuzzy? Embedding similarity? Documentar.
- [ ] Sentiment analysis está calibrada? PT-BR vs EN tratamento.

### 🧪 Testes a executar

```sql
-- T4.1: Cobertura de menções por nó
SELECT n.name, n.type, COUNT(m.id) as mention_count
FROM supply_chain_nodes n
LEFT JOIN supply_chain_mentions m ON m.node_id = n.id
WHERE m.created_at > datetime('now', '-30 days') OR m.created_at IS NULL
GROUP BY n.id
ORDER BY mention_count ASC;
-- ALERTA: nós com 0 menções em 30 dias podem estar mal nomeados ou serem irrelevantes

-- T4.2: Sentiment distribution
SELECT 
  ROUND(sentiment, 1) as sentiment_bucket,
  COUNT(*) as n
FROM supply_chain_mentions
WHERE created_at > datetime('now', '-30 days')
GROUP BY sentiment_bucket;
-- INSIGHT: se >80% das menções são neutras (sentiment ~0), análise de sentiment provavelmente partida

-- T4.3: Edges não usadas
SELECT e.src, e.dst, e.relation
FROM supply_chain_edges e
WHERE NOT EXISTS (
  SELECT 1 FROM supply_chain_mentions m1
  JOIN supply_chain_mentions m2 ON m1.article_url = m2.article_url
  WHERE m1.node_id = e.src AND m2.node_id = e.dst
);
-- INSIGHT: edges nunca activadas por artigos co-mencionados podem ser irrelevantes
```

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Node coverage rate (30d) | nós com >=1 menção / 24 | >80% |
| Mention orphan rate | menções com node_id=NULL / total menções | <10% |
| Edge activation rate | edges co-mencionados / 36 | >50% |
| Sentiment dispersion | std deviation do sentiment | >0.3 (se for muito baixo, está colado em zero) |

### ✅ Critérios de aceitação

- Todos os 24 nós têm pelo menos 1 menção em 90 dias
- Sentiment analysis distingue claramente positivo/negativo (não tudo neutro)
- Pelo menos 60% dos edges activam em algum momento

### ⚡ Optimizações a considerar

1. **Grafo expansível:** considerar pipeline que sugere novos nós baseado em entidades frequentes não cobertas. Human-review antes de promover.
2. **Edge weights:** edges actuais são binárias. Adicionar peso baseado em frequência de co-menção pode melhorar propagação na Onda 6.
3. **Multilingual matching:** se mention rate em fontes PT é desproporcionalmente baixa, problema de matching de termos.

### 🚨 Red flags

- Grafo enviesado para EUA/EU (faltar nós críticos da Ásia)
- Mais de 30% dos artigos sobre commodities não geram nenhuma menção (matching pobre)

---

## ONDA 5a — Temporal Acceleration / Divergence Detection

### 🎯 Objectivo da auditoria
Validar que os thresholds 2× (aceleração) e 0.3× (desaceleração) estão calibrados e que detectam aceleração real, não apenas ruído estatístico.

### 📋 Checklist de auditoria de código

- [ ] `temporal.py` — baseline é calculado em que janela? 7d? 30d? Documentar.
- [ ] Os thresholds 2.0 e 0.3 são hardcoded ou configuráveis? Se hardcoded, mover para config.
- [ ] Há protecção contra divisão por zero (baseline = 0)?
- [ ] `temporal_snapshots` está a ser populado de hora em hora? Verificar gaps.

### 🧪 Testes a executar

```sql
-- T5.1: Gaps em temporal_snapshots
WITH hours AS (
  SELECT datetime('now', '-' || (n) || ' hours') as h
  FROM (SELECT 0 as n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 -- ... gerar 168 horas)
)
SELECT h.h, COUNT(t.bucket) as snapshot_count
FROM hours h
LEFT JOIN temporal_snapshots t ON strftime('%Y-%m-%d %H:00', t.bucket) = strftime('%Y-%m-%d %H:00', h.h)
GROUP BY h.h
HAVING snapshot_count = 0;
-- ALERTA: gaps indicam falha no cron market-monitor

-- T5.2: Distribuição de ratios de aceleração
SELECT 
  category,
  AVG(current_count * 1.0 / NULLIF(baseline_count, 0)) as avg_ratio,
  MAX(current_count * 1.0 / NULLIF(baseline_count, 0)) as max_ratio,
  COUNT(*) FILTER (WHERE current_count > 2 * baseline_count) as accel_events
FROM temporal_snapshots
WHERE bucket > datetime('now', '-30 days')
GROUP BY category;
-- INSIGHT: categorias que nunca aceleram (avg_ratio sempre ~1) podem ter baseline mal definido
```

### 🧪 Backtest histórico (CRÍTICO)

Re-correr o detector temporal contra eventos conhecidos onde **sabemos** que houve aceleração de cobertura:

| Evento | Data | Categoria esperada | Onda 5a deveria disparar? |
|---|---|---|---|
| ChatGPT launch | 2022-11-30 | tecnologia_ia | SIM |
| SVB collapse | 2023-03-10 | financas | SIM |
| Hamas attack on Israel | 2023-10-07 | geopolitica | SIM |
| China gallium restrictions | 2023-07-03 | cadeia_suprimentos | SIM |

**Output esperado:** tabela com `event_date | detected? | lead_time_hours | confidence`. Se o sistema falha em >25% destes eventos óbvios, recalibrar thresholds.

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Snapshot completeness | snapshots presentes / horas esperadas (168 últimas) | >98% |
| Accel event rate | eventos com ratio >2.0 por semana, por categoria | 1-5 (não zero, não 50) |
| Backtest recall | eventos históricos detectados / total | >75% |
| False accel rate | eventos detectados sem confirmação subsequente em patterns | <40% |

### ✅ Critérios de aceitação

- Sem gaps >2h em temporal_snapshots
- Recall >75% no backtest histórico
- Ratio de eventos accel/total razoável (não zero, não excesso)

### ⚡ Optimizações a considerar

1. **Thresholds adaptativos por categoria:** "tecnologia_ia" é estruturalmente mais ruidosa que "cadeia_suprimentos". Thresholds devem reflectir isto.
2. **Baseline ponderada:** baseline 30d trata uma notícia de há 30 dias igual a uma de ontem. Considerar EMA (exponential moving average).
3. **Z-score em vez de ratio:** `(current - baseline) / std_dev` é estatisticamente mais robusto que `current/baseline`.

### 🚨 Red flags

- Mesmo evento histórico não disparou em backtest
- Categoria nunca acelera (baseline alto demais ou matching pobre)
- Ratio máximo absurdamente alto (1000×) — provavelmente erro de zero division ou bug

---

## ONDA 6 — Supply-Chain Anomaly Detection

### 🎯 Objectivo da auditoria
Validar três tipos distintos de anomalia: spike (anomalia num nó), propagation (espalha por nós conectados), correlated chains (3+ nós saltam juntos).

### 📋 Checklist de auditoria de código

- [ ] `supply_chain_analyzer.py` — definição matemática de "spike" está documentada? (e.g., >3 std dev da média?)
- [ ] Detecção de propagation considera direcção das edges?
- [ ] `cross_pillar_chains` tem `members_hash` (de-dup chains semelhantes)?
- [ ] Há cooldown para evitar alertar mesma chain repetidamente?

### 🧪 Testes a executar

```sql
-- T6.1: Distribuição dos tipos de anomalia detectados
SELECT 
  json_extract(data_json, '$.anomaly_type') as type,
  COUNT(*) as n
FROM cross_pillar_chains
WHERE created_at > datetime('now', '-60 days')
GROUP BY type;
-- INSIGHT: se 100% é "spike" e 0% é "propagation", o detector de propagação não funciona

-- T6.2: Chains de tamanho variado
SELECT 
  json_array_length(json_extract(data_json, '$.nodes')) as chain_size,
  COUNT(*) as n
FROM cross_pillar_chains
GROUP BY chain_size;
-- INSIGHT: 99% das chains com size=2 = não há detecção real de chains, só pares
```

### 🧪 Backtest contra eventos reais

| Evento | Nós envolvidos esperados | Tipo esperado |
|---|---|---|
| Russia gas crisis 2022 | gas → energia → industria | propagation |
| Taiwan earthquake Apr 2024 | TSMC → chips → carros/eletrónica | propagation |
| China gallium ban Jul 2023 | gallium → chips → defesa/auto | correlated chain |
| Suez canal 2021 | shipping → energia → cadeia global | propagation |

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Anomaly type diversity | tipos distintos detectados / 3 | 3/3 |
| Avg chain size | tamanho médio das chains correlated | >=3 |
| Historical recall | eventos do backtest detectados | >50% |
| False chain rate | chains detectadas e marcadas FP via Onda 11 | <30% |

### ✅ Critérios de aceitação

- Todos os 3 tipos de anomalia detectados em últimos 60 dias
- Chains correlated têm em média 3+ nós (não 2)
- Recall histórico >50%

### ⚡ Optimizações a considerar

1. **Graph algorithms:** usar networkx para detectar comunidades dinâmicas (Louvain, Leiden) em vez de heurísticas manuais.
2. **Temporal propagation:** quanto tempo entre primeira menção do nó A e propagação para nó B? Distribuição informa thresholds.

### 🚨 Red flags

- Apenas um tipo de anomalia a aparecer (provavelmente os outros dois estão partidos)
- Chains sempre com mesmos 2-3 nós (algoritmo preso em local minimum)

---

## ONDA 7 — Supply-Chain Visualization (Cytoscape.js)

### 🎯 Objectivo da auditoria
Validar que a visualização é **usada** (não apenas existe) e que escala com o crescimento do grafo dinâmico (Onda 10).

### 📋 Checklist de auditoria de código

- [ ] Layout do Cytoscape é adequado para grafos com 100+ nós (Onda 10 vai crescer)? Considerar `cose-bilkent` ou `fcose`.
- [ ] Há filtros (por tipo de nó, sentiment, recência)?
- [ ] Performance: render time com 500 nós?
- [ ] Persistência de view state (zoom, pan, filtros) entre sessões?

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Page load time (P95) | medir com browser devtools ou Lighthouse | <3s |
| Render time 500 nodes | benchmark com mock data | <2s |
| User interactions/session | analytics simples (clicks, filtros aplicados) | baseline |

### ⚡ Optimizações a considerar

1. **Lazy loading:** só renderizar nós no viewport actual + 1 hop.
2. **Edge bundling:** com 36→100+ edges, bundling melhora legibilidade.
3. **Saved views:** "Energy crisis view", "Chips view" como bookmarks.

### 🚨 Red flags

- Tu próprio nunca usas a página (sinal de que tem fricção UX)
- Crashes do browser com grafos grandes

---

## ONDA 8 — sqlite-vec ANN Clustering + Embedding Versioning

### 🎯 Objectivo da auditoria
Validar que ANN não está a perder qualidade comparado a brute-force, e que o versionamento de embeddings permite migração futura sem corromper histórico.

### 📋 Checklist de auditoria de código

- [ ] `embeddings.py` — `embedding_version` está a ser registado para cada embedding?
- [ ] Existe path de migração quando o modelo de embeddings muda (Voyage 3-lite → futuro Voyage 4)?
- [ ] `pattern_matcher.py` — fallback brute-force funciona se sqlite-vec falhar?
- [ ] Parâmetro K (top-K) está documentado e configurável?

### 🧪 Testes a executar

```python
# T8.1: ANN vs brute-force recall benchmark
# Para uma amostra de 100 queries:
#   - Obter top-10 via sqlite-vec (ANN)
#   - Obter top-10 via brute-force cosine
#   - Calcular recall@10 = |ANN ∩ BF| / 10
# Target: recall@10 > 0.90

# T8.2: Latency benchmark
# Medir P50, P95, P99 latency para queries em DB com:
#   - 1k embeddings
#   - 10k embeddings  
#   - 25k embeddings (limite actual)
# ANN deve ser >10× mais rápido que brute-force em 25k
```

```sql
-- T8.3: Verificar consistência embeddings vs embeddings_vec
SELECT 
  (SELECT COUNT(*) FROM embeddings) as main_count,
  (SELECT COUNT(*) FROM embeddings_vec) as vec_count,
  (SELECT COUNT(*) FROM embeddings WHERE url NOT IN (SELECT url FROM embeddings_vec)) as orphan_in_main,
  (SELECT COUNT(*) FROM embeddings_vec WHERE url NOT IN (SELECT url FROM embeddings)) as orphan_in_vec;
-- ALERTA: orphans = desync entre tabelas

-- T8.4: Versionamento
SELECT embedding_version, COUNT(*) FROM embeddings GROUP BY embedding_version;
-- INSIGHT: se houver múltiplas versões, há mix de qualidades. Documentar plano de re-embedding.
```

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| ANN recall@10 vs brute-force | benchmark 100 queries | >0.90 |
| Latency P95 (25k embeddings) | benchmark | <100ms |
| Embedding versions count | SQL | 1 (idealmente) |
| Orphan rate | embeddings em main sem par em vec | 0% |

### ✅ Critérios de aceitação

- ANN recall@10 > 0.90 contra brute-force
- Latency P95 < 100ms em 25k embeddings
- Zero orphans entre `embeddings` e `embeddings_vec`

### ⚡ Optimizações a considerar

1. **Re-embedding strategy:** se Voyage lançar versão melhor, qual o plano? Background job que re-processa em batches?
2. **Embedding compression:** quantização para int8 reduz storage 4× com perda mínima.

### 🚨 Red flags

- Recall ANN < 0.85 (degradação inaceitável)
- Mix de embedding_versions sem plano de migração
- Tabela `embeddings_vec` >2× tamanho de `embeddings` (overhead absurdo)

---

## ONDA 9 — Cross-Pillar Correlation Engine

### 🎯 Objectivo da auditoria
Validar que 3+ pillars simultaneamente é critério estatisticamente significativo e que alertas consolidados realmente reduzem ruído.

### 📋 Checklist de auditoria de código

- [ ] `cross_pillar.py` — definição dos 4 pillars está documentada? (tecnologia, geopolítica, mercados, supply chain?)
- [ ] Threshold "≥3 pillars" é configurável?
- [ ] `cross_pillar_chains` tem deduplicação por `members_hash`?
- [ ] Cooldown para mesma chain (não alertar duas vezes em 24h)?

### 🧪 Testes a executar

```sql
-- T9.1: Chains por número de pillars
SELECT 
  json_array_length(pillars_json) as n_pillars,
  COUNT(*) as n_chains
FROM cross_pillar_chains
WHERE created_at > datetime('now', '-60 days')
GROUP BY n_pillars;
-- INSIGHT: distribuição deve ser concentrada em 3, com cauda fina em 4

-- T9.2: Combinações de pillars mais frequentes
SELECT 
  pillars_json,
  COUNT(*) as freq
FROM cross_pillar_chains
WHERE created_at > datetime('now', '-90 days')
GROUP BY pillars_json
ORDER BY freq DESC
LIMIT 10;
-- INSIGHT: se sempre os mesmos 3 pillars co-ocorrem, falta diversidade
```

### 🧪 Estatística: testar significância

**Hipótese nula:** 3+ pillars co-ocorrerem é apenas chance.

**Teste:**
1. Calcular probabilidade marginal de cada pillar disparar num dia: P(pillar=1) por dia.
2. Sob independência: P(3+ pillars) = combinatória de P(pillar=1).
3. Observar a frequência empírica. Se empírica > teórica em pelo menos 3×, há sinal real. Se não, é ruído.

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Chains/week | contagem semanal | 1-5 |
| Pillar distribution | quantos % das chains envolvem cada pillar | >15% cada |
| Significance ratio | empírica/teórica de 3+ pillars co-ocorrendo | >3× |
| Consolidated alert reduction | (alertas individuais suprimidos)/(alertas totais) | >20% |

### ✅ Critérios de aceitação

- Test estatístico de significância passa (chains 3+ pillars > random)
- Pelo menos 4 combinações distintas de pillars em 90 dias
- Redução demonstrável de spam de alertas

### ⚡ Optimizações a considerar

1. **Pillar weighting:** nem todos os pillars têm igual peso. "Geopolítica + Supply Chain" historicamente preditivo de movimentos de mercado; "Tech + Ciência" pode ser ruído acadêmico.
2. **Temporal window adaptativo:** window actual é 48h? Eventos rápidos (flash crash) precisam window menor; tendências macro precisam window maior.

### 🚨 Red flags

- Test estatístico falha (3+ pillars é só ruído)
- Mesma combinação domina (>70% das chains) — sistema enviesado

---

## ONDA 10 — Dynamic Knowledge Graph with Human Review

### 🎯 Objectivo da auditoria
Validar que a extração de triplas tem qualidade suficiente para reduzir a carga de revisão humana, e que o grafo aprovado está a crescer com sinal real.

### 📋 Checklist de auditoria de código

- [ ] `graph_extractor.py` — 8 entity types e 14 predicates estão hardcoded ou em config?
- [ ] Há prompt versioning para o Haiku? Mudanças de prompt invalidam triplas antigas?
- [ ] Review UI tem batch operations (aprovar 10 de uma vez)?
- [ ] Entidades canonical têm fuzzy matching? ("Apple Inc.", "Apple", "APPL" → mesmo canonical)

### 🧪 Testes a executar

```sql
-- T10.1: Fila de review (backlog)
SELECT status, COUNT(*) FROM graph_entities GROUP BY status;
SELECT status, COUNT(*) FROM graph_relationships GROUP BY status;
-- ALERTA: se backlog "staged" > 500, revisão humana não escala

-- T10.2: Approval rate
SELECT 
  COUNT(*) FILTER (WHERE status='approved') * 1.0 / 
  COUNT(*) FILTER (WHERE status IN ('approved', 'rejected')) as approval_rate
FROM graph_entities;
-- INSIGHT: approval_rate <60% = Haiku produz lixo; >95% = humano está rubber-stamping

-- T10.3: Duplicação canonical
SELECT canonical, COUNT(*) FROM graph_entities GROUP BY canonical HAVING COUNT(*) > 1;
-- ALERTA: deveria ser zero (canonical é UNIQUE)

-- T10.4: Top entities (sanity check)
SELECT canonical, mention_count FROM graph_entities WHERE status='approved' ORDER BY mention_count DESC LIMIT 20;
-- INSIGHT: top 20 deveria ser reconhecível (OpenAI, NVIDIA, China, etc.). Se aparecer ruído, extracção tem bug.
```

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Backlog size | entidades + relações em "staged" | <100 |
| Approval rate | aprovadas / (aprovadas + rejeitadas) | 70-90% |
| Review time/week | tempo manual gasto | <30 min |
| Triple precision | aprovadas manualmente como "objetivamente verdadeiras" | medir |
| Canonical dedup rate | entidades fundidas / extraídas | medir |

### ✅ Critérios de aceitação

- Approval rate entre 70% e 90% (sweet spot — abaixo é lixo, acima é rubber-stamp)
- Backlog não cresce indefinidamente
- Top 20 entidades aprovadas são reconhecivelmente relevantes

### ⚡ Optimizações a considerar

1. **Pre-filtering:** entidades com mention_count=1 e confidence<0.5 podem ser auto-rejeitadas (não vale tempo humano).
2. **Active learning:** mostrar primeiro as triplas onde o modelo está mais incerto (confidence ~0.5). Maximiza valor do tempo humano.
3. **Canonical resolution via embeddings:** "Apple Inc.", "Apple Corporation", "AAPL" devem fundir automaticamente via similaridade.

### 🚨 Red flags

- Backlog a crescer >50% mês/mês (revisão não acompanha)
- Approval rate <50% ou >95% (extracção pobre ou revisão sem critério)
- Top entidades incluem stop words, fragmentos, URLs (bug no parser)

---

## ONDA 11 — Backtesting · System Snapshots · Outcome Labelling · Quality Metrics

### 🎯 Objectivo da auditoria
**Esta é a onda mais importante para validar.** Sem ela, todas as outras métricas são especulação. Validar: snapshots fiéis, replay sem leakage, outcomes em volume suficiente para estatística.

### 📋 Checklist de auditoria de código

- [ ] `system_snapshots` — snapshot_type cobre todos os componentes? (trends, cross_pillar, supply_chain, graph)
- [ ] Replay é **estritamente** sem leakage do futuro? (i.e., re-correr análise com dados do timestamp T não pode aceder a dados de T+1)
- [ ] `event_outcomes` tem UNIQUE(event_type, event_id) para evitar double-labelling?
- [ ] Há UI para marcar outcomes facilmente, ou só via API?

### 🧪 Testes a executar (críticos)

```sql
-- T11.1: Volume de outcomes labelled (sample size)
SELECT event_type, outcome, COUNT(*) as n
FROM event_outcomes
GROUP BY event_type, outcome;
-- CRÍTICO: para precision por event_type ser estatisticamente válida, precisa >=30 outcomes por (type, outcome)
-- Se tens 5 TP e 2 FP em "pattern_alta", a "precisão de 71%" não significa nada

-- T11.2: Backtest determinismo
-- Re-correr backtest em janela X, comparar com run anterior
SELECT * FROM backtest_runs WHERE window = '...' ORDER BY created_at DESC LIMIT 2;
-- Os result_json devem ser idênticos. Se não são, há non-determinism

-- T11.3: Snapshot completeness
SELECT snapshot_type, 
       COUNT(*) as n,
       MIN(captured_at) as first,
       MAX(captured_at) as last,
       (julianday(MAX(captured_at)) - julianday(MIN(captured_at))) as span_days
FROM system_snapshots
GROUP BY snapshot_type;
-- INSIGHT: span_days indica há quanto tempo tens snapshots. <30d = insuficiente para backtest sério.

-- T11.4: Quality metrics actuais
-- (Esta é uma chamada API: GET /api/metrics/quality)
-- Comparar precision reportada vs cálculo manual via SQL:
SELECT event_type,
       COUNT(*) FILTER (WHERE outcome='true_positive') * 1.0 / COUNT(*) as precision_manual
FROM event_outcomes
WHERE outcome IN ('true_positive', 'false_positive')
GROUP BY event_type;
-- Deve bater com o endpoint
```

### 🧪 Teste de leakage (CRÍTICO)

Construir um teste de unit que:
1. Pega snapshot do estado em T1 (e.g., 2024-06-01).
2. Insere um artigo "future" em T2 (2024-06-15).
3. Roda replay_window(T0, T1).
4. **Assert:** nenhuma referência ao artigo de T2 aparece no resultado do replay.

Se este teste falha, o backtest está contaminado e **todas as métricas de precisão são fraude**.

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Outcomes labelled total | COUNT(*) em event_outcomes | >300 (mínimo estatístico) |
| Outcomes por event_type | por event_type | >=30 |
| Snapshot coverage | days_span por snapshot_type | >90 dias |
| Precision por event_type | SQL acima | report (não target — é o que mede) |
| Leakage test pass | unit test | PASS |

### ✅ Critérios de aceitação

- Leakage test passa (esta é binária — não há "quase passar")
- Pelo menos 30 outcomes por event_type principal
- Snapshots cobrindo >=90 dias
- Backtest determinístico (re-runs produzem mesmo resultado)

### ⚡ Optimizações a considerar

1. **Outcomes labelling UI:** se levas >30s para marcar cada outcome, vais procrastinar. Atalhos de teclado (T = true positive, F = false positive, U = unclear).
2. **Bulk replay:** correr backtest em todos os últimos 12 meses overnight, comparar com manual.
3. **Confidence intervals:** report `precision = 0.72 ± 0.08 (95% CI)` em vez de só `0.72`. Honestidade estatística.

### 🚨 Red flags

- **<30 outcomes labelled total** = ainda não tens dados para qualquer afirmação estatística
- Leakage test falha = sistema todo é unreliable
- Backtest produz resultados diferentes em re-runs = non-determinism

---

## ONDA 12 — Bubble Detection (LPPL + Quant Layer)

### 🎯 Objectivo da auditoria
Esta onda é **a única que vai informar decisões financeiras reais**. Bar de validação tem de ser dramaticamente mais alto que ondas anteriores.

### 📋 Checklist de auditoria de código

- [ ] `quant_bars`, `quant_indicators`, `quant_features` migrados para Postgres+TimescaleDB?
- [ ] LPPL fitting usa formulação Filimonov-Sornette (4 linear + 3 nonlinear params, mais estável)?
- [ ] Há implementação de DS LPPLS **Confidence™** e **Trust™** indicators (Zhang, Sornette 2016)?
- [ ] Multi-window analysis (60d, 120d, 240d, 365d) com agregação?
- [ ] FRED/yfinance pulls são incrementais (não re-pull histórico completo)?
- [ ] Integração com Cross-Pillar (Onda 9) — bubble detector é o "5º pillar"?

### 🧪 Testes a executar (CRÍTICOS)

#### Test 12.1: Backtest contra bolhas históricas consensuais

| Bolha | Pico | Início do backtest | Recall esperado | Lead time mínimo |
|---|---|---|---|---|
| Dot-com (NASDAQ) | 2000-03-10 | 1999-01-01 | SIM | 60+ dias |
| Credit/Housing (S&P) | 2007-10-09 | 2006-06-01 | SIM | 90+ dias |
| BTC bubble 2017 | 2017-12-17 | 2017-06-01 | SIM | 30+ dias |
| BTC bubble 2021 | 2021-11-10 | 2021-06-01 | SIM | 30+ dias |
| Meme stocks GME | 2021-01-28 | 2020-11-01 | OPCIONAL | (evento curto, difícil) |

**Critério:** sistema deve detectar **pelo menos 3 das 4** bolhas principais (não conta meme stocks).

#### Test 12.2: Stress test de fit LPPL

Para CADA bolha histórica:
1. Fit em janela 60d, 120d, 240d, 365d.
2. Comparar `t_c` previsto entre janelas.
3. Calcular desvio padrão de `t_c` (em dias).
4. **Pass criteria:** `std(t_c) < 30 dias` entre janelas. Se varia muito, fit instável.

#### Test 12.3: False positive rate em períodos não-bolha

Correr detector em períodos onde **NÃO** houve bolha consensual:
- 2015 (mercado lateral)
- 2018-2019 (correção, mas não bolha)
- 2023 (recovery)

**Pass criteria:** <2 alertas "bubble high confidence" por ano nestes períodos.

#### Test 12.4: Bootstrap confidence

Para cada predição actual (live):
1. Bootstrap resample do data window 1000 vezes.
2. Refit LPPL em cada resample.
3. Computar distribuição de `t_c`.
4. Reportar `t_c = X ± Y dias (95% CI)`.

**Output:** se o CI é >100 dias, o sistema não tem precisão suficiente para timing — só pode dizer "está caro", não "vai cair na semana X".

### 📊 Métricas a coletar

| Métrica | Como medir | Target |
|---|---|---|
| Historical recall | bolhas detectadas / total | >=3/4 (75%) |
| Lead time median | dias entre detecção e pico | >30 dias |
| False positive rate | alertas em períodos calmos / ano | <2/ano |
| LPPL t_c stability | std(t_c) entre janelas | <30 dias |
| Bootstrap CI width | largura média do 95% CI de t_c | <100 dias |
| Latency LPPL fit | tempo de cálculo | <30s por ticker |

### ✅ Critérios de aceitação

- **Recall histórico >=75%** nos 4 backtests principais
- **Lead time mediano >30 dias** (avisar no pico é inútil)
- **False positive rate <2/ano** em períodos calmos
- **LPPL fit stable** (`std(t_c) < 30 dias` entre janelas)
- **Confidence intervals reportados** (não só pontos)

**Sem TODOS estes critérios cumpridos, NÃO alocar capital real baseado em alertas desta onda.**

### ⚡ Optimizações a considerar

1. **Multi-asset cross-validation:** se XLK dispara mas QQQ não (apesar de altamente correlacionados), há bug.
2. **Sinais auxiliares:** GSADF test, Shiller CAPE, Buffett indicator como camadas paralelas. Concordância de 3+ sinais = alta confiança.
3. **Sentiment integration:** combinar LPPL (preço) com temporal de notícias (narrativa). Cross-pillar real.
4. **Position sizing baseado em confidence:** alert ALTA → ajuste pequeno; alert + bootstrap CI apertado → ajuste maior.

### 🚨 Red flags (CRÍTICOS — qualquer um destes mata a onda)

- Falha em detectar 2+ das 4 bolhas históricas
- Lead time mediano <14 dias (avisa quando já é tarde)
- False positive rate >5/ano (perderás confiança rapidamente)
- LPPL fit produz `t_c` num range >90 dias entre janelas (não há sinal)
- Sistema dispara em correção normal de -10% como se fosse bolha estourando

### 🛡️ Protocolo obrigatório antes de alocar capital

1. **Paper trading mode** activado por **mínimo 6 meses** após validação inicial.
2. **`decisions_journal.md`** com cada alerta marcado como "would have acted: yes/no, why".
3. **Comparação contra baseline** buy-and-hold do mesmo índice no mesmo período.
4. **Só após 6 meses de paper trading com Sharpe ratio igual ou melhor que buy-and-hold**, considerar capital real.
5. **Capital inicial: máximo 5% do portfolio.** Escalar apenas com track record adicional.

---

## Apêndice A — Stack de Ferramentas para Auditoria

| Categoria | Ferramenta | Para que |
|---|---|---|
| Optimização | `optuna` | Walk-forward optimization, Bayesian search |
| LPPL | `lppls` (PyPI) | Implementação validada da formulação Filimonov-Sornette |
| Time-series tests | `statsmodels` | GSADF, ADF, KPSS |
| Change point | `ruptures` | Detecção de breaks estruturais |
| Bootstrap | `arch` ou `scipy.stats` | Bootstrap confidence intervals |
| Graph | `networkx` | Análise do supply chain graph |
| Profiling | `py-spy`, `memray` | Encontrar bottlenecks em produção |
| LLM eval | `promptfoo`, `deepeval` | Regression tests de prompts |
| Data quality | `great-expectations` | Validação automática de schemas |

---

## Apêndice B — KPIs Globais do Sistema (Dashboard de Saúde)

Implementar uma view `/api/health/kpis` que retorna:

```json
{
  "system_uptime_30d": 0.998,
  "llm_cost_mtd_usd": 8.42,
  "llm_cost_forecast_eom_usd": 10.31,
  "feed_availability": 0.96,
  "article_dedup_rate": 0.03,
  "patterns_alta_per_week": 4.2,
  "cross_pillar_chains_per_week": 1.8,
  "graph_review_backlog": 47,
  "outcomes_labelled_total": 312,
  "outcomes_labelled_last_7d": 8,
  "bubble_alerts_active": 0,
  "bubble_detector_paper_pnl_pct": null,
  "last_backtest_run": "2026-05-20T14:23:00Z"
}
```

Olhar este endpoint **diariamente, 30 segundos**. Mudança fora de range = investigar.

---

## Apêndice C — Template de Relatório por Onda

Cada `audit_reports/onda_N_audit.md` deve seguir:

```markdown
# Auditoria Onda N — [Nome]
**Data:** YYYY-MM-DD
**Executor:** Claude Code (commit hash: ...)
**Versão do sistema auditado:** ...

## 1. Resumo Executivo (3 frases)
- O que está a funcionar
- O que está a falhar
- Próxima acção recomendada

## 2. Checklist de Código
[copiar checklist da onda e marcar pass/fail/N-A com link para ficheiro+linha]

## 3. Resultados dos Testes SQL
[query | resultado | interpretação]

## 4. Métricas Mensuradas
[tabela: métrica | valor actual | target | status]

## 5. Backtests Históricos (quando aplicável)
[evento | esperado | observado | lead time | TP/FP]

## 6. Critérios de Aceitação
- [x] Critério 1 — passou
- [ ] Critério 2 — falhou (razão: ...)

## 7. Red Flags Identificadas
[lista]

## 8. Optimizações Sugeridas (priorizadas)
1. [Optimização] — impacto estimado: alto/médio/baixo — esforço: ...
2. ...

## 9. Decisão
- [ ] Onda APROVADA — manter em produção
- [ ] Onda APROVADA COM CONDIÇÕES — implementar optimizações 1, 2
- [ ] Onda REPROVADA — desactivar até refactor

## 10. Anexos
- Logs relevantes
- Scripts executados
- Dados em CSV
```

---

## Apêndice D — Ordem de Execução Recomendada

```
Semana 1: Princípios Gerais (P1-P6) + Onda 11 (Backtesting)
  ↓
  Sem Onda 11 validada, todas as outras métricas são especulação.

Semana 2: Ondas 1-3 (RSS, Patterns, Digest)
  ↓
  Fundação. Sem dados de qualidade, ondas superiores são lixo.

Semana 3: Onda 8 (sqlite-vec) + Onda 10 (Knowledge Graph)
  ↓
  Camadas de qualidade que afectam tudo a jusante.

Semana 4: Ondas 4, 5a, 6 (Supply chain, Temporal, Anomalias)
  ↓
  Componentes analíticas core.

Semana 5: Ondas 7, 9 (Visualização, Cross-Pillar)
  ↓
  UX + síntese.

Semana 6-8: Onda 12 (Bubble Detection)
  ↓
  Auditoria mais extensa porque toca capital real.
  Backtests devem cobrir 4 bolhas históricas, stress testing, paper trading setup.

Semana 9: Documento final consolidado + decisão de quais ondas mantém/refactor/kill.
```

---

## Nota Final

Este plano é desenhado para **expor problemas, não para escondê-los**. Se o Claude Code reporta que tudo passa em todas as ondas no primeiro run, **desconfia** — provavelmente os testes não estão a apertar suficientemente. Boas auditorias encontram problemas. Problemas encontrados são bugs corrigidos antes de custar dinheiro real.

**A regra final:**

> *"Confiança em um sistema financeiro vem de track record medido, não de complexidade técnica. Um sistema simples com 6 meses de paper trading validado vale infinitamente mais que um sistema sofisticado sem validação."*

— Fim do documento —
