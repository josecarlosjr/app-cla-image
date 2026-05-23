# Glossário — PIA / Bubble Engine

Definições curtas, em linguagem simples. Agrupado por domínio.

---

## Detecção de bolha (estatística)

**LPPL** — *Log-Periodic Power Law* (Sornette, 2003). Ajusta aos preços uma
curva de crescimento super-exponencial com oscilações que aceleram. Se a
curva encaixa bem, é assinatura de bolha. Saída: probabilidade de bolha
[0..1]. É o `momentum_signal`.

**GSADF** — *Generalized Sup Augmented Dickey-Fuller* (Phillips, Shi, Yu,
2015). Teste estatístico de "explosividade": detecta quando uma série de
preço deixou de se comportar normalmente (raiz unitária rejeitada a favor de
comportamento explosivo). Crítico 95% ≈ 1.49.

**credit-to-GDP gap** — Desvio do crédito-sobre-PIB em relação à sua
tendência de longo prazo (BIS). O indicador histórico mais robusto de bolha
de crédito; o buffer contracíclico de Basel III é calibrado nele. >2% =
gatilho; >10% = máximo histórico.

**HPI** — *House Price Index*. Índice de preço de habitação (Eurostat:
2015=100). Mede inflação imobiliária. Variação a/a >10% = froth.

**CAPE / Shiller P/E** — Preço sobre lucro ajustado ciclicamente (10 anos).
Métrica de valuation de longo prazo (usada no plano de backtest).

**OAS** — *Option-Adjusted Spread*. Quanto a mais um título de crédito paga
sobre o título do governo. HY OAS apertado (<3%) = froth de crédito; spike =
fuga para qualidade.

**Inversão da curva de juros** — Quando juros de curto prazo passam os de
longo (10Y-3M < 0). Historicamente precede recessão em 6-18 meses.

**VIX** — Índice de volatilidade implícita do S&P 500. <15 calmo, 25
nervoso, 40+ medo.

---

## Bubble Engine (contrato de scoring)

**Signal** — A unidade de saída de cada detector:
`Signal(score 0..1, confidence 0..1, detail)`. `score` = intensidade de
bolha; `confidence` = quanta/quão confiável é a evidência.

**composite** — O score combinado: `Σ(peso·score·conf) / Σ(peso·conf)`. Diz
**quão** bolha, dada a evidência presente. Sinal sem dado (conf=0) sai da
conta, não dilui.

**aggregate_confidence** — `Σ(peso·conf) / Σ(peso)`. Diz **quanta** evidência
está por trás do composite. Cobertura fina derruba este número mesmo com
composite alto.

**coverage** — Fração de sinais que tinham algum dado (ex.: 2/3).

**should_flag()** — A regra de disparo: só sinaliza bolha se `composite` E
`aggregate_confidence` cruzam os limiares (≥0.70 e ≥0.50). Garante que um
sinal sozinho nunca dispara — exige corroboração.

**momentum / temporal / graph_fragility** — Os 3 sinais já implementados:
LPPL (preço super-exponencial), aceleração, e nº de dependências no grafo ao
redor do setor (superfície de contágio).

**valuation / credit / sentiment / structure** — Os 4 sinais ainda não
implementados (peso 0 hoje).

---

## Quant Layer (dados)

**watchlist** — A lista de 11 tickers que o sistema acompanha: SPY, QQQ, IWM,
BTC-USD, ETH-USD, XLK, XLE, XLF, GLD, TLT, HYG.

**quant_bars** — Tabela (hypertable) de preços OHLCV diários por ticker.

**quant_valuations** — Tabela de valuations (P/E, P/B, market cap) por ticker.

**quant_indicators** — Tabela de séries macro escalares: FRED, BIS
(`BIS_CREDIT_GAP_*`), Eurostat (`EUROSTAT_HPI_*`), BPstat (`BPSTAT_*`).

**quant_features** — Saída dos detectores: `lppl_bubble_prob` e `gsadf_stat`
por ticker.

**OHLCV** — Open, High, Low, Close, Volume (os 5 números de uma barra de preço).

**hypertable** — Tabela do TimescaleDB otimizada para séries temporais
(particionada por tempo automaticamente).

**TimescaleDB** — Extensão do PostgreSQL para dados de série temporal.

---

## Pilares de análise

**pillar (pilar)** — Um eixo temático: tecnologia, energia, geopolítica,
cadeia de suprimentos, etc. Os scores de tendência são por pilar/categoria.

**pattern (padrão)** — Tema coberto por 2+ fontes independentes; tem nível de
confiança (ALTA/MEDIA/BAIXA).

**cross-pillar** — Detecção de quando múltiplos pilares se movem juntos
(sinal de evento sistêmico).

**temporal (Onda 5a)** — Detecção de aceleração/divergência no ritmo de
cobertura de um tema.

**enrichment** — Extração (via LLM) de entidades e tópicos de cada artigo,
cacheada por URL.

**embeddings** — Vetores (Voyage AI) que representam o significado de um
texto, para busca por similaridade.

**Knowledge Graph (KG)** — Grafo de entidades + relações extraído das
notícias, com revisão humana (staged → approved/rejected).

**entity_type** — Tipo de entidade no KG: company, country, person,
technology, mineral, product, organization, event, e os financeiros
(asset_class, financial_instrument, central_bank, regulator).

**predicate (predicado)** — A relação no KG: produces, supplies, depends_on,
competes_with, inflates, triggers_default, etc.

**graph_fragility** — No Bubble Engine, o sinal derivado de quantas
dependências o grafo mostra ao redor de um setor (mais arestas = mais
superfície de contágio).

---

## Infra

**cronjob** — Tarefa Kubernetes agendada (ex.: ingestão FRED a cada 6h).

**ArgoCD** — Ferramenta de GitOps: o que está no git é o que roda no cluster.

**KSOPS / SOPS / age** — Pipeline de criptografia de secrets: senhas ficam
criptografadas no git, descriptografadas só no cluster.

**PVC** — *Persistent Volume Claim*: o disco persistente onde vive o SQLite e
os arquivos de estado (`/data`).

**Haiku** — O modelo Claude mais barato/rápido, usado para as narrativas dos
alertas (custo baixo).

**FastAPI** — O framework Python que serve a API (`/api/...`).
