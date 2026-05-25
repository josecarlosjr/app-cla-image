# PIA — Arquitetura em linguagem simples

> Documento de alto nível. Explica **o que cada peça faz e por que existe**,
> sem jargão. Para definições curtas de termos, ver `docs/glossary.md`.
> Para o plano de validação histórica, ver `docs/backtest-plan.md`.

---

## 1. O que é o PIA

O **PIA (Personal Intelligence Agent)** é um sistema que lê o mundo
(notícias, preços, dados macro), procura padrões, e avisa você quando algo
importante acontece — incluindo o objetivo final: **detectar bolhas
financeiras antes que estourem.**

Pense em 3 camadas empilhadas:

```
  [ 1. INGESTÃO ]   coletar dados crus do mundo
        ↓
  [ 2. ANÁLISE  ]   transformar dados em sinais (padrões, scores, grafos)
        ↓
  [ 3. DECISÃO  ]   combinar sinais → alertas (Telegram) + dashboard
```

O **Bubble Engine** (Onda 13) é o topo da camada 3: ele consome quase tudo
abaixo dele.

---

## 2. Os componentes, um a um

### Camada 1 — Ingestão

**Feeds (RSS) + Filtro de Relevância**
Lê ~37 fontes de notícias. Cada artigo recebe uma nota de relevância (via
LLM) para o que interessa a você. Por que: separar sinal de ruído antes de
qualquer análise cara.

**Quant Layer — ingesters** (Onda 12)
Quatro "robôs" agendados que puxam números, não texto:
- **FRED** — indicadores macro dos EUA (curva de juros, spreads de crédito,
  M2, VIX...). 15 séries.
- **yfinance** — preços diários (OHLCV) + valuations (P/E) de uma
  *watchlist* de 11 tickers (SPY, QQQ, BTC, XLK, XLE, XLF...).
- **BIS** — *credit-to-GDP gap* por país (o melhor indicador histórico de
  bolha de crédito).
- **Eurostat + BPstat** — índices de preço de habitação (UE e Portugal).
Por que: o resto do sistema lê texto; bolhas precisam de *números* —
valuation, momentum, crédito, imobiliário.

**Monitor de preços + Crypto Scanner**
Vigiam preços (Brent, ouro, BTC) e criptos em alta, mandam alerta no
Telegram quando cruzam thresholds. Independentes do Bubble Engine.

### Camada 2 — Análise

**Pattern Matcher**
Quando 2+ fontes independentes cobrem o mesmo tema, isso vira um *pattern*
(padrão) com nível de confiança. Por que: uma fonte pode errar; convergência
de fontes é sinal mais forte.

**Cross-Pillar** (Onda 9)
Detecta quando vários "pilares" (tecnologia, energia, geopolítica, cadeia de
suprimentos...) se movem juntos. Por que: crises reais atravessam setores —
um choque em chips vira choque em autos vira choque em mercados.

**Temporal** (Onda 5a)
Mede *aceleração*: o ritmo de atenção/cobertura de um tema está acelerando?
Por que: bolhas têm assinatura temporal — atenção cresce exponencialmente,
não linearmente.

**Supply Chain**
Grafo de dependências minerais → componentes → produtos. Detecta gargalos
(ex.: lítio → bateria → carro elétrico). Por que: risco de cadeia é risco
de preço.

**Knowledge Graph (KG)** (Onda 10)
Um grafo *dinâmico* extraído das notícias: entidades (empresas, países,
bancos centrais, classes de ativo) ligadas por predicados (`depends_on`,
`inflates`, `triggers_default`...). Tudo passa por revisão humana antes de
entrar no grafo "aprovado". Por que: permite traçar **cadeias de contágio**
— "SPY → setor tech → NVIDIA → TSMC → risco Taiwan".

**Quant Layer — detectores** (Onda 12)
Dois testes estatísticos rodam sobre os preços:
- **LPPL** (Sornette) — ajusta uma curva de crescimento super-exponencial
  com oscilações; output = probabilidade de bolha [0..1].
- **GSADF** (Phillips-Shi-Yu) — teste de "explosividade" estatística; detecta
  quando uma série deixou de se comportar normalmente.
Por que: são os dois métodos acadêmicos consagrados para bolha de preço.

### Camada 3 — Decisão

**Quant Dashboard**
Página web com curva de juros, spreads de crédito, VIX, watchlist com
LPPL/GSADF, e o painel macro/imobiliário (credit gap + HPI com sparklines).

**Quant Alerts**
Cronjob diário: se algum ticker cruza thresholds de bolha, gera uma narrativa
curta (via Haiku) e manda no Telegram. Enriquecido com contexto do grafo
(Phase C) e contexto macro (credit gap, HPI).

**Bubble Engine** (Onda 13) — *o topo*
Combina os sinais de todas as camadas num **score de bolha por setor**. A
ideia central:

```
  Cada sinal vira um  Signal(score 0..1, confidence 0..1)
  composite            = quão bolha (dada a evidência)
  aggregate_confidence = quanta evidência por trás
  should_flag()        = só dispara se AMBOS forem altos
```

O `confidence` é a peça que evita o erro mais perigoso: um número confiante
construído sobre dados ausentes. Um sinal fraco sozinho **nunca** dispara um
alerta de bolha — exige corroboração de múltiplos sinais (disciplina
Sornette). Sinais implementados até agora: `momentum` (LPPL), `temporal`,
`graph_fragility`. Faltam: `valuation`, `credit`, `sentiment`, `structure`.

---

## 3. Onde cada coisa roda (infra)

```
  Kubernetes (k3s, ArgoCD faz o deploy via GitOps)
  ├── personal-agent-api      (FastAPI — serve o dashboard e endpoints)
  ├── frontend                (React + Vite — o dashboard)
  ├── postgres (TimescaleDB)  (séries temporais: quant_*)
  ├── PVC /data               (SQLite agent.db: notícias, padrões, grafo)
  └── CronJobs:
        monitor, news, crypto, patterns, digest (manhã/noite),
        notifications, e os quant: fred, yfinance, detectors, alerts,
        bis, eurostat, bpstat
```

**Dois bancos, de propósito:** SQLite (`/data/agent.db`) guarda o que é
leitura-pesada (notícias, padrões, grafo); Postgres/TimescaleDB absorve as
séries temporais de alta frequência que a detecção de bolha precisa.

**Secrets** ficam criptografados no git (SOPS+age via KSOPS) e o ArgoCD
descriptografa no cluster — nada de senha em texto plano no repositório.

---

## 4. O caminho de uma notícia até um alerta de bolha

```
  artigo RSS
    → filtro de relevância (vale a pena?)
    → enriquecimento (extrai entidades/tópicos)
    → Pattern Matcher (2+ fontes concordam? vira padrão)
    → Knowledge Graph (entidades + relações, revisão humana)
  preço (yfinance)
    → quant_bars (Postgres)
    → detectores LPPL/GSADF → quant_features
  macro (FRED/BIS/Eurostat/BPstat)
    → quant_indicators

  Bubble Engine combina tudo:
    momentum (LPPL) + temporal + graph_fragility [+ valuation/credit/...]
    → composite + aggregate_confidence
    → should_flag? → narrativa (Haiku) → Telegram + dashboard
```

---

## 5. Estado atual (Maio 2026)

- Camadas 1 e 2: **operacionais**.
- Quant Layer (Onda 12): **completo** (dados + dashboard + alerts).
- Bubble Engine (Onda 13): **núcleo de scoring validado** (Passo 1.5) +
  **orquestrador no ar** (Passo 2). Scores de bolha **por ticker** ao vivo,
  combinando preço (momentum/LPPL) e notícias (temporal + graph_fragility) —
  3 de 7 sinais ligados, expostos em `/api/bubble/scores` e na página Bubble
  Engine. Backtest e calibração dos pesos ainda **pendentes**.
- **Nenhum alerta de bolha automático no ar**: os scores são *informativos*
  (o orquestrador não dispara Telegram) até o backtest validar a calibração —
  ver `docs/backtest-plan.md`.
