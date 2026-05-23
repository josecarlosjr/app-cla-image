# Plano de backtest — validar o Bubble Engine antes de ir pro ar

> Regra: **nenhum alerta de bolha automático vai pro Telegram** antes de o
> engine ser testado contra bolhas históricas conhecidas. Este documento é o
> roteiro desse teste.

---

## 1. Objetivo

Responder, com números, a uma pergunta simples:

> Se o Bubble Engine existisse em 1999, 2007 e 2020, ele teria acendido
> **antes** dos estouros — e ficado quieto nos períodos calmos?

Se não acende antes das bolhas conhecidas, ou acende o tempo todo (falsos
positivos), está mal-calibrado e **não** pode disparar alertas reais.

---

## 2. Os 3 episódios

| Episódio | Pico | O que testa | Proxy de preço |
|---|---|---|---|
| **Dotcom** | Mar/2000 | bolha de ações tech / "new paradigm" | `^IXIC` (NASDAQ), `^GSPC` |
| **GFC / subprime** | 2007-08 | bolha de crédito + imobiliário | `^GSPC`, `XLF`, credit gap US, HPI |
| **Crypto / meme / SPAC** | Nov/2021 | bolha de ativos especulativos | `BTC-USD`, `ARKK`, `^IXIC` |

Cada um estressa dimensões diferentes do engine — por isso os três, não um.

---

## 3. O que dá e o que NÃO dá pra backtestar (honestidade)

Esta é a limitação central, e precisa estar clara antes de tirar conclusões:

| Sinal | Backtestável? | Por quê |
|---|---|---|
| `momentum` (LPPL) | ✅ sim | preço tem histórico profundo (buscável) |
| `temporal` (preço) | ✅ sim | idem |
| `credit` (BIS gap) | ✅ sim | BIS publica desde 1961 |
| `valuation` (CAPE) | ✅ sim | Shiller CAPE desde 1871 |
| HPI (imobiliário) | ✅ parcial | Eurostat cobre 2008; mais raso para 2000 |
| `temporal` (notícias) | ❌ não | sem arquivo histórico de notícias |
| `graph_fragility` (KG) | ❌ não | KG só existe desde que o sistema ligou |
| `sentiment` / narrativa | ❌ não | idem |
| `structure` (concentração) | ⚠️ depende | precisa de holdings históricos |

**Conclusão:** o backtest valida a **metade quantitativa** do engine (preço,
crédito, valuation). A **metade narrativa** (notícias, grafo, sentimento) só
pode ser validada **para frente** (forward-test / paper-trade), porque não
há dados históricos dela. Qualquer afirmação de "o engine completo está
validado" seria falsa — e o documento de arquitetura deve refletir isso.

---

## 4. Metodologia: replay point-in-time

O erro clássico de backtest é *lookahead* (usar dados do futuro). Evitar
assim:

1. Buscar histórico profundo dos proxies de preço (ex.: 1995→hoje) numa
   tabela separada de backtest (não a watchlist de produção).
2. Para cada data `t` numa grade (ex.: mensal, 1998→2002 para dotcom):
   - Computar cada sinal backtestável **usando só dados até `t`**.
   - Rodar `composite_score` + `should_flag` com os mesmos pesos/limiares de
     produção.
   - Registrar `composite`, `aggregate_confidence`, `flagged` em `t`.
3. Marcar o pico real do episódio.
4. Medir (ver seção 5).

Reusa as **funções puras** de `bubble_scoring.py` direto — o ponto de elas
serem puras era exatamente este: dá pra alimentá-las com dados históricos
sem tocar no cluster.

---

## 5. Critérios de sucesso (métricas)

| Métrica | Pergunta | Alvo |
|---|---|---|
| **Lead time** | Quantos meses antes do pico o engine flagou? | > 0 (idealmente 3-18 meses) |
| **Acendeu antes do pico?** | `flagged=true` em algum `t` antes do pico? | sim nos 3 episódios |
| **Falsos positivos** | Flagou em períodos calmos (ex.: 2004-06, 2013-16)? | poucos / nenhum |
| **Precisão** | dos `flagged=true`, quantos foram seguidos de queda real? | alta |
| **Trajetória do composite** | sobe monotônico rumo ao pico? | idealmente sim |

Um engine que acende 2 meses antes do pico em todos os 3, e fica quieto nos
períodos calmos, está validado para os sinais quant.

---

## 6. Calibração (o que ajustar se falhar)

Os pesos (momentum 0.40 / temporal 0.30 / graph 0.30) e limiares (0.70 /
0.50) são **placeholder** hoje. O backtest é o que os calibra:

- Se acende tarde demais → baixar limiares ou subir peso do sinal mais
  antecipativo (provável: credit gap, que vira meses antes).
- Se há falsos positivos demais → subir limiares ou exigir mais cobertura.
- Se um sinal nunca contribui → revisar sua normalização (ex.: a rampa do
  temporal, o cap do graph).

---

## 7. Passos de implementação (quando autorizado)

1. `backtest_bubble.py` — busca histórico profundo (yfinance + BIS + CAPE),
   roda o replay point-in-time, salva resultados.
2. Endpoint `/api/bubble/backtest` + página/aba no Bubble Engine mostrando,
   por episódio: gráfico do `composite` ao longo do tempo, marcação do pico,
   lead time, e a lista de quando `flagged` virou true.
3. Você revisa os 3 gráficos. Só então decidimos os pesos/limiares finais.
4. **Só depois disso** o Quant Alerts passa a usar o Bubble Engine para
   disparar alertas reais (hoje ele usa só LPPL/GSADF por ticker).

---

## 8. Sequência recomendada (resumo)

```
  Passo 2  (orquestrador: scores reais por setor, sem alerta automático)
     ↓
  Backtest (este documento) → calibra pesos/limiares
     ↓
  Forward-test dos sinais narrativos (paper, algumas semanas)
     ↓
  Só então: alertas de bolha automáticos no Telegram
```

A disciplina é deliberada: o engine pode estar matematicamente correto
(self-test 6/6) e ainda assim mal-calibrado para o mundo real. O backtest é
a ponte entre "a matemática funciona" e "eu confio nos alertas".
