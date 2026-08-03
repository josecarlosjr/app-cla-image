# Onda 13 Sprint B — findings (sintético, ground-truth)

Estudo cego, detectores importados as-is, zero afinação. Mede
discriminação bolha-vs-não-bolha em DGPs de ground-truth. **Não** prova
true-positives nos crashes reais nem lead time — isso é a Fase A (gate
histórico in-pod).

## Resultados (60 seeds/família salvo indicado)

**Parte 3 — comparação nas 5 famílias LPPL-DGP:**

| família | v1 (R²) mean / %fl | v2 (composto) mean | GSADF %explosive |
|---|---|---|---|
| gbm_flat (ruído) | 0.475 / 32% | 0.308 | 0% |
| gbm_drift (bull) | 0.661 / 57% | 0.258 | 0% |
| exp/linear-trend | 0.99 / 100% | 0.008 | 28% |
| linear | 0.97 / 100% | 0.004 | 0% |
| LPPL fraca (7%) | 0.908 / 100% | 0.200 | 0% |
| **LPPL forte (81%)** | **0.982 / 100%** | **0.215** | **0%** |

Separação (bolha ÷ pior não-bolha, >1 discrimina): v1 **0.92**, v2 **0.70**.

**GSADF no DGP dele (raiz explosiva, 40 seeds):**

| série | bsadf_mean | %explosive |
|---|---|---|
| random_walk (ρ=1) | −0.70 | **0%** |
| explosive_AR (ρ=1.03) | 78.6 | **100%** |

## Veredicto por detector

- **LPPL v1 (bubble_prob=R²): FALHA.** Tendências (exp 0.99, linear 0.97)
  pontuam ≥ bolha real (0.98), em qualquer amplitude. Mede ajuste-a-
  tendência, não assinatura de bolha. Falha na sua PRÓPRIA definição.
- **LPPL v2 (composto oscilação): FALHA, e ao contrário.** Uma bolha LPPL
  real é dominada pela tendência — a oscilação explica só ~22% da variância
  (osc_indicator 0.22) → v2 baixo (0.215). O ruído do random walk dá
  oscilação-share MAIOR (0.31-0.48) → pontua acima da bolha. O fix pune
  bolhas e premeia ruído. Pior que v1.
- **GSADF: DISCRIMINA no DGP dele** (0% random walk, 100% explosivo). O 0%
  na bolha LPPL NÃO é falha — é mismatch: LPPL (super-exponencial
  determinística + oscilação, Sornette) ≠ raiz explosiva estocástica
  (Phillips-Shi-Yu). Um único sintético não testa ambos.

## Insight de método

**LPPL e GSADF detectam bolhas DIFERENTES.** O sintético LPPL testa
justamente o LPPL (falha) mas é estímulo errado para o GSADF. O GSADF só
é testável no DGP explosivo (passa) ou no histórico real.

Correcção de estímulo aplicada e reportada: o controlo positivo original
subia só 7% (ruído > sinal) — inválido; refeito a 81% (`lppl_strong_
control.py`). Não muda o veredicto do v1/v2 (falham em ambas amplitudes).

## Recomendação para a Fase A (gate histórico)

1. **NÃO levar LPPL v1 nem v2 como sinal isolado.** Ambos falham a
   discriminação em ground-truth. R²-como-bubble_prob é fundamentalmente
   um medidor de tendência. Como sinal FRACO num ensemble (intenção
   original do bubble_scoring), talvez; como gatilho isolado, não.
2. **Levar o GSADF ao gate histórico.** É o único que discrimina em
   ground-truth. A pergunta que só o histórico responde: os crashes reais
   (dotcom/GFC/2020) têm o carácter explosivo que o GSADF apanha (a
   literatura PSY 2015 diz que sim), com que lead time e que taxa de
   falsos positivos em períodos calmos.
3. Nota de calibração: `bsadf` do AR sintético (78) é irrealista (ρ=1.03
   composto 52×); bolhas reais são mais suaves → `bsadf` real perto do
   limiar fixo 1.49. O walk-forward histórico é que calibra o limiar.

## Limite honesto

Sintético prova discriminação em DGP perfeito. Não prova nada sobre
crashes reais nem lead time. Nenhum detector isolado deve disparar
alertas com base só nisto — os alertas continuam (e bem) travados.
