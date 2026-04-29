# image-app-cla

Uses github actions to create images and push to dockerhub

**Resumo**
O sistema é LLM-centric com heurísticas de suporte:

LLMs fazem o trabalho pesado (análise, síntese, extração de entidades)
Embeddings + cosseno fazem a similaridade
Clustering greedy O(n²) agrupa artigos similares
Regras manuais fazem scoring/ranking/detecção temporal
Keyword matching classifica artigos em categorias



Técnicas Computacionais do Sistema:
1. **LLM (Large Language Models)** — Principal motor de análise
   
Componente	       Modelo	      Uso

**Agent (chat)**-	Claude Sonnet,	Conversação, raciocínio, tool use (loop de até 5 iterações).

**Pattern Matcher**-	Claude Sonnet,	Análise semântica de clusters de notícias → gera texto estruturado.

**News Analyzer**-	Claude Sonnet,	Análise causa-efeito de notícias relevantes.

**Crypto Scanner**-	Claude Sonnet,	Avaliação oportunidade/armadilha de criptomoedas.

**Digest**-    Claude Sonnet,	Síntese de dados brutos → briefing matinal/noturno.

**Fact Extractor**-	Claude Haiku,	Extração de entidades pessoais do usuário (forced tool use).

**Enrichment**-	    Claude Haiku,	Extração de entidades e tópicos de artigos.


Nenhum fine-tuning — tudo usa prompting com estrutura forçada (templates *PADRAO:*, *CAUSA RAIZ:*, etc.).

**2. NLP / Embeddings** — Representação vetorial
Técnica	Implementação	Arquivo
Embeddings semânticos	Voyage AI API	embeddings.py
TF-IDF fallback	scikit-learn (local)	embeddings.py
Similaridade cosseno	NumPy (dot product / norms)	embeddings.py
Usado para calcular similaridade entre artigos antes do clustering.

**3. Clustering** — Detecção de padrões
Algoritmo: Greedy single-pass clustering (pattern_matcher.py:_cluster_articles)

para cada artigo i (não atribuído):
    criar cluster [i]
    para cada artigo j > i (não atribuído):
        se similaridade(i, j) >= threshold:
            adicionar j ao cluster
    se cluster tem 2+ artigos → guardar
Isso é um single-linkage greedy — não é K-means, DBSCAN, nem hierárquico. É um algoritmo simples O(n²) que agrupa por similaridade direta ao primeiro elemento do cluster.

**Thresholds:**

**Semântico (Voyage)**: 0.50 (ou 0.35 com boost de entidades)
**TF-IDF fallback:** 0.30
**Mínimo 2 fontes distintas** = "strong pattern"


**4. Scoring / Ranking**— Algoritmos baseados em regras
Relevance Filter (relevance_filter.py) — Score 0-100 com 5 componentes:

.Pattern match score (artigo aparece em cluster?)
.Cross-source score (coberto por múltiplas fontes?)
.Entity overlap score (entidades compartilhadas)
.User interest score (match com fatos do usuário)
.Base quality score (peso da fonte)


**Trend Scorer (trend_scorer.py)** — Score 0-100 por categoria:

Contagem ponderada de artigos (fontes premium peso 3x, médias 2x)
Normalização e detecção de tendência (rising/falling/stable)
Ambos são heurísticas manuais, não machine learning.

**5. Detecção Temporal**— Estatística descritiva
Acceleration (temporal.py):

ratio = artigos_nas_últimas_12h / (média_7_dias × 12h)
se ratio >= 2.0 e diff_absoluta >= 3 → "acelerando"
se ratio <= 0.3 → "desacelerando"
Divergence (temporal.py):

source_ratio = fontes_recentes_avg / fontes_baseline_avg
se |source_ratio - 1.0| >= 0.4 → "divergindo"
Isso é detecção de anomalia por limiar fixo — não usa z-score, desvio padrão, nem modelos estatísticos mais sofisticados.

**6. Extração de informação** — Keyword matching
Classificação de artigos (pattern_matcher.py:_classify_article):

Simples if keyword in text — sem regex, sem NER, sem modelo

Entity/Topic matching (enrichment.py:entity_topic_score):

Overlap de conjuntos (Jaccard-like) entre entidades extraídas pelo Haiku.


O que NÃO está sendo usado:
Técnica	Status
Redes neurais treinadas/fine-tuned	Nenhuma
Classificação supervisionada (SVM, Random Forest)	Nenhuma
Deep learning próprio	Nenhum
Grafos de conhecimento (knowledge graphs)	Nenhum (o mapa é visual, não um grafo real)
Sentiment analysis dedicado	Nenhum (o LLM faz implicitamente)
Time series forecasting (ARIMA, Prophet)	Nenhum
Reinforcement learning	Nenhum
Data mining formal (Apriori, FP-Growth)	Nenhum




