# Personal Intelligence Agent — Architecture

## System Overview

```mermaid
flowchart TB
    classDef source fill:#dbeafe,stroke:#1e40af,color:#1e3a5f
    classDef process fill:#f3e8ff,stroke:#6b21a8,color:#3b0764
    classDef llm fill:#fef3c7,stroke:#d97706,color:#78350f
    classDef store fill:#d1fae5,stroke:#047857,color:#064e3b
    classDef output fill:#ffe4e6,stroke:#be123c,color:#881337
    classDef cron fill:#f1f5f9,stroke:#64748b,color:#334155,stroke-dasharray: 5 5

    subgraph SOURCES["DATA SOURCES — 37 RSS Feeds + APIs"]
        direction LR
        S_TECH["TECNOLOGIA_IA (9)\nACM · IEEE · TechCrunch\nArs Technica · HN\nReddit r/technology"]:::source
        S_CYBER["CIBERSEGURANCA (5)\nHacker News · Dark Reading\nCISA · Bleeping Computer\narXiv CS.CR"]:::source
        S_MARKET["MERCADOS (6)\nCNBC · MarketWatch\nSeeking Alpha · Nasdaq\nReddit r/stocks · r/investing"]:::source
        S_OTHER["GEO + SCI + SPACE\n+ DEVOPS (17)\nBBC · Reuters · G1\narXiv AI · SpaceNews\nDZone · The New Stack"]:::source
        S_CRYPTO["CoinGecko API\nTop 250 coins\nBTC · ETH · Brent · Gold"]:::source
    end

    subgraph INGESTION["INGESTION LAYER"]
        FM["FeedManager\n(feeds.py)\nasync httpx · XML/Atom parser\nUser-Agent · 15 per feed"]:::process
        CS["Crypto Scanner\n(crypto_scanner.py)\nprice alerts · watchlist"]:::process
    end

    subgraph ENRICHMENT["ENRICHMENT LAYER"]
        direction LR
        ENR["Entity / Topic Extraction\n(enrichment.py)\nHaiku · ~$4/mo\ncached by URL"]:::llm
        EMB["Semantic Embeddings\n(embeddings.py)\nVoyage AI · TF-IDF fallback\ncached in SQLite"]:::llm
    end

    subgraph ANALYSIS["ANALYSIS LAYER"]
        direction LR
        PM["Pattern Matcher\n(pattern_matcher.py)\ncluster → Claude Sonnet\n~$7/mo · ALTA/MEDIA/BAIXA"]:::llm
        RF["Relevance Filter\n(relevance_filter.py)\n5-component scoring 0-100\npattern + cross-source +\nentity + user interest + base"]:::process
        TS["Trend Scorer\n(trend_scorer.py)\n8 categories\nweighted article counts"]:::process
        TMP["Temporal Detection\n(temporal.py) — F5a\nacceleration · divergence\n$0/mo"]:::process
    end

    subgraph DB["SQLite — agent.db (WAL mode)"]
        direction LR
        DB_ART[("articles\n3000 max\nURL primary key")]:::store
        DB_PAT[("patterns\n100 max\nwith analysis")]:::store
        DB_ENR[("enrichments\n5000 cache\nentities+topics")]:::store
        DB_EMB[("embeddings\nvector BLOB\nmodel-keyed")]:::store
        DB_TMP[("temporal\n30 days\nhourly buckets")]:::store
        DB_TRD[("trend_scores\ncurrent state")]:::store
    end

    subgraph AGENT_CORE["AGENT CORE"]
        BOT["Telegram Bot\n(bot.py)\npolling · user whitelist\n/start /stats /help"]:::output
        AGENT["Agent\n(agent.py)\nClaude Sonnet · tool loop\nmax 5 iterations\n12 tools available"]:::llm
        MEM["Memory\n(memory.py)\nhistory + facts\nJSON persistent"]:::store
    end

    subgraph API_LAYER["REST API — FastAPI port 8000"]
        direction LR
        API_DATA["Data Endpoints (12 GET)\n/news · /patterns · /trends\n/temporal · /prices · /alerts\n/map/nodes · /crypto/movers\n/crypto/trending · /jobs\n/memory/stats · /news/analysis"]:::output
        API_ACT["Action Endpoints\n(4 POST + 1 PUT)\n/feeds/refresh\n/patterns/detect\n/agent/chat\n/jobs · /jobs/:id"]:::output
    end

    subgraph OUTPUTS["OUTPUTS"]
        direction LR
        DIGEST_OUT["Digest\n(digest.py)\nSonnet · ~$2/mo\nmorning 9h · evening 21h"]:::llm
        NOTIFY_OUT["Notifications\n(notifications.py)\njobs · patterns · temporal\ncooldown anti-spam"]:::process
        DASH["Dashboard\n(frontend)\napp-cla repo\nK8s deployed"]:::output
    end

    subgraph CRONS["CronJobs (K8s)"]
        direction TB
        CR1["news_analyzer\n⏰ 9h · 14h · 21h"]:::cron
        CR2["crypto_scanner\n⏰ every hour (:30)"]:::cron
        CR3["pattern_matcher\n+ trend_scorer\n⏰ 10h · 18h"]:::cron
        CR4["digest\n⏰ 9h morning\n⏰ 21h evening"]:::cron
        CR5["notifications\n⏰ every 4 hours"]:::cron
    end

    %% Data flow
    S_TECH & S_CYBER & S_MARKET & S_OTHER --> FM
    S_CRYPTO --> CS

    FM -->|"new articles"| DB_ART
    FM -->|"hourly stats"| TMP
    CS -->|"price data"| MEM

    DB_ART -->|"uncached articles"| ENR
    DB_ART -->|"article texts"| EMB
    ENR -->|"entities + topics"| DB_ENR
    EMB -->|"vectors"| DB_EMB

    DB_ENR & DB_EMB -->|"hybrid similarity"| PM
    PM -->|"analysed patterns"| DB_PAT
    DB_ART & DB_PAT -->|"score inputs"| RF
    RF -->|"scored articles"| DB_ART
    DB_ART & DB_PAT -->|"category counts"| TS
    TS --> DB_TRD
    TMP --> DB_TMP

    %% CronJob triggers
    CR1 -.->|triggers| FM
    CR1 -.->|triggers| RF
    CR2 -.->|triggers| CS
    CR3 -.->|triggers| PM
    CR3 -.->|triggers| TS
    CR4 -.->|triggers| DIGEST_OUT
    CR5 -.->|triggers| NOTIFY_OUT

    %% Agent flow
    BOT <-->|"user messages"| AGENT
    AGENT <-->|"history + facts"| MEM

    %% Output connections
    DB_ART & DB_PAT & DB_TRD & DB_TMP --> API_DATA
    API_DATA --> DASH
    API_ACT -->|"on-demand"| FM
    API_ACT -->|"on-demand"| PM

    DIGEST_OUT -->|"Telegram"| BOT
    NOTIFY_OUT -->|"Telegram"| BOT
    PM -->|"ALTA confidence"| BOT
```

## Data Flow — Article Lifecycle

```mermaid
flowchart LR
    classDef step fill:#f3e8ff,stroke:#6b21a8,color:#3b0764
    classDef decision fill:#fef3c7,stroke:#d97706,color:#78350f
    classDef store fill:#d1fae5,stroke:#047857,color:#064e3b

    A["RSS Feed\n(37 sources)"]:::step
    --> B["FeedManager\nfetch + parse"]:::step
    --> C{"URL exists\nin DB?"}:::decision

    C -->|"Yes"| D["Skip\n(INSERT OR IGNORE)"]:::step
    C -->|"No"| E["Store in\narticles table"]:::store

    E --> F["Record temporal\nsnapshot"]:::step
    E --> G["Enrich\n(Haiku)\nentities + topics"]:::step
    E --> H["Embed\n(Voyage AI)\nsemantic vector"]:::step

    G & H --> I["Pattern Matcher\ncluster similar articles\n2+ sources = strong"]:::step
    I --> J{"Strong\npattern?"}:::decision

    J -->|"No"| K["Skip"]:::step
    J -->|"Yes"| L["Analyse with\nClaude Sonnet\nALTA/MEDIA/BAIXA"]:::step

    L --> M["Store pattern\nin DB"]:::store
    L --> N{"ALTA\nconfidence?"}:::decision

    N -->|"Yes"| O["Telegram\nalert 🔔"]:::step
    N -->|"No"| P["Available\nvia API"]:::step

    E --> Q["Relevance\nFilter\nscore 0-100"]:::step
    Q --> R["Update article\nscore in DB"]:::store
    R --> S["Dashboard\n📊"]:::step
```

## Cost Summary

```
┌──────────────────────────────────────────────────┐
│          Monthly Cost Breakdown (~$15)            │
├──────────────────────┬──────────┬────────────────┤
│ Component            │ Model    │ Cost/month     │
├──────────────────────┼──────────┼────────────────┤
│ Pattern Matcher      │ Sonnet   │ ~$7.20         │
│ Enrichment           │ Haiku    │ ~$3.60         │
│ Digest (2x/day)      │ Sonnet   │ ~$2.00         │
│ News Analyzer alerts │ Sonnet   │ ~$1.50         │
│ Crypto alerts        │ Sonnet   │ ~$0.70         │
├──────────────────────┼──────────┼────────────────┤
│ Temporal (F5a)       │ Python   │ $0.00          │
│ Trend Scorer         │ Python   │ $0.00          │
│ Relevance Filter     │ Python   │ $0.00          │
│ Voyage AI embeddings │ API      │ $0.00 (free)   │
├──────────────────────┼──────────┼────────────────┤
│ TOTAL                │          │ ~$15/month     │
└──────────────────────┴──────────┴────────────────┘
```

## Infrastructure

```
┌─ Kubernetes Cluster ─────────────────────────────┐
│                                                   │
│  ┌─ Namespace: personal-agent ─────────────────┐ │
│  │                                              │ │
│  │  Deployment: personal-agent (1 replica)      │ │
│  │  ├── Container: agent                        │ │
│  │  │   ├── Image: app-cla-agent:sha-xxxxx      │ │
│  │  │   ├── CMD: python bot.py                  │ │
│  │  │   ├── Port: 8000 (FastAPI)                │ │
│  │  │   ├── CPU: 100m-500m                      │ │
│  │  │   └── RAM: 128Mi-512Mi                    │ │
│  │  └── Volume: agent-data (PVC)                │ │
│  │      └── /data/agent.db (SQLite + WAL)       │ │
│  │                                              │ │
│  │  Service: agent-api (ClusterIP:8000)         │ │
│  │                                              │ │
│  │  CronJobs: 5 scheduled tasks                 │ │
│  │  ├── news_analyzer   (9h, 14h, 21h)         │ │
│  │  ├── crypto_scanner  (every hour)            │ │
│  │  ├── pattern_matcher (10h, 18h)              │ │
│  │  ├── digest          (9h, 21h)               │ │
│  │  └── notifications   (every 4h)              │ │
│  │                                              │ │
│  │  Secrets: agent-secrets (SOPS + age)         │ │
│  │  ├── ANTHROPIC_API_KEY                       │ │
│  │  ├── TELEGRAM_BOT_TOKEN                      │ │
│  │  ├── TELEGRAM_ALLOWED_USER_ID                │ │
│  │  └── VOYAGE_API_KEY (optional)               │ │
│  └──────────────────────────────────────────────┘ │
│                                                   │
│  ┌─ Namespace: personal-agent (frontend) ───────┐ │
│  │  Deployment: backend (Go API proxy)          │ │
│  │  Deployment: frontend (React dashboard)      │ │
│  │  Ingress: dashboard.local                    │ │
│  └──────────────────────────────────────────────┘ │
│                                                   │
│  ArgoCD: auto-sync from github.com/josecarlosjr  │
│  ├── app-cla (K8s manifests + KSOPS)             │
│  └── app-cla-image (Docker image source)         │
└───────────────────────────────────────────────────┘
```
