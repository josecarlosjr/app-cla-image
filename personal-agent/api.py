import os
import json
import time
import logging
from datetime import datetime

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database as db

from log_config import setup_logging

setup_logging()

DATA_DIR = os.getenv("DATA_DIR", "/data")

os.makedirs(DATA_DIR, exist_ok=True)

logger = logging.getLogger(__name__)

app = FastAPI(title="Personal Intelligence Agent API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8080",
        "https://dashboard.local",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers: read JSON files from PVC
# ---------------------------------------------------------------------------

def _read_json(filename: str) -> list | dict:
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def _write_json(filename: str, data):
    path = os.path.join(DATA_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class JobCreate(BaseModel):
    company: str
    role: str
    url: str = ""
    status: str = "applied"
    notes: str = ""


class JobUpdate(BaseModel):
    status: str
    notes: str = ""


class ChatMessage(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# GET /api/prices — current BTC/ETH/Brent/Gold
# ---------------------------------------------------------------------------

_movers_cache: dict = {"data": None, "expires": 0.0}
MOVERS_TTL = 300


@app.get("/api/crypto/movers")
async def get_crypto_movers():
    now = time.time()
    if _movers_cache["data"] and now < _movers_cache["expires"]:
        return _movers_cache["data"]

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.coingecko.com/api/v3/coins/markets",
                params={
                    "vs_currency": "usd",
                    "order": "market_cap_desc",
                    "per_page": 250,
                    "page": 1,
                    "sparkline": "false",
                    "price_change_percentage": "1h,24h,7d",
                },
            )
            resp.raise_for_status()
            coins = resp.json()
    except Exception as e:
        logger.warning("CoinGecko movers error: %s", e)
        if _movers_cache["data"]:
            return _movers_cache["data"]
        return {"gainers": [], "losers": [], "updated_at": None}

    for c in coins:
        c["_change_1h"] = c.get("price_change_percentage_1h_in_currency") or 0

    valid = [c for c in coins if c.get("current_price") is not None]
    by_change = sorted(valid, key=lambda x: x["_change_1h"], reverse=True)

    def _slim(c: dict) -> dict:
        return {
            "id": c.get("id", ""),
            "name": c.get("name", ""),
            "symbol": (c.get("symbol") or "").upper(),
            "image": c.get("image", ""),
            "price_usd": c.get("current_price", 0),
            "change_1h": c.get("_change_1h", 0),
            "change_24h": c.get("price_change_percentage_24h") or 0,
            "change_7d": c.get("price_change_percentage_7d_in_currency") or 0,
            "market_cap": c.get("market_cap", 0),
            "market_cap_rank": c.get("market_cap_rank"),
            "volume_24h": c.get("total_volume", 0),
        }

    result = {
        "gainers": [_slim(c) for c in by_change[:10]],
        "losers": [_slim(c) for c in by_change[-10:]],
        "updated_at": datetime.now().isoformat(),
    }
    _movers_cache["data"] = result
    _movers_cache["expires"] = now + MOVERS_TTL
    return result


@app.get("/api/prices")
async def get_prices():
    prices = {}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.coingecko.com/api/v3/simple/price",
                params={
                    "ids": "bitcoin,ethereum",
                    "vs_currencies": "usd,eur",
                    "include_24hr_change": "true",
                },
            )
            data = resp.json()
            for coin in ("bitcoin", "ethereum"):
                if coin in data:
                    prices[coin] = data[coin]
    except Exception as e:
        logger.warning("CoinGecko error: %s", e)

    monitor_state = _read_json("monitor_state.json")
    if isinstance(monitor_state, dict):
        lp = monitor_state.get("last_prices", {})
        if "brent" in lp:
            prices["brent"] = {"usd": lp["brent"]}
        if "gold" in lp:
            prices["gold"] = {"usd": lp["gold"]}

    return {"prices": prices, "updated_at": datetime.now().isoformat()}


# ---------------------------------------------------------------------------
# GET /api/alerts — monitor alerts
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
async def get_alerts():
    state = _read_json("monitor_state.json")
    if isinstance(state, dict):
        return {
            "last_alerts": state.get("last_alerts", {}),
            "last_prices": state.get("last_prices", {}),
        }
    return {"last_alerts": {}, "last_prices": {}}


# ---------------------------------------------------------------------------
# POST /api/feeds/refresh — on-demand feed fetch + scoring
# ---------------------------------------------------------------------------

@app.post("/api/feeds/refresh")
async def refresh_feeds():
    from feeds import FeedManager
    from trend_scorer import calculate_scores, calculate_connections
    from relevance_filter import score_articles, save_scored

    fm = FeedManager()
    new_articles = await fm.fetch_all()
    all_articles = fm.get_all_cached()

    scores = calculate_scores(all_articles)
    patterns = db.get_patterns()
    connections = calculate_connections(patterns)

    output = dict(scores)
    output["connections"] = connections
    output["updated_at"] = datetime.now().isoformat()
    db.save_trend_scores(output)

    scored = await score_articles(all_articles, patterns)
    save_scored(scored)

    return {
        "new_articles": len(new_articles),
        "total_cached": len(all_articles),
        "scored": len(scored),
    }


# ---------------------------------------------------------------------------
# POST /api/patterns/detect — on-demand pattern detection (uses LLM)
# ---------------------------------------------------------------------------

@app.post("/api/patterns/detect")
async def detect_patterns():
    from pattern_matcher import detect_patterns_on_demand
    from trend_scorer import calculate_connections
    result = await detect_patterns_on_demand()

    if result.get("new_patterns", 0) > 0:
        patterns = db.get_patterns()
        connections = calculate_connections(patterns)
        scores = db.get_trend_scores_data() or {}
        scores["connections"] = connections
        scores["updated_at"] = datetime.now().isoformat()
        db.save_trend_scores(scores)

    return result


# ---------------------------------------------------------------------------
# GET /api/crypto/trending — crypto scanner results
# ---------------------------------------------------------------------------

@app.get("/api/crypto/trending")
async def get_crypto_trending():
    scans = _read_json("crypto_scan.json")
    if isinstance(scans, list):
        return {"scans": scans[-20:], "total": len(scans)}
    return {"scans": [], "total": 0}


# ---------------------------------------------------------------------------
# GET /api/news — feed articles
# ---------------------------------------------------------------------------

@app.get("/api/news")
async def get_news(category: str = Query("", description="Filter by category")):
    articles = db.get_articles(scored_only=True, category=category or "")
    if not articles:
        articles = db.get_articles(category=category or "")
    return {"articles": articles[:100], "total": len(articles)}


# ---------------------------------------------------------------------------
# GET /api/news/analysis — processed news analyses
# ---------------------------------------------------------------------------

@app.get("/api/news/analysis")
async def get_news_analysis():
    data = _read_json("analyzed_news.json")
    if isinstance(data, dict):
        return {
            "analyzed_urls": len(data.get("analyzed_urls", [])),
            "last_run": data.get("last_run"),
        }
    return {"analyzed_urls": 0, "last_run": None}


# ---------------------------------------------------------------------------
# GET /api/patterns — pattern matcher results
# ---------------------------------------------------------------------------

@app.get("/api/patterns")
async def get_patterns(
    confidence: str = Query("", description="ALTA, MEDIA, BAIXA"),
    category: str = Query("", description="Filter by category (e.g. chips_ia, financas)"),
):
    patterns = db.get_patterns(confidence=confidence, category=category)
    return {"patterns": patterns[:20], "total": len(patterns)}


# ---------------------------------------------------------------------------
# GET /api/trends — trend scores for map
# ---------------------------------------------------------------------------

@app.get("/api/trends")
async def get_trends():
    scores = db.get_trend_scores_data()
    if scores:
        return scores
    return {"updated_at": None}


# ---------------------------------------------------------------------------
# GET /api/map/nodes — map nodes + connections for SVG
# ---------------------------------------------------------------------------

@app.get("/api/map/nodes")
async def get_map_nodes():
    scores = db.get_trend_scores_data()
    if not scores:
        return {"nodes": [], "connections": []}

    nodes = []
    for cat in [
        "chips_ia", "energia", "minerais", "geopolitica",
        "ciberseguranca", "ciencia", "espaco_defesa", "financas",
        "cadeia_suprimentos",
    ]:
        info = scores.get(cat, {})
        nodes.append({
            "id": cat,
            "score": info.get("score", 0),
            "trend": info.get("trend", "stable"),
            "articles": info.get("articles", 0),
        })

    connections = scores.get("connections", [])
    return {"nodes": nodes, "connections": connections}


# ---------------------------------------------------------------------------
# GET /api/temporal — acceleration & divergence detection (F5a)
# ---------------------------------------------------------------------------

@app.get("/api/temporal")
async def get_temporal():
    from temporal import get_temporal_summary
    return get_temporal_summary()


# ---------------------------------------------------------------------------
# Jobs CRUD
# ---------------------------------------------------------------------------

@app.get("/api/jobs")
async def get_jobs():
    jobs = _read_json("jobs_tracker.json")
    if not isinstance(jobs, list):
        jobs = []
    return {"jobs": jobs, "total": len(jobs)}


@app.post("/api/jobs")
async def create_job(job: JobCreate):
    jobs = _read_json("jobs_tracker.json")
    if not isinstance(jobs, list):
        jobs = []
    job_id = len(jobs) + 1
    new_job = {
        "id": job_id,
        "company": job.company,
        "role": job.role,
        "url": job.url,
        "status": job.status,
        "notes": job.notes,
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
    }
    jobs.append(new_job)
    _write_json("jobs_tracker.json", jobs)
    return new_job


@app.put("/api/jobs/{job_id}")
async def update_job(job_id: int, update: JobUpdate):
    jobs = _read_json("jobs_tracker.json")
    if not isinstance(jobs, list):
        raise HTTPException(404, "No jobs found")
    for j in jobs:
        if j["id"] == job_id:
            j["status"] = update.status
            if update.notes:
                j["notes"] = update.notes
            j["updated"] = datetime.now().isoformat()
            _write_json("jobs_tracker.json", jobs)
            return j
    raise HTTPException(404, f"Job {job_id} not found")


# ---------------------------------------------------------------------------
# POST /api/agent/chat — interact with the agent
# ---------------------------------------------------------------------------

@app.post("/api/agent/chat")
async def agent_chat(msg: ChatMessage):
    from agent import process_message
    from memory import Memory

    memory = Memory()
    try:
        response = await process_message(msg.message, memory)
        return {"response": response}
    except Exception as e:
        logger.error("Agent chat error: %s", e)
        raise HTTPException(500, f"Agent error: {e}")


# ---------------------------------------------------------------------------
# GET /api/memory/stats
# ---------------------------------------------------------------------------

@app.get("/api/memory/stats")
async def get_memory_stats():
    data = _read_json("memory.json")
    if isinstance(data, dict):
        history = data.get("history", [])
        facts = data.get("facts", [])
        user_msgs = sum(1 for m in history if m.get("role") == "user")
        assistant_msgs = sum(1 for m in history if m.get("role") == "assistant")
        return {
            "total_messages": len(history),
            "user_messages": user_msgs,
            "assistant_messages": assistant_msgs,
            "facts_count": len(facts),
            "facts": facts,
        }
    return {"total_messages": 0, "user_messages": 0, "assistant_messages": 0, "facts_count": 0, "facts": []}


# ---------------------------------------------------------------------------
# GET /api/supply-chain — full knowledge graph with mention signals
# ---------------------------------------------------------------------------

@app.get("/api/supply-chain")
async def get_supply_chain():
    from supply_chain import get_full_graph
    return get_full_graph()


@app.post("/api/supply-chain/extract")
async def extract_supply_chain_mentions():
    from supply_chain_extractor import extract_mentions
    result = await extract_mentions()
    return result


@app.get("/api/supply-chain/analysis")
async def get_supply_chain_analysis():
    from supply_chain_analyzer import analyze
    return analyze()


@app.get("/api/supply-chain/impact/{node_id}")
async def get_supply_chain_impact(node_id: str):
    from supply_chain import get_impact_chain, get_dependents, get_dependencies
    return {
        "node_id": node_id,
        "impact_chain": get_impact_chain(node_id),
        "dependents": get_dependents(node_id),
        "dependencies": get_dependencies(node_id),
    }


@app.get("/api/supply-chain/mentions")
async def get_supply_chain_mentions_api(
    node_id: str = Query("", description="Filter by node"),
    hours: int = Query(168, description="Lookback window in hours"),
):
    mentions = db.get_supply_chain_mentions(node_id=node_id, hours=hours)
    counts = db.get_supply_chain_mention_counts(hours=hours)
    return {"mentions": mentions[:100], "counts": counts}


# ---------------------------------------------------------------------------
# GET /api/cross-pillar — chain detections (Onda 9)
# ---------------------------------------------------------------------------

@app.get("/api/cross-pillar/chains")
async def get_cross_pillar_chains(
    hours: int = Query(168, description="Lookback window in hours"),
    limit: int = Query(20, description="Max chains returned"),
):
    return {"chains": db.get_cross_pillar_chains(hours=hours, limit=limit)}


# ---------------------------------------------------------------------------
# Backtest, Snapshots & Outcomes (Onda 11)
# ---------------------------------------------------------------------------

class OutcomeBody(BaseModel):
    outcome: str  # true_positive | false_positive | unclear
    notes: str = ""
    event_timestamp: str = ""


class BacktestBody(BaseModel):
    days_back: int = 30
    eval_step_hours: int = 24
    pattern_lookback_hours: int = 48


@app.post("/api/backtest/run")
async def run_backtest_endpoint(body: BacktestBody):
    from backtest import run_backtest
    days = max(1, min(body.days_back, 365))
    try:
        return run_backtest(
            days_back=days,
            eval_step_hours=max(1, body.eval_step_hours),
            pattern_lookback_hours=max(1, body.pattern_lookback_hours),
        )
    except Exception as e:
        logger.error("Backtest run failed: %s", e)
        raise HTTPException(500, f"Backtest failed: {e}")


@app.get("/api/backtest/runs")
async def list_backtest_runs(limit: int = Query(20, description="Max runs returned")):
    return {"runs": db.get_backtest_runs(limit=limit)}


@app.get("/api/backtest/runs/{run_id}")
async def get_backtest_run_detail(run_id: int):
    run = db.get_backtest_run(run_id)
    if not run:
        raise HTTPException(404, f"Backtest run {run_id} not found")
    return run


@app.post("/api/snapshots/capture")
async def trigger_snapshot_capture():
    from backtest import capture_snapshots
    try:
        return {"captured": capture_snapshots()}
    except Exception as e:
        logger.error("Snapshot capture failed: %s", e)
        raise HTTPException(500, f"Snapshot capture failed: {e}")


@app.get("/api/snapshots")
async def get_snapshots_endpoint(
    snapshot_type: str = Query("", description="Filter: trends, cross_pillar, supply_chain, graph"),
    days: int = Query(30, description="Lookback in days"),
    limit: int = Query(50, description="Max snapshots"),
):
    return {
        "snapshots": db.get_snapshots(
            snapshot_type=snapshot_type, days=days, limit=limit,
        ),
    }


@app.post("/api/outcomes/{event_type}/{event_id}")
async def mark_outcome(event_type: str, event_id: str, body: OutcomeBody):
    if body.outcome not in ("true_positive", "false_positive", "unclear"):
        raise HTTPException(
            400, "outcome must be true_positive, false_positive or unclear",
        )
    oid = db.upsert_outcome(
        event_type=event_type,
        event_id=event_id,
        outcome=body.outcome,
        notes=body.notes,
        event_timestamp=body.event_timestamp,
    )
    return {"id": oid, "event_type": event_type, "event_id": event_id,
            "outcome": body.outcome}


@app.get("/api/outcomes")
async def list_outcomes(
    event_type: str = Query("", description="Filter by event type"),
    outcome: str = Query("", description="Filter by outcome"),
    limit: int = Query(200, description="Max outcomes"),
):
    return {
        "outcomes": db.get_outcomes(
            event_type=event_type, outcome=outcome, limit=limit,
        ),
    }


@app.get("/api/metrics/quality")
async def get_quality_metrics_endpoint(
    days: int = Query(90, description="Lookback in days"),
):
    return db.get_quality_metrics(days=days)


# ---------------------------------------------------------------------------
# Dynamic Knowledge Graph (Onda 10)
# ---------------------------------------------------------------------------

class ReviewAction(BaseModel):
    action: str  # "approve" or "reject"


@app.get("/api/graph/stats")
async def get_graph_stats():
    return db.get_graph_stats()


@app.get("/api/graph/entities")
async def get_graph_entities(
    status: str = Query("", description="Filter: staged, approved, rejected"),
    entity_type: str = Query("", description="Filter by entity type"),
    limit: int = Query(100, description="Max results"),
):
    entities = db.get_graph_entities(
        status=status, entity_type=entity_type, limit=limit,
    )
    return {"entities": entities, "total": len(entities)}


@app.get("/api/graph/relationships")
async def get_graph_relationships(
    status: str = Query("", description="Filter: staged, approved, rejected"),
    limit: int = Query(100, description="Max results"),
):
    rels = db.get_graph_relationships(status=status, limit=limit)
    return {"relationships": rels, "total": len(rels)}


@app.post("/api/graph/entities/{entity_id}/review")
async def review_graph_entity(entity_id: int, body: ReviewAction):
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action must be 'approve' or 'reject'")
    ok = db.update_graph_entity_status(entity_id, body.action + "d")
    if not ok:
        raise HTTPException(404, f"Entity {entity_id} not found")
    return {"id": entity_id, "status": body.action + "d"}


@app.post("/api/graph/relationships/{rel_id}/review")
async def review_graph_relationship(rel_id: int, body: ReviewAction):
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action must be 'approve' or 'reject'")
    ok = db.update_graph_relationship_status(rel_id, body.action + "d")
    if not ok:
        raise HTTPException(404, f"Relationship {rel_id} not found")
    return {"id": rel_id, "status": body.action + "d"}


@app.post("/api/graph/entities/batch-review")
async def batch_review_entities(body: dict):
    action = body.get("action", "")
    ids = body.get("ids", [])
    if action not in ("approve", "reject") or not ids:
        raise HTTPException(400, "Need action (approve/reject) and ids[]")
    status = action + "d"
    count = 0
    for eid in ids:
        if db.update_graph_entity_status(int(eid), status):
            count += 1
    return {"updated": count, "status": status}


@app.post("/api/graph/relationships/batch-review")
async def batch_review_relationships(body: dict):
    action = body.get("action", "")
    ids = body.get("ids", [])
    if action not in ("approve", "reject") or not ids:
        raise HTTPException(400, "Need action (approve/reject) and ids[]")
    status = action + "d"
    count = 0
    for rid in ids:
        if db.update_graph_relationship_status(int(rid), status):
            count += 1
    return {"updated": count, "status": status}


@app.post("/api/graph/extract")
async def trigger_graph_extraction():
    from graph_extractor import extract_graph_triples
    try:
        result = await extract_graph_triples()
        return result
    except Exception as e:
        logger.error("Graph extraction failed: %s", e)
        raise HTTPException(500, f"Graph extraction failed: {e}")


@app.get("/api/graph/full")
async def get_full_graph():
    return db.get_graph_for_display(status="approved")


# ---------------------------------------------------------------------------
# Cross-pillar chains (Onda 9)
# ---------------------------------------------------------------------------

@app.get("/api/cross-pillar/active")
async def get_cross_pillar_active(
    window_hours: int = Query(168, description="Window for live event collection"),
):
    """Live detection — runs detect_chains without persistence."""
    from cross_pillar import detect_chains
    from pillars import PILLAR_LABELS
    chains = detect_chains(window_hours=window_hours)
    return {
        "chains": chains,
        "pillar_labels": PILLAR_LABELS,
        "window_hours": window_hours,
    }


# ---------------------------------------------------------------------------
# Entry point for standalone testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
