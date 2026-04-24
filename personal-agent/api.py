import os
import json
import time
import logging
from datetime import datetime

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DATA_DIR = os.getenv("DATA_DIR", "/data")
LOG_FILE = os.path.join(DATA_DIR, "agent.log")

os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
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
    scored = _read_json("feeds_scored.json")
    if isinstance(scored, list) and scored:
        articles = scored
    else:
        articles = _read_json("feeds_cache.json")
        if not isinstance(articles, list):
            articles = []
    if category:
        articles = [a for a in articles if a.get("category") == category]
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
async def get_patterns(confidence: str = Query("", description="ALTA, MEDIA, BAIXA")):
    patterns = _read_json("patterns.json")
    if not isinstance(patterns, list):
        patterns = []
    if confidence:
        patterns = [p for p in patterns if p.get("confidence") == confidence.upper()]
    return {"patterns": patterns[-20:], "total": len(patterns)}


# ---------------------------------------------------------------------------
# GET /api/trends — trend scores for map
# ---------------------------------------------------------------------------

@app.get("/api/trends")
async def get_trends():
    scores = _read_json("trend_scores.json")
    if isinstance(scores, dict):
        return scores
    return {"updated_at": None}


# ---------------------------------------------------------------------------
# GET /api/map/nodes — map nodes + connections for SVG
# ---------------------------------------------------------------------------

@app.get("/api/map/nodes")
async def get_map_nodes():
    scores = _read_json("trend_scores.json")
    if not isinstance(scores, dict):
        return {"nodes": [], "connections": []}

    nodes = []
    for cat in [
        "chips_ia", "energia", "minerais", "geopolitica",
        "ciberseguranca", "ciencia", "espaco_defesa", "financas",
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
# Entry point for standalone testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
