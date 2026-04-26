"""SQLite persistence layer — replaces JSON file storage.

Single database at $DATA_DIR/agent.db with WAL mode for concurrent reads.
Auto-migrates from legacy JSON files on first run.

Tables:
    articles    — RSS articles with optional relevance scores
    patterns    — detected cross-source patterns
    enrichments — Haiku entity/topic extractions (URL-keyed cache)
    embeddings  — Voyage AI vectors (URL-keyed cache)
    trend_scores — category scores + connections
"""

import json
import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone

import numpy as np

DATA_DIR = os.getenv("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "agent.db")

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    url TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT DEFAULT '',
    source TEXT DEFAULT '',
    category TEXT DEFAULT '',
    published TEXT DEFAULT '',
    fetched_at TEXT NOT NULL,
    relevance_score INTEGER,
    relevance_trusted INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_articles_fetched ON articles(fetched_at);
CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source);
CREATE INDEX IF NOT EXISTS idx_articles_score ON articles(relevance_score);

CREATE TABLE IF NOT EXISTS patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    articles_json TEXT NOT NULL,
    categories_json TEXT NOT NULL,
    sources_json TEXT NOT NULL,
    num_sources INTEGER DEFAULT 0,
    analysis TEXT DEFAULT '',
    confidence TEXT DEFAULT 'MEDIA',
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_patterns_timestamp ON patterns(timestamp);
CREATE INDEX IF NOT EXISTS idx_patterns_confidence ON patterns(confidence);

CREATE TABLE IF NOT EXISTS enrichments (
    url TEXT PRIMARY KEY,
    entities_json TEXT NOT NULL,
    topics_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS embeddings (
    url TEXT PRIMARY KEY,
    vector BLOB NOT NULL,
    model TEXT NOT NULL,
    dims INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trend_scores (
    key TEXT PRIMARY KEY,
    data_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

# ---------------------------------------------------------------------------
# Connection singleton
# ---------------------------------------------------------------------------

_conn: sqlite3.Connection | None = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.executescript(_SCHEMA)
        _migrate_from_json()
    return _conn


# ---------------------------------------------------------------------------
# Articles
# ---------------------------------------------------------------------------

def upsert_articles(articles: list[dict]) -> list[dict]:
    """Insert articles, skip existing URLs. Returns newly inserted."""
    if not articles:
        return []
    conn = _db()
    new = []
    with conn:
        for a in articles:
            url = a.get("url", "")
            if not url:
                continue
            cursor = conn.execute(
                """INSERT OR IGNORE INTO articles
                   (url, title, summary, source, category, published, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (url, a.get("title", ""), a.get("summary", ""),
                 a.get("source", ""), a.get("category", ""),
                 a.get("published", ""), a.get("fetched_at", "")),
            )
            if cursor.rowcount > 0:
                new.append(a)
    return new


def get_articles(
    *,
    category: str = "",
    hours: int = 0,
    scored_only: bool = False,
    limit: int = 0,
) -> list[dict]:
    conn = _db()
    clauses: list[str] = []
    params: list = []

    if category:
        clauses.append("category = ?")
        params.append(category)
    if hours > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        clauses.append("fetched_at >= ?")
        params.append(cutoff)
    if scored_only:
        clauses.append("relevance_score IS NOT NULL")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order = "ORDER BY relevance_score DESC" if scored_only else "ORDER BY fetched_at DESC"
    limit_sql = f"LIMIT {int(limit)}" if limit > 0 else ""

    rows = conn.execute(
        f"SELECT * FROM articles {where} {order} {limit_sql}", params,
    ).fetchall()
    return [_row_to_article(r) for r in rows]


def update_article_scores(scored: list[dict]) -> None:
    conn = _db()
    with conn:
        for a in scored:
            url = a.get("url", "")
            if not url:
                continue
            conn.execute(
                "UPDATE articles SET relevance_score = ?, relevance_trusted = ? WHERE url = ?",
                (a.get("relevance_score"), int(a.get("relevance_trusted", False)), url),
            )


def clear_stale_scores(days: int = 7) -> None:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with conn:
        conn.execute(
            """UPDATE articles SET relevance_score = NULL, relevance_trusted = 0
               WHERE fetched_at < ? AND relevance_score IS NOT NULL""",
            (cutoff,),
        )


def prune_articles(max_rows: int = 2000) -> None:
    conn = _db()
    count = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    if count <= max_rows:
        return
    with conn:
        conn.execute(
            """DELETE FROM articles WHERE url NOT IN
               (SELECT url FROM articles ORDER BY fetched_at DESC LIMIT ?)""",
            (max_rows,),
        )
    logger.info("Pruned articles: %d → %d", count, max_rows)


def _row_to_article(row: sqlite3.Row) -> dict:
    d = dict(row)
    if d.get("relevance_trusted") is not None:
        d["relevance_trusted"] = bool(d["relevance_trusted"])
    return d


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

def insert_pattern(pattern: dict) -> None:
    conn = _db()
    with conn:
        conn.execute(
            """INSERT INTO patterns
               (articles_json, categories_json, sources_json, num_sources,
                analysis, confidence, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                json.dumps(pattern.get("articles", []), ensure_ascii=False),
                json.dumps(pattern.get("categories", []), ensure_ascii=False),
                json.dumps(pattern.get("sources", []), ensure_ascii=False),
                pattern.get("num_sources", 0),
                pattern.get("analysis", ""),
                pattern.get("confidence", "MEDIA"),
                pattern.get("timestamp", datetime.now(timezone.utc).isoformat()),
            ),
        )


def get_patterns(
    *,
    hours: int = 0,
    confidence: str = "",
    limit: int = 0,
) -> list[dict]:
    conn = _db()
    clauses: list[str] = []
    params: list = []

    if hours > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        clauses.append("timestamp >= ?")
        params.append(cutoff)
    if confidence:
        clauses.append("confidence = ?")
        params.append(confidence.upper())

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit_sql = f"LIMIT {int(limit)}" if limit > 0 else ""

    rows = conn.execute(
        f"SELECT * FROM patterns {where} ORDER BY timestamp DESC {limit_sql}",
        params,
    ).fetchall()
    return [_row_to_pattern(r) for r in rows]


def get_pattern_article_titles() -> set[str]:
    conn = _db()
    rows = conn.execute("SELECT articles_json FROM patterns").fetchall()
    titles: set[str] = set()
    for row in rows:
        for a in json.loads(row["articles_json"]):
            titles.add(a.get("title", ""))
    return titles


def prune_patterns(max_rows: int = 100) -> None:
    conn = _db()
    count = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    if count <= max_rows:
        return
    with conn:
        conn.execute(
            """DELETE FROM patterns WHERE id NOT IN
               (SELECT id FROM patterns ORDER BY timestamp DESC LIMIT ?)""",
            (max_rows,),
        )


def _row_to_pattern(row: sqlite3.Row) -> dict:
    return {
        "articles": json.loads(row["articles_json"]),
        "categories": json.loads(row["categories_json"]),
        "sources": json.loads(row["sources_json"]),
        "num_sources": row["num_sources"],
        "analysis": row["analysis"],
        "confidence": row["confidence"],
        "timestamp": row["timestamp"],
    }


# ---------------------------------------------------------------------------
# Enrichments
# ---------------------------------------------------------------------------

def get_enrichments_batch(urls: list[str]) -> dict[str, dict]:
    if not urls:
        return {}
    conn = _db()
    result: dict[str, dict] = {}
    for i in range(0, len(urls), 900):
        batch = urls[i : i + 900]
        placeholders = ",".join("?" * len(batch))
        rows = conn.execute(
            f"SELECT url, entities_json, topics_json FROM enrichments WHERE url IN ({placeholders})",
            batch,
        ).fetchall()
        for row in rows:
            result[row["url"]] = {
                "entities": json.loads(row["entities_json"]),
                "topics": json.loads(row["topics_json"]),
            }
    return result


def save_enrichment(url: str, entities: list[str], topics: list[str]) -> None:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """INSERT OR REPLACE INTO enrichments (url, entities_json, topics_json, created_at)
               VALUES (?, ?, ?, ?)""",
            (url, json.dumps(entities, ensure_ascii=False),
             json.dumps(topics, ensure_ascii=False), now),
        )


def prune_enrichments(max_entries: int = 5000) -> None:
    conn = _db()
    count = conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
    if count <= max_entries:
        return
    with conn:
        conn.execute(
            """DELETE FROM enrichments WHERE url NOT IN
               (SELECT url FROM enrichments ORDER BY created_at DESC LIMIT ?)""",
            (max_entries,),
        )


# ---------------------------------------------------------------------------
# Embeddings (vector cache)
# ---------------------------------------------------------------------------

def get_embeddings_batch(urls: list[str], model: str) -> dict[str, np.ndarray]:
    if not urls:
        return {}
    conn = _db()
    result: dict[str, np.ndarray] = {}
    for i in range(0, len(urls), 900):
        batch = urls[i : i + 900]
        placeholders = ",".join("?" * len(batch))
        rows = conn.execute(
            f"SELECT url, vector, dims FROM embeddings WHERE model = ? AND url IN ({placeholders})",
            [model] + batch,
        ).fetchall()
        for row in rows:
            vec = np.frombuffer(row["vector"], dtype=np.float32).copy()
            if vec.shape[0] == row["dims"]:
                result[row["url"]] = vec
    return result


def save_embeddings_batch(
    url_vector_pairs: list[tuple[str, np.ndarray]], model: str,
) -> None:
    if not url_vector_pairs:
        return
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.executemany(
            """INSERT OR REPLACE INTO embeddings (url, vector, model, dims, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            [(url, vec.tobytes(), model, vec.shape[0], now)
             for url, vec in url_vector_pairs],
        )


def prune_embeddings(max_entries: int = 10000) -> None:
    conn = _db()
    count = conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]
    if count <= max_entries:
        return
    with conn:
        conn.execute(
            """DELETE FROM embeddings WHERE url NOT IN
               (SELECT url FROM embeddings ORDER BY created_at DESC LIMIT ?)""",
            (max_entries,),
        )


# ---------------------------------------------------------------------------
# Trend Scores
# ---------------------------------------------------------------------------

def save_trend_scores(data: dict) -> None:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """INSERT OR REPLACE INTO trend_scores (key, data_json, updated_at)
               VALUES ('current', ?, ?)""",
            (json.dumps(data, ensure_ascii=False), now),
        )


def get_trend_scores_data() -> dict | None:
    conn = _db()
    row = conn.execute(
        "SELECT data_json FROM trend_scores WHERE key = 'current'",
    ).fetchone()
    if row:
        return json.loads(row["data_json"])
    return None


# ---------------------------------------------------------------------------
# JSON → SQLite migration (runs once when DB is first created)
# ---------------------------------------------------------------------------

def _migrate_from_json() -> None:
    global _conn
    conn = _conn
    if conn is None:
        return

    count = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    if count > 0:
        return

    logger.info("Migrating JSON files → SQLite...")

    # 1. feeds_cache.json → articles
    _migrate_file(conn, "feeds_cache.json", _import_articles_cache)

    # 2. feeds_scored.json → article scores
    _migrate_file(conn, "feeds_scored.json", _import_articles_scored)

    # 3. patterns.json → patterns
    _migrate_file(conn, "patterns.json", _import_patterns)

    # 4. enriched_articles.json → enrichments
    _migrate_file(conn, "enriched_articles.json", _import_enrichments)

    # 5. trend_scores.json → trend_scores
    _migrate_file(conn, "trend_scores.json", _import_trend_scores)

    logger.info("JSON → SQLite migration complete.")


def _migrate_file(conn: sqlite3.Connection, filename: str, importer):
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data:
            importer(conn, data)
            logger.info("Migrated %s", filename)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to migrate %s: %s", filename, e)


def _import_articles_cache(conn: sqlite3.Connection, articles: list):
    with conn:
        conn.executemany(
            """INSERT OR IGNORE INTO articles
               (url, title, summary, source, category, published, fetched_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(a.get("url", ""), a.get("title", ""), a.get("summary", ""),
              a.get("source", ""), a.get("category", ""),
              a.get("published", ""), a.get("fetched_at", ""))
             for a in articles if a.get("url")],
        )


def _import_articles_scored(conn: sqlite3.Connection, scored: list):
    with conn:
        for a in scored:
            url = a.get("url", "")
            if not url:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO articles
                   (url, title, summary, source, category, published, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (url, a.get("title", ""), a.get("summary", ""),
                 a.get("source", ""), a.get("category", ""),
                 a.get("published", ""), a.get("fetched_at", "")),
            )
            conn.execute(
                "UPDATE articles SET relevance_score = ?, relevance_trusted = ? WHERE url = ?",
                (a.get("relevance_score"), int(a.get("relevance_trusted", False)), url),
            )


def _import_patterns(conn: sqlite3.Connection, patterns: list):
    with conn:
        for p in patterns:
            conn.execute(
                """INSERT INTO patterns
                   (articles_json, categories_json, sources_json, num_sources,
                    analysis, confidence, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    json.dumps(p.get("articles", []), ensure_ascii=False),
                    json.dumps(p.get("categories", []), ensure_ascii=False),
                    json.dumps(p.get("sources", []), ensure_ascii=False),
                    p.get("num_sources", 0),
                    p.get("analysis", ""),
                    p.get("confidence", "MEDIA"),
                    p.get("timestamp", ""),
                ),
            )


def _import_enrichments(conn: sqlite3.Connection, enriched: dict):
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.executemany(
            """INSERT OR IGNORE INTO enrichments
               (url, entities_json, topics_json, created_at)
               VALUES (?, ?, ?, ?)""",
            [(url, json.dumps(d.get("entities", []), ensure_ascii=False),
              json.dumps(d.get("topics", []), ensure_ascii=False), now)
             for url, d in enriched.items()],
        )


def _import_trend_scores(conn: sqlite3.Connection, scores: dict):
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """INSERT OR REPLACE INTO trend_scores (key, data_json, updated_at)
               VALUES ('current', ?, ?)""",
            (json.dumps(scores, ensure_ascii=False), now),
        )
