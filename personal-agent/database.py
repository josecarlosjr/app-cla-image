"""SQLite persistence layer — replaces JSON file storage.

Single database at $DATA_DIR/agent.db with WAL mode for concurrent reads.
Auto-migrates from legacy JSON files on first run.

Tables:
    articles    — RSS articles with optional relevance scores
    patterns    — detected cross-source patterns
    enrichments — Haiku entity/topic extractions (URL-keyed cache)
    embeddings  — Voyage AI vectors (URL-keyed cache)
    trend_scores — category scores + connections
    temporal_snapshots — hourly article counts per category (F5a)
    supply_chain_nodes — knowledge graph nodes (minerals, components, products)
    supply_chain_edges — dependency relationships between nodes
    supply_chain_mentions — article-level mentions with sentiment signals
"""

import json
import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone

import numpy as np

try:
    import sqlite_vec
    _SQLITE_VEC_LIB_AVAILABLE = True
except ImportError:
    sqlite_vec = None
    _SQLITE_VEC_LIB_AVAILABLE = False

DATA_DIR = os.getenv("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "agent.db")

VOYAGE_EMBEDDING_DIM = 512
EMBEDDING_VERSION_DEFAULT = "voyage-3-lite"

logger = logging.getLogger(__name__)

_VEC_AVAILABLE = False

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
    embedding_version TEXT NOT NULL DEFAULT 'v0',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_embeddings_version ON embeddings(embedding_version);

CREATE TABLE IF NOT EXISTS trend_scores (
    key TEXT PRIMARY KEY,
    data_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS temporal_snapshots (
    category TEXT NOT NULL,
    bucket TEXT NOT NULL,
    article_count INTEGER DEFAULT 0,
    source_count INTEGER DEFAULT 0,
    PRIMARY KEY (category, bucket)
);
CREATE INDEX IF NOT EXISTS idx_temporal_bucket ON temporal_snapshots(bucket);

CREATE TABLE IF NOT EXISTS supply_chain_nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    keywords_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS supply_chain_edges (
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    relation TEXT NOT NULL DEFAULT 'requires',
    weight REAL DEFAULT 1.0,
    PRIMARY KEY (src, dst, relation),
    FOREIGN KEY (src) REFERENCES supply_chain_nodes(id),
    FOREIGN KEY (dst) REFERENCES supply_chain_nodes(id)
);
CREATE INDEX IF NOT EXISTS idx_sc_edges_src ON supply_chain_edges(src);
CREATE INDEX IF NOT EXISTS idx_sc_edges_dst ON supply_chain_edges(dst);

CREATE TABLE IF NOT EXISTS supply_chain_mentions (
    node_id TEXT NOT NULL,
    article_url TEXT NOT NULL,
    sentiment TEXT DEFAULT 'neutral',
    timestamp TEXT NOT NULL,
    PRIMARY KEY (node_id, article_url),
    FOREIGN KEY (node_id) REFERENCES supply_chain_nodes(id)
);
CREATE INDEX IF NOT EXISTS idx_sc_mentions_node ON supply_chain_mentions(node_id);
CREATE INDEX IF NOT EXISTS idx_sc_mentions_ts ON supply_chain_mentions(timestamp);

CREATE TABLE IF NOT EXISTS cross_pillar_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    members_hash TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    pillars_json TEXT NOT NULL,
    events_json TEXT NOT NULL,
    narrative TEXT DEFAULT '',
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cpc_detected ON cross_pillar_chains(detected_at);
CREATE INDEX IF NOT EXISTS idx_cpc_hash ON cross_pillar_chains(members_hash);
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
        _try_load_sqlite_vec(_conn)
        _conn.executescript(_SCHEMA)
        _migrate_embeddings_schema(_conn)
        _ensure_vec_table(_conn)
        _migrate_from_json()
    return _conn


def _try_load_sqlite_vec(conn: sqlite3.Connection) -> None:
    global _VEC_AVAILABLE
    if not _SQLITE_VEC_LIB_AVAILABLE:
        logger.warning("sqlite-vec lib not installed; falling back to brute-force similarity")
        return
    try:
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        _VEC_AVAILABLE = True
        logger.info("sqlite-vec loaded — ANN candidate search enabled")
    except (sqlite3.OperationalError, AttributeError) as e:
        logger.warning("sqlite-vec failed to load (%s); falling back to brute-force", e)


def _migrate_embeddings_schema(conn: sqlite3.Connection) -> None:
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(embeddings)")}
    if "embedding_version" not in cols:
        with conn:
            conn.execute(
                "ALTER TABLE embeddings ADD COLUMN embedding_version TEXT NOT NULL DEFAULT 'v0'"
            )
        logger.info("Migrated embeddings table: added embedding_version column")


def _ensure_vec_table(conn: sqlite3.Connection) -> None:
    if not _VEC_AVAILABLE:
        return
    try:
        with conn:
            conn.execute(
                f"""CREATE VIRTUAL TABLE IF NOT EXISTS embeddings_vec USING vec0(
                    url TEXT PRIMARY KEY,
                    embedding FLOAT[{VOYAGE_EMBEDDING_DIM}] distance_metric=cosine
                )"""
            )
    except sqlite3.OperationalError as e:
        logger.warning("Could not create vec0 table: %s", e)


def is_vec_available() -> bool:
    return _VEC_AVAILABLE


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
    category: str = "",
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
    if category:
        clauses.append("categories_json LIKE ?")
        params.append(f"%{category}%")

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
        "id": row["id"],
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


def prune_enrichments(max_entries: int = 12000) -> None:
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
            """INSERT OR REPLACE INTO embeddings
               (url, vector, model, dims, embedding_version, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(url, vec.astype(np.float32).tobytes(), model, vec.shape[0], model, now)
             for url, vec in url_vector_pairs],
        )

    if not _VEC_AVAILABLE:
        return
    vec_pairs = [
        (url, vec.astype(np.float32).tobytes())
        for url, vec in url_vector_pairs
        if vec.shape[0] == VOYAGE_EMBEDDING_DIM
    ]
    if not vec_pairs:
        return
    try:
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO embeddings_vec (url, embedding) VALUES (?, ?)",
                vec_pairs,
            )
    except sqlite3.OperationalError as e:
        logger.warning("vec0 insert failed: %s", e)


def prune_embeddings(max_entries: int = 25000) -> None:
    conn = _db()
    count = conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]
    if count <= max_entries:
        return
    with conn:
        cutoff_row = conn.execute(
            "SELECT created_at FROM embeddings ORDER BY created_at DESC LIMIT 1 OFFSET ?",
            (max_entries - 1,),
        ).fetchone()
        if not cutoff_row:
            return
        cutoff = cutoff_row["created_at"]
        stale_urls = [
            r["url"] for r in conn.execute(
                "SELECT url FROM embeddings WHERE created_at < ?", (cutoff,)
            )
        ]
        conn.execute(
            "DELETE FROM embeddings WHERE created_at < ?", (cutoff,),
        )
        if _VEC_AVAILABLE and stale_urls:
            try:
                for i in range(0, len(stale_urls), 500):
                    batch = stale_urls[i:i + 500]
                    placeholders = ",".join("?" * len(batch))
                    conn.execute(
                        f"DELETE FROM embeddings_vec WHERE url IN ({placeholders})",
                        batch,
                    )
            except sqlite3.OperationalError as e:
                logger.warning("vec0 prune failed: %s", e)


def find_similar_embeddings(
    query_vec: np.ndarray, k: int = 50,
) -> list[tuple[str, float]]:
    """Top-K nearest neighbours by cosine distance via sqlite-vec.

    Returns [(url, distance), ...] sorted by distance ascending.
    Empty list if sqlite-vec is unavailable or vec table empty.
    """
    if not _VEC_AVAILABLE:
        return []
    if query_vec.shape[0] != VOYAGE_EMBEDDING_DIM:
        return []
    conn = _db()
    try:
        rows = conn.execute(
            """SELECT url, distance FROM embeddings_vec
               WHERE embedding MATCH ? AND k = ?
               ORDER BY distance""",
            (query_vec.astype(np.float32).tobytes(), int(k)),
        ).fetchall()
        return [(r["url"], float(r["distance"])) for r in rows]
    except sqlite3.OperationalError as e:
        logger.warning("vec0 KNN query failed: %s", e)
        return []


def rebuild_vec_index_for_version(target_version: str) -> int:
    """Drop incompatible vectors and rebuild vec0 from canonical embeddings table.

    Called when the embedding model/version changes — purges all rows whose
    embedding_version does not match target_version, leaving only consistent
    vectors. Returns number of rows kept.
    """
    conn = _db()
    with conn:
        deleted_urls = [
            r["url"] for r in conn.execute(
                "SELECT url FROM embeddings WHERE embedding_version != ?",
                (target_version,),
            )
        ]
        if deleted_urls:
            conn.execute(
                "DELETE FROM embeddings WHERE embedding_version != ?",
                (target_version,),
            )
            logger.info(
                "Pruned %d embeddings with version != %s",
                len(deleted_urls), target_version,
            )

    if not _VEC_AVAILABLE:
        return conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]

    try:
        with conn:
            if deleted_urls:
                for i in range(0, len(deleted_urls), 500):
                    batch = deleted_urls[i:i + 500]
                    placeholders = ",".join("?" * len(batch))
                    conn.execute(
                        f"DELETE FROM embeddings_vec WHERE url IN ({placeholders})",
                        batch,
                    )
        kept = conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]
        return kept
    except sqlite3.OperationalError as e:
        logger.warning("rebuild_vec_index failed: %s", e)
        return 0


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
# Temporal Snapshots (F5a)
# ---------------------------------------------------------------------------

def record_temporal_snapshots(stats: list[dict]) -> None:
    """Upsert hourly article counts per category. Accumulates within same hour."""
    if not stats:
        return
    conn = _db()
    with conn:
        for s in stats:
            conn.execute(
                """INSERT INTO temporal_snapshots
                   (category, bucket, article_count, source_count)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(category, bucket) DO UPDATE SET
                   article_count = article_count + excluded.article_count,
                   source_count = MAX(source_count, excluded.source_count)""",
                (s["category"], s["bucket"], s["article_count"], s["source_count"]),
            )


def get_temporal_snapshots(*, category: str = "", hours: int = 168) -> list[dict]:
    """Get snapshots for the last N hours (default 7 days)."""
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H")
    params: list = [cutoff]
    cat_clause = ""
    if category:
        cat_clause = "AND category = ?"
        params.append(category)
    rows = conn.execute(
        f"""SELECT category, bucket, article_count, source_count
            FROM temporal_snapshots
            WHERE bucket >= ? {cat_clause}
            ORDER BY bucket ASC""",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def prune_temporal_snapshots(days: int = 30) -> None:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H")
    with conn:
        conn.execute("DELETE FROM temporal_snapshots WHERE bucket < ?", (cutoff,))


# ---------------------------------------------------------------------------
# Supply Chain Knowledge Graph
# ---------------------------------------------------------------------------

def seed_supply_chain(nodes: list[dict], edges: list) -> None:
    conn = _db()
    with conn:
        for n in nodes:
            conn.execute(
                """INSERT OR REPLACE INTO supply_chain_nodes (id, name, type, keywords_json)
                   VALUES (?, ?, ?, ?)""",
                (n["id"], n["name"], n["type"],
                 json.dumps(n.get("keywords", []), ensure_ascii=False)),
            )
        for e in edges:
            if isinstance(e, dict):
                src, dst, rel = e["src"], e["dst"], e.get("relation", "requires")
                weight = e.get("weight", 1.0)
            else:
                src, dst, rel = e[0], e[1], e[2] if len(e) > 2 else "requires"
                weight = 1.0
            conn.execute(
                """INSERT OR REPLACE INTO supply_chain_edges (src, dst, relation, weight)
                   VALUES (?, ?, ?, ?)""",
                (src, dst, rel, weight),
            )
    logger.info("Seeded supply chain: %d nodes, %d edges.", len(nodes), len(edges))


def get_supply_chain_nodes() -> list[dict]:
    conn = _db()
    rows = conn.execute("SELECT * FROM supply_chain_nodes").fetchall()
    return [
        {"id": r["id"], "name": r["name"], "type": r["type"],
         "keywords": json.loads(r["keywords_json"])}
        for r in rows
    ]


def get_supply_chain_edges() -> list[dict]:
    conn = _db()
    rows = conn.execute("SELECT * FROM supply_chain_edges").fetchall()
    return [
        {"src": r["src"], "dst": r["dst"],
         "relation": r["relation"], "weight": r["weight"]}
        for r in rows
    ]


def upsert_supply_chain_mention(
    node_id: str, article_url: str, sentiment: str, timestamp: str,
) -> None:
    conn = _db()
    with conn:
        conn.execute(
            """INSERT OR REPLACE INTO supply_chain_mentions
               (node_id, article_url, sentiment, timestamp)
               VALUES (?, ?, ?, ?)""",
            (node_id, article_url, sentiment, timestamp),
        )


def upsert_supply_chain_mentions_batch(mentions: list[dict]) -> None:
    if not mentions:
        return
    conn = _db()
    with conn:
        conn.executemany(
            """INSERT OR REPLACE INTO supply_chain_mentions
               (node_id, article_url, sentiment, timestamp)
               VALUES (?, ?, ?, ?)""",
            [(m["node_id"], m["article_url"], m["sentiment"], m["timestamp"])
             for m in mentions],
        )


def get_supply_chain_mentions(
    *, node_id: str = "", hours: int = 168,
) -> list[dict]:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    clauses = ["timestamp >= ?"]
    params: list = [cutoff]
    if node_id:
        clauses.append("node_id = ?")
        params.append(node_id)
    where = f"WHERE {' AND '.join(clauses)}"
    rows = conn.execute(
        f"""SELECT node_id, article_url, sentiment, timestamp
            FROM supply_chain_mentions {where}
            ORDER BY timestamp DESC""",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def get_supply_chain_mention_counts(hours: int = 168) -> dict[str, dict]:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    rows = conn.execute(
        """SELECT node_id, sentiment, COUNT(*) as cnt
           FROM supply_chain_mentions
           WHERE timestamp >= ?
           GROUP BY node_id, sentiment""",
        (cutoff,),
    ).fetchall()
    result: dict[str, dict] = {}
    for r in rows:
        nid = r["node_id"]
        if nid not in result:
            result[nid] = {"total": 0, "sentiments": {}}
        result[nid]["total"] += r["cnt"]
        result[nid]["sentiments"][r["sentiment"]] = r["cnt"]
    return result


def prune_supply_chain_mentions(days: int = 30) -> None:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with conn:
        conn.execute(
            "DELETE FROM supply_chain_mentions WHERE timestamp < ?", (cutoff,),
        )


# ---------------------------------------------------------------------------
# Cross-pillar chains (Onda 9)
# ---------------------------------------------------------------------------

def insert_cross_pillar_chain(chain: dict) -> int:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            """INSERT INTO cross_pillar_chains
               (members_hash, window_start, window_end, pillars_json,
                events_json, narrative, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                chain["members_hash"],
                chain["window_start"],
                chain["window_end"],
                json.dumps(chain["pillars"], ensure_ascii=False),
                json.dumps(chain["events"], ensure_ascii=False),
                chain.get("narrative", ""),
                now,
            ),
        )
        return cursor.lastrowid or 0


def chain_exists(members_hash: str, since_hours: int = 24) -> bool:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    row = conn.execute(
        """SELECT 1 FROM cross_pillar_chains
           WHERE members_hash = ? AND detected_at >= ? LIMIT 1""",
        (members_hash, cutoff),
    ).fetchone()
    return row is not None


def get_cross_pillar_chains(*, hours: int = 168, limit: int = 50) -> list[dict]:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    rows = conn.execute(
        """SELECT * FROM cross_pillar_chains
           WHERE detected_at >= ?
           ORDER BY detected_at DESC LIMIT ?""",
        (cutoff, limit),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "members_hash": r["members_hash"],
            "window_start": r["window_start"],
            "window_end": r["window_end"],
            "pillars": json.loads(r["pillars_json"]),
            "events": json.loads(r["events_json"]),
            "narrative": r["narrative"],
            "detected_at": r["detected_at"],
        }
        for r in rows
    ]


def prune_cross_pillar_chains(days: int = 60) -> None:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with conn:
        conn.execute(
            "DELETE FROM cross_pillar_chains WHERE detected_at < ?", (cutoff,),
        )


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
