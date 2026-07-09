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
import math
from datetime import datetime, timedelta, timezone

import numpy as np

try:
    import sqlite_vec
    _SQLITE_VEC_LIB_AVAILABLE = True
except ImportError:
    sqlite_vec = None
    _SQLITE_VEC_LIB_AVAILABLE = False

DATA_DIR = os.getenv("DATA_DIR", "/data")
DB_PATH = os.getenv("DB_PATH") or os.path.join(DATA_DIR, "agent.db")

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
    timestamp TEXT NOT NULL,
    regime_snapshot_json TEXT,
    regime_def_version INTEGER
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

CREATE TABLE IF NOT EXISTS graph_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    canonical TEXT NOT NULL UNIQUE,
    entity_type TEXT NOT NULL,
    pillar TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    source_url TEXT DEFAULT '',
    mention_count INTEGER DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'staged',
    reviewed_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ge_status ON graph_entities(status);
CREATE INDEX IF NOT EXISTS idx_ge_type ON graph_entities(entity_type);

CREATE TABLE IF NOT EXISTS graph_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL,
    predicate TEXT NOT NULL,
    object_id INTEGER NOT NULL,
    confidence REAL DEFAULT 0.5,
    source_url TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    mention_count INTEGER DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'staged',
    reviewed_at TEXT DEFAULT '',
    FOREIGN KEY (subject_id) REFERENCES graph_entities(id),
    FOREIGN KEY (object_id) REFERENCES graph_entities(id)
);
CREATE INDEX IF NOT EXISTS idx_gr_status ON graph_relationships(status);
CREATE INDEX IF NOT EXISTS idx_gr_subject ON graph_relationships(subject_id);
CREATE INDEX IF NOT EXISTS idx_gr_object ON graph_relationships(object_id);

CREATE TABLE IF NOT EXISTS system_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_type TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snap_type_time ON system_snapshots(snapshot_type, captured_at);

CREATE TABLE IF NOT EXISTS event_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    event_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    notes TEXT DEFAULT '',
    event_timestamp TEXT DEFAULT '',
    marked_at TEXT NOT NULL,
    UNIQUE (event_type, event_id)
);
CREATE INDEX IF NOT EXISTS idx_outcomes_type ON event_outcomes(event_type);
CREATE INDEX IF NOT EXISTS idx_outcomes_outcome ON event_outcomes(outcome);

CREATE TABLE IF NOT EXISTS backtest_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    config_json TEXT DEFAULT '{}',
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backtest_created ON backtest_runs(created_at);

CREATE TABLE IF NOT EXISTS macro_indicators (
    indicator TEXT NOT NULL,
    ts TEXT NOT NULL,
    value REAL NOT NULL,
    source TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    metadata TEXT,
    PRIMARY KEY (indicator, ts)
);
CREATE INDEX IF NOT EXISTS idx_macro_indicator_ts ON macro_indicators(indicator, ts DESC);
CREATE INDEX IF NOT EXISTS idx_macro_fetched_at ON macro_indicators(fetched_at DESC);
"""

# ---------------------------------------------------------------------------
# Connection singleton
# ---------------------------------------------------------------------------

_conn: sqlite3.Connection | None = None

# Tables introduced after the initial schema (Onda 10 and Onda 11). If a
# persistent volume survives an image upgrade and the original schema run
# never reached these CREATE statements, the database ends up missing them
# and any graph/backtest code path crashes with "no such table: ...". The
# guard in `_db` re-applies the schema whenever any of these are absent.
_LATE_ADDED_TABLES = (
    "graph_entities",
    "graph_relationships",
    "system_snapshots",
    "event_outcomes",
    "backtest_runs",
    "macro_indicators",
)


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _try_load_sqlite_vec(_conn)
        # Column-level migrations must run BEFORE executescript: the
        # schema contains CREATE INDEX statements on columns added via
        # ALTER TABLE, which would crash on a stale table that predates
        # the column.
        _migrate_embeddings_schema(_conn)
        _migrate_patterns_schema(_conn)
        _conn.executescript(_SCHEMA)
        _ensure_vec_table(_conn)
        _migrate_from_json()
    _ensure_late_added_tables(_conn)
    return _conn


def _ensure_late_added_tables(conn: sqlite3.Connection) -> None:
    existing = {
        r["name"]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = [t for t in _LATE_ADDED_TABLES if t not in existing]
    if not missing:
        return
    logger.warning(
        "DB missing late-added tables %s — reapplying schema", missing,
    )
    _migrate_embeddings_schema(conn)
    conn.executescript(_SCHEMA)


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
    table_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='embeddings'"
    ).fetchone()
    if not table_exists:
        return
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(embeddings)")}
    if "embedding_version" not in cols:
        with conn:
            conn.execute(
                "ALTER TABLE embeddings ADD COLUMN embedding_version TEXT NOT NULL DEFAULT 'v0'"
            )
        logger.info("Migrated embeddings table: added embedding_version column")

    # Retag pre-versioning embeddings (tagged 'v0' by the ALTER TABLE default)
    # to the current model — the only Voyage model the project has ever used
    # is voyage-3-lite, so 'v0' rows are voyage-3-lite vectors mis-labelled.
    # Without this, _reconcile_embedding_version_once() deletes them all on
    # first refresh after a restart, forcing a bulk re-embed that hits the
    # Voyage rate limit and falls back to a slow O(n²) TF-IDF on every text
    # cached — long enough for the ingress to 502 the request.
    with conn:
        cur = conn.execute(
            "UPDATE embeddings SET embedding_version = ? "
            "WHERE embedding_version = 'v0'",
            (EMBEDDING_VERSION_DEFAULT,),
        )
        if cur.rowcount:
            logger.info(
                "Retagged %d legacy 'v0' embeddings as %s",
                cur.rowcount, EMBEDDING_VERSION_DEFAULT,
            )


def _migrate_patterns_schema(conn: sqlite3.Connection) -> None:
    """Add regime columns to a pre-B2 ``patterns`` table if missing.

    Espelha ``_migrate_embeddings_schema``: PRAGMA + ALTER TABLE idempotente.
    Corre antes de ``executescript(_SCHEMA)`` porque o CREATE TABLE já lá
    inclui as colunas — para volumes novos os dois caminhos convergem no
    mesmo schema; para volumes existentes só este caminho as adiciona.

    As duas colunas movem-se em par (ambas preenchidas para patterns
    anotados, ambas NULL para skips) — decisão de higiene epistémica
    ratificada no checkpoint da Fase 2. A informação "qual foi o motivo
    do skip" vive no log estruturado ``pattern_regime_skipped``, não numa
    coluna do pattern.
    """
    table_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='patterns'"
    ).fetchone()
    if not table_exists:
        return
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(patterns)")}
    with conn:
        if "regime_snapshot_json" not in cols:
            conn.execute(
                "ALTER TABLE patterns ADD COLUMN regime_snapshot_json TEXT"
            )
            logger.info(
                "Migrated patterns table: added regime_snapshot_json column"
            )
        if "regime_def_version" not in cols:
            conn.execute(
                "ALTER TABLE patterns ADD COLUMN regime_def_version INTEGER"
            )
            logger.info(
                "Migrated patterns table: added regime_def_version column"
            )


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


def prune_articles(max_rows: int = 2000, retention_days: int = 0) -> None:
    """Prune articles by row cap or by age.

    When retention_days > 0, drops articles older than that many days
    (Onda 11: long-term retention for backtesting). Otherwise applies the
    legacy fixed-row cap.
    """
    conn = _db()
    count = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    if retention_days > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with conn:
            cursor = conn.execute(
                "DELETE FROM articles WHERE fetched_at < ?", (cutoff,),
            )
            if cursor.rowcount > 0:
                logger.info(
                    "Pruned %d articles older than %d days", cursor.rowcount, retention_days,
                )
        return
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

def insert_pattern(
    pattern: dict,
    *,
    regime_snapshot_json: str | None = None,
    regime_def_version: int | None = None,
) -> None:
    """Insert a detected pattern row.

    ``regime_snapshot_json`` + ``regime_def_version`` são opcionais e
    andam SEMPRE em par:
      - ambos preenchidos → pattern anotado sob a versão indicada;
      - ambos None (default) → pattern sem anotação de regime
        (missing/stale/erro no cálculo — decidido pelo caller, tipicamente
        via ``pattern_matcher._maybe_compute_regime``).
    O caller deve nunca passar só um dos dois; esta função aceita ambos
    NULL sem levantar erro (schema permite-o) mas não tenta reconstruir
    o par a partir do que o caller passar de forma inconsistente.
    """
    conn = _db()
    with conn:
        conn.execute(
            """INSERT INTO patterns
               (articles_json, categories_json, sources_json, num_sources,
                analysis, confidence, timestamp,
                regime_snapshot_json, regime_def_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                json.dumps(pattern.get("articles", []), ensure_ascii=False),
                json.dumps(pattern.get("categories", []), ensure_ascii=False),
                json.dumps(pattern.get("sources", []), ensure_ascii=False),
                pattern.get("num_sources", 0),
                pattern.get("analysis", ""),
                pattern.get("confidence", "MEDIA"),
                pattern.get("timestamp", datetime.now(timezone.utc).isoformat()),
                regime_snapshot_json,
                regime_def_version,
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
    # regime_snapshot_json / regime_def_version são adicionadas em B2:
    # devolvidas como RAW (sem json.loads) porque quem quer o snapshot
    # desserializado usa o endpoint dedicado /api/patterns/{id}/regime.
    # O list endpoint fica minimalista (string + int) — cliente que só
    # queira saber "que patterns têm regime" faz um SELECT campo-a-campo.
    # Ambas as chaves estão sempre presentes; valor None quando skip.
    keys = row.keys() if hasattr(row, "keys") else []
    return {
        "id": row["id"],
        "articles": json.loads(row["articles_json"]),
        "categories": json.loads(row["categories_json"]),
        "sources": json.loads(row["sources_json"]),
        "num_sources": row["num_sources"],
        "analysis": row["analysis"],
        "confidence": row["confidence"],
        "timestamp": row["timestamp"],
        "regime_snapshot_json": (
            row["regime_snapshot_json"]
            if "regime_snapshot_json" in keys else None
        ),
        "regime_def_version": (
            row["regime_def_version"]
            if "regime_def_version" in keys else None
        ),
    }


def get_pattern_by_id(pattern_id: int) -> dict | None:
    """Fetch a single pattern by id, or None if not found.

    Usado pelo endpoint /api/patterns/{id}/regime. Devolve o dict via
    _row_to_pattern (mesmos campos que get_patterns) — a desserialização
    do snapshot fica com o caller, para não bloatar este helper com
    conhecimento do formato B2 do regime.
    """
    conn = _db()
    row = conn.execute(
        "SELECT * FROM patterns WHERE id = ?", (int(pattern_id),),
    ).fetchone()
    if row is None:
        return None
    return _row_to_pattern(row)


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
# Dynamic Knowledge Graph (Onda 10)
# ---------------------------------------------------------------------------

def upsert_graph_entity(
    name: str,
    canonical: str,
    entity_type: str,
    pillar: str = "",
    source_url: str = "",
) -> int:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        existing = conn.execute(
            "SELECT id, mention_count FROM graph_entities WHERE canonical = ?",
            (canonical,),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE graph_entities SET mention_count = mention_count + 1 WHERE id = ?",
                (existing["id"],),
            )
            return existing["id"]
        cursor = conn.execute(
            """INSERT INTO graph_entities
               (name, canonical, entity_type, pillar, first_seen, source_url)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, canonical, entity_type, pillar, now, source_url),
        )
        return cursor.lastrowid or 0


def upsert_graph_relationship(
    subject_id: int,
    predicate: str,
    object_id: int,
    confidence: float = 0.5,
    source_url: str = "",
) -> int:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        existing = conn.execute(
            """SELECT id, mention_count, confidence FROM graph_relationships
               WHERE subject_id = ? AND predicate = ? AND object_id = ?""",
            (subject_id, predicate, object_id),
        ).fetchone()
        if existing:
            new_conf = min(1.0, existing["confidence"] + 0.05)
            conn.execute(
                """UPDATE graph_relationships
                   SET mention_count = mention_count + 1, confidence = ?
                   WHERE id = ?""",
                (new_conf, existing["id"]),
            )
            return existing["id"]
        cursor = conn.execute(
            """INSERT INTO graph_relationships
               (subject_id, predicate, object_id, confidence, first_seen, source_url)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (subject_id, predicate, object_id, confidence, now, source_url),
        )
        return cursor.lastrowid or 0


def get_graph_entities(
    *, status: str = "", entity_type: str = "", limit: int = 100,
) -> list[dict]:
    conn = _db()
    clauses: list[str] = []
    params: list = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if entity_type:
        clauses.append("entity_type = ?")
        params.append(entity_type)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""SELECT * FROM graph_entities {where}
            ORDER BY mention_count DESC, first_seen DESC LIMIT ?""",
        params + [limit],
    ).fetchall()
    return [dict(r) for r in rows]


def get_graph_relationships(
    *, status: str = "", limit: int = 100,
) -> list[dict]:
    conn = _db()
    clause = "WHERE r.status = ?" if status else ""
    params: list = [status] if status else []
    rows = conn.execute(
        f"""SELECT r.*, s.name AS subject_name, s.canonical AS subject_canonical,
                   o.name AS object_name, o.canonical AS object_canonical
            FROM graph_relationships r
            JOIN graph_entities s ON r.subject_id = s.id
            JOIN graph_entities o ON r.object_id = o.id
            {clause}
            ORDER BY r.mention_count DESC, r.first_seen DESC LIMIT ?""",
        params + [limit],
    ).fetchall()
    return [dict(r) for r in rows]


def update_graph_entity_status(entity_id: int, status: str) -> bool:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            "UPDATE graph_entities SET status = ?, reviewed_at = ? WHERE id = ?",
            (status, now, entity_id),
        )
        return cursor.rowcount > 0


def update_graph_relationship_status(rel_id: int, status: str) -> bool:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            "UPDATE graph_relationships SET status = ?, reviewed_at = ? WHERE id = ?",
            (status, now, rel_id),
        )
        return cursor.rowcount > 0


def get_graph_stats() -> dict:
    conn = _db()
    entity_counts = {}
    for row in conn.execute(
        "SELECT status, COUNT(*) as cnt FROM graph_entities GROUP BY status"
    ):
        entity_counts[row["status"]] = row["cnt"]
    rel_counts = {}
    for row in conn.execute(
        "SELECT status, COUNT(*) as cnt FROM graph_relationships GROUP BY status"
    ):
        rel_counts[row["status"]] = row["cnt"]
    return {"entities": entity_counts, "relationships": rel_counts}


def get_entity_id_by_canonical(canonical: str) -> int | None:
    conn = _db()
    row = conn.execute(
        "SELECT id FROM graph_entities WHERE canonical = ?", (canonical,),
    ).fetchone()
    return row["id"] if row else None


def get_graph_for_display(status: str = "approved") -> dict:
    entities = get_graph_entities(status=status, limit=500)
    relationships = get_graph_relationships(status=status, limit=500)
    return {"entities": entities, "relationships": relationships}


# ---------------------------------------------------------------------------
# System snapshots (Onda 11) — capture state-over-time for backtesting
# ---------------------------------------------------------------------------

def insert_snapshot(snapshot_type: str, data: dict) -> int:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            """INSERT INTO system_snapshots (snapshot_type, captured_at, data_json)
               VALUES (?, ?, ?)""",
            (snapshot_type, now, json.dumps(data, ensure_ascii=False, default=str)),
        )
        return cursor.lastrowid or 0


def get_snapshots(
    *, snapshot_type: str = "", days: int = 30, limit: int = 100,
) -> list[dict]:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    clauses = ["captured_at >= ?"]
    params: list = [cutoff]
    if snapshot_type:
        clauses.append("snapshot_type = ?")
        params.append(snapshot_type)
    where = f"WHERE {' AND '.join(clauses)}"
    rows = conn.execute(
        f"""SELECT id, snapshot_type, captured_at, data_json
            FROM system_snapshots {where}
            ORDER BY captured_at DESC LIMIT ?""",
        params + [limit],
    ).fetchall()
    return [
        {
            "id": r["id"],
            "snapshot_type": r["snapshot_type"],
            "captured_at": r["captured_at"],
            "data": json.loads(r["data_json"]),
        }
        for r in rows
    ]


def get_snapshot_at(snapshot_type: str, target_iso: str) -> dict | None:
    """Return the snapshot of the given type closest-before target time."""
    conn = _db()
    row = conn.execute(
        """SELECT id, snapshot_type, captured_at, data_json FROM system_snapshots
           WHERE snapshot_type = ? AND captured_at <= ?
           ORDER BY captured_at DESC LIMIT 1""",
        (snapshot_type, target_iso),
    ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "snapshot_type": row["snapshot_type"],
        "captured_at": row["captured_at"],
        "data": json.loads(row["data_json"]),
    }


def prune_snapshots(days: int = 365) -> None:
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with conn:
        conn.execute(
            "DELETE FROM system_snapshots WHERE captured_at < ?", (cutoff,),
        )


# ---------------------------------------------------------------------------
# Event outcomes (Onda 11) — user labels for signal quality measurement
# ---------------------------------------------------------------------------

def upsert_outcome(
    event_type: str,
    event_id: str,
    outcome: str,
    notes: str = "",
    event_timestamp: str = "",
) -> int:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        existing = conn.execute(
            "SELECT id FROM event_outcomes WHERE event_type = ? AND event_id = ?",
            (event_type, event_id),
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE event_outcomes SET outcome = ?, notes = ?, marked_at = ?
                   WHERE id = ?""",
                (outcome, notes, now, existing["id"]),
            )
            return existing["id"]
        cursor = conn.execute(
            """INSERT INTO event_outcomes
               (event_type, event_id, outcome, notes, event_timestamp, marked_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (event_type, event_id, outcome, notes, event_timestamp, now),
        )
        return cursor.lastrowid or 0


def get_outcomes(
    *, event_type: str = "", outcome: str = "", limit: int = 200,
) -> list[dict]:
    conn = _db()
    clauses: list[str] = []
    params: list = []
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""SELECT * FROM event_outcomes {where}
            ORDER BY marked_at DESC LIMIT ?""",
        params + [limit],
    ).fetchall()
    return [dict(r) for r in rows]


def get_outcome_for(event_type: str, event_id: str) -> dict | None:
    conn = _db()
    row = conn.execute(
        "SELECT * FROM event_outcomes WHERE event_type = ? AND event_id = ?",
        (event_type, event_id),
    ).fetchone()
    return dict(row) if row else None


def _wilson_interval(tp: int, total: int, z: float = 1.96):
    """Wilson 95% score interval for a binomial proportion.

    Honest for small n: gives (None, None) when total <= 0, asymmetric
    bounds otherwise (Wilson is exact at p=0 or p=1, no need to clamp).
    Returns rounded (low, high) ∈ [0, 1].
    """
    if total <= 0:
        return (None, None)
    p = tp / total
    denom = 1.0 + (z * z) / total
    centre = (p + (z * z) / (2 * total)) / denom
    margin = (z * math.sqrt((p * (1.0 - p) + (z * z) / (4 * total)) / total)) / denom
    return (round(max(0.0, centre - margin), 3), round(min(1.0, centre + margin), 3))


def get_quality_metrics(*, days: int = 90, by: str = "marked_at") -> dict:
    """Aggregate outcomes by type → precision (Wilson 95% CI) + n.

    ``by`` chooses the time column for the window: ``marked_at`` (when the
    outcome was labelled, default) or ``event_timestamp`` (when the event
    actually happened). Legacy outcomes with empty event_timestamp are
    excluded when ``by='event_timestamp'``.
    """
    col = "event_timestamp" if by == "event_timestamp" else "marked_at"
    extra = " AND event_timestamp != ''" if col == "event_timestamp" else ""
    conn = _db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = conn.execute(
        f"""SELECT event_type, outcome, COUNT(*) as cnt
            FROM event_outcomes
            WHERE {col} >= ?{extra}
            GROUP BY event_type, outcome""",
        (cutoff,),
    ).fetchall()
    by_type: dict[str, dict] = {}
    for r in rows:
        et = r["event_type"]
        bucket = by_type.setdefault(
            et, {"true_positive": 0, "false_positive": 0, "unclear": 0, "total": 0},
        )
        bucket[r["outcome"]] = r["cnt"]
        bucket["total"] += r["cnt"]
    for et, b in by_type.items():
        labelled = b["true_positive"] + b["false_positive"]
        b["n"] = labelled
        b["precision"] = (
            round(b["true_positive"] / labelled, 3) if labelled > 0 else None
        )
        low, high = _wilson_interval(b["true_positive"], labelled)
        b["precision_low"] = low
        b["precision_high"] = high
    return {"window_days": days, "filter_by": col, "by_type": by_type}


# ---------------------------------------------------------------------------
# Unlabelled events (Onda 11) — feeds the outcome-labelling UI
# ---------------------------------------------------------------------------

_UNLABELLED_PATTERN_SQL = """
    SELECT 'pattern' AS event_type, CAST(p.id AS TEXT) AS event_id,
           p.confidence AS confidence, p.categories_json AS categories_json,
           NULL AS pillars_json, p.analysis AS detail, p.timestamp AS ts
    FROM patterns p
    WHERE NOT EXISTS (
        SELECT 1 FROM event_outcomes o
        WHERE o.event_type = 'pattern' AND o.event_id = CAST(p.id AS TEXT)
    )
"""

_UNLABELLED_CHAIN_SQL = """
    SELECT 'chain' AS event_type, CAST(c.id AS TEXT) AS event_id,
           NULL AS confidence, NULL AS categories_json,
           c.pillars_json AS pillars_json, c.narrative AS detail,
           c.detected_at AS ts
    FROM cross_pillar_chains c
    WHERE NOT EXISTS (
        SELECT 1 FROM event_outcomes o
        WHERE o.event_type = 'chain' AND o.event_id = CAST(c.id AS TEXT)
    )
"""

_UNLABELLED_SOURCES = {
    "pattern": _UNLABELLED_PATTERN_SQL,
    "chain": _UNLABELLED_CHAIN_SQL,
}


def get_unlabelled_events(
    *, event_type: str = "", limit: int = 50, offset: int = 0,
) -> dict:
    """Patterns / chains with no outcome marked yet, newest first.

    Anti-joins event_outcomes on the (event_type, event_id) convention the
    labelling UI writes with: event_id is str() of the row's integer id.
    Returns {events, total, limit, offset} for offset-based pagination.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    et = (event_type or "").strip().lower()

    if et in _UNLABELLED_SOURCES:
        union = _UNLABELLED_SOURCES[et]
    elif et == "":
        union = f"{_UNLABELLED_PATTERN_SQL} UNION ALL {_UNLABELLED_CHAIN_SQL}"
    else:
        return {"events": [], "total": 0, "limit": limit, "offset": offset}

    conn = _db()
    total = conn.execute(f"SELECT COUNT(*) AS n FROM ({union}) AS sub").fetchone()["n"]
    rows = conn.execute(
        f"SELECT * FROM ({union}) AS sub ORDER BY ts DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()

    events = []
    for r in rows:
        if r["event_type"] == "pattern":
            cats = json.loads(r["categories_json"] or "[]")
            title = f"{r['confidence']} · {', '.join(cats) if cats else '—'}"
            kind = "Pattern"
        else:
            pillars = json.loads(r["pillars_json"] or "[]")
            title = " → ".join(pillars) if pillars else "cross-pillar"
            kind = "Chain"
        events.append({
            "event_type": r["event_type"],
            "event_id": r["event_id"],
            "kind": kind,
            "title": title,
            "detail": r["detail"] or "",
            "timestamp": r["ts"] or "",
        })
    return {"events": events, "total": total, "limit": limit, "offset": offset}


# ---------------------------------------------------------------------------
# Backtest runs (Onda 11)
# ---------------------------------------------------------------------------

def insert_backtest_run(
    window_start: str, window_end: str, config: dict, result: dict,
) -> int:
    conn = _db()
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            """INSERT INTO backtest_runs
               (window_start, window_end, config_json, result_json, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                window_start, window_end,
                json.dumps(config, ensure_ascii=False, default=str),
                json.dumps(result, ensure_ascii=False, default=str),
                now,
            ),
        )
        return cursor.lastrowid or 0


def get_backtest_runs(*, limit: int = 20) -> list[dict]:
    conn = _db()
    rows = conn.execute(
        """SELECT id, window_start, window_end, config_json, result_json, created_at
           FROM backtest_runs ORDER BY created_at DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "window_start": r["window_start"],
            "window_end": r["window_end"],
            "config": json.loads(r["config_json"] or "{}"),
            "result": json.loads(r["result_json"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def get_backtest_run(run_id: int) -> dict | None:
    conn = _db()
    row = conn.execute(
        """SELECT id, window_start, window_end, config_json, result_json, created_at
           FROM backtest_runs WHERE id = ?""",
        (run_id,),
    ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "config": json.loads(row["config_json"] or "{}"),
        "result": json.loads(row["result_json"]),
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# Historical queries (Onda 11) — used by backtest replay
# ---------------------------------------------------------------------------

def get_articles_in_window(
    *, start_iso: str, end_iso: str, category: str = "", limit: int = 5000,
) -> list[dict]:
    conn = _db()
    clauses = ["fetched_at >= ?", "fetched_at < ?"]
    params: list = [start_iso, end_iso]
    if category:
        clauses.append("category = ?")
        params.append(category)
    where = f"WHERE {' AND '.join(clauses)}"
    rows = conn.execute(
        f"""SELECT * FROM articles {where}
            ORDER BY fetched_at ASC LIMIT ?""",
        params + [limit],
    ).fetchall()
    return [_row_to_article(r) for r in rows]


def get_patterns_in_window(*, start_iso: str, end_iso: str) -> list[dict]:
    conn = _db()
    rows = conn.execute(
        """SELECT * FROM patterns WHERE timestamp >= ? AND timestamp < ?
           ORDER BY timestamp ASC""",
        (start_iso, end_iso),
    ).fetchall()
    return [_row_to_pattern(r) for r in rows]


def get_chains_in_window(*, start_iso: str, end_iso: str) -> list[dict]:
    conn = _db()
    rows = conn.execute(
        """SELECT * FROM cross_pillar_chains
           WHERE detected_at >= ? AND detected_at < ?
           ORDER BY detected_at ASC""",
        (start_iso, end_iso),
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
