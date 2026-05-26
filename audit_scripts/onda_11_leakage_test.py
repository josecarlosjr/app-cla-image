"""Onda 11 — leakage test (the CRITICAL one).

Per PIA_Wave_Audit_Plan.md §Onda 11 "Teste de leakage":

  > Se este teste falha, o backtest está contaminado e todas as métricas
  > de precisão são fraude.

It is self-contained: it builds its OWN throwaway SQLite DB (via a temp
DATA_DIR) with controlled rows, runs the real `replay_window`, and asserts
that data created AFTER the replay window can never appear in the replay
output — at both the query level and end-to-end.

Runnable anywhere (no cluster, no live data, no LLM):
    python audit_scripts/onda_11_leakage_test.py
or under pytest (the test_* function is collected).
"""

import os
import sys
import tempfile

# Point the DB layer at a throwaway dir BEFORE importing it (DATA_DIR is
# read at module import time in database.py).
_TMP = tempfile.mkdtemp(prefix="onda11_leak_")
os.environ["DATA_DIR"] = _TMP

# audit_scripts/ lives one level below the package; make personal-agent importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "personal-agent"))

import database as db                      # noqa: E402
from backtest import replay_window          # noqa: E402

# Fixed, explicit window. "past" rows fall inside it; "future" rows fall
# AFTER its end and must never surface.
T0 = "2024-06-01T00:00:00+00:00"
T1 = "2024-06-10T00:00:00+00:00"
PAST = "2024-06-05T12:00:00+00:00"     # inside [T0, T1)
FUTURE = "2024-06-20T00:00:00+00:00"   # after T1 — the leakage probe


def _seed() -> None:
    conn = db._db()  # auto-creates the full schema
    with conn:
        conn.executescript("DELETE FROM articles; DELETE FROM patterns; "
                            "DELETE FROM cross_pillar_chains;")
        # Articles — tagged with unique categories so we can detect them
        # in the replay output (which returns counts by category).
        conn.execute(
            "INSERT INTO articles (url,title,fetched_at,category) VALUES (?,?,?,?)",
            ("http://x/past", "past article", PAST, "past_evt"),
        )
        conn.execute(
            "INSERT INTO articles (url,title,fetched_at,category) VALUES (?,?,?,?)",
            ("http://x/future", "future article", FUTURE, "future_leak"),
        )
        # Patterns (filtered by `timestamp`)
        for ts, conf in ((PAST, "ALTA"), (FUTURE, "ALTA")):
            conn.execute(
                "INSERT INTO patterns (articles_json,categories_json,sources_json,"
                "num_sources,confidence,timestamp) VALUES ('[]','[]','[]',3,?,?)",
                (conf, ts),
            )
        # Chains (filtered by `detected_at`)
        for ts in (PAST, FUTURE):
            conn.execute(
                "INSERT INTO cross_pillar_chains (members_hash,window_start,window_end,"
                "pillars_json,events_json,detected_at) VALUES (?,?,?,?,?,?)",
                (f"h{ts}", T0, T1, '["tech","mercados","geo"]', "[]", ts),
            )


def test_no_future_leakage_in_replay() -> None:
    _seed()

    # --- 1. Query level: window readers must exclude future-dated rows ---
    arts = db.get_articles_in_window(start_iso=T0, end_iso=T1)
    cats = {a.get("category") for a in arts}
    assert "past_evt" in cats, "positive control failed: past article not visible"
    assert "future_leak" not in cats, "LEAKAGE: future article visible in window query"

    pats = db.get_patterns_in_window(start_iso=T0, end_iso=T1)
    assert len(pats) == 1, f"LEAKAGE: expected 1 past pattern, got {len(pats)}"

    chains = db.get_chains_in_window(start_iso=T0, end_iso=T1)
    assert len(chains) == 1, f"LEAKAGE: expected 1 past chain, got {len(chains)}"

    # --- 2. End-to-end: future category must not appear in ANY replay tick ---
    rep = replay_window(T0, T1, eval_step_hours=24, pattern_lookback_hours=48)
    saw_past = False
    for tick in rep["ticks"]:
        by_cat = tick["articles_by_category"]
        assert "future_leak" not in by_cat, (
            f"LEAKAGE: future article surfaced in replay tick {tick['at']}"
        )
        if "past_evt" in by_cat:
            saw_past = True
    assert saw_past, "positive control failed: past article never surfaced in replay"


if __name__ == "__main__":
    try:
        test_no_future_leakage_in_replay()
    except AssertionError as e:
        print(f"FAIL  leakage test: {e}")
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        print(f"ERROR leakage test: {type(e).__name__}: {e}")
        sys.exit(2)
    print("PASS  no future leakage — query level AND end-to-end replay")
    print("      (replay filters articles by fetched_at, patterns by timestamp,")
    print("       chains by detected_at — all storage-time columns)")
