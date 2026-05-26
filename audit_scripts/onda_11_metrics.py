"""Onda 11 metrics collector — backtesting, snapshots, outcomes, quality.

Re-executable. Run against the LIVE SQLite agent.db (Onda 11 lives
entirely in SQLite; the quant_* Postgres tables belong to Onda 12).

    # in-cluster (DATA_DIR=/data is the default):
    python audit_scripts/onda_11_metrics.py
    # or point at a copy:
    python audit_scripts/onda_11_metrics.py --db /path/to/agent.db

Collects:
  T11.1  outcome sample sizes (statistical-validity gate, >=30 per type)
  T11.2  backtest determinism (replay a fixed window twice -> identical?)
  T11.3  snapshot completeness (the 4 types, span in days)
  T11.4  quality precision per event_type (SQL vs get_quality_metrics)
  P2     idempotency (article / outcome duplicates)
  leak   invokes onda_11_leakage_test.py (the critical binary test)

Prints a human-readable report plus a JSON blob at the end to paste back.
Read-only except the leakage test, which uses its own throwaway DB.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))

ap = argparse.ArgumentParser()
ap.add_argument("--db", help="path to agent.db (default: $DATA_DIR/agent.db or /data/agent.db)")
ap.add_argument("--det-days", type=int, default=30,
                help="window (days) for the determinism replay")
args = ap.parse_args()

# DATA_DIR must be set before importing database.py.
if args.db:
    os.environ["DATA_DIR"] = os.path.dirname(os.path.abspath(args.db)) or "."
sys.path.insert(0, os.path.join(_HERE, "..", "personal-agent"))

import database as db                       # noqa: E402
from backtest import replay_window           # noqa: E402

report: dict = {"db_path": db.DB_PATH, "generated_at": datetime.now(timezone.utc).isoformat()}


def _q(sql: str, params=()) -> list[dict]:
    return [dict(r) for r in db._db().execute(sql, params).fetchall()]


def _print_header(title: str) -> None:
    print(f"\n{'=' * 4} {title} {'=' * 4}")


# --- T11.1 outcome sample sizes ----------------------------------------
_print_header("T11.1 outcome sample sizes (need >=30 per type for stats)")
rows = _q("SELECT event_type, outcome, COUNT(*) n FROM event_outcomes "
          "GROUP BY event_type, outcome ORDER BY event_type, outcome")
total = sum(r["n"] for r in rows)
by_type: dict[str, dict] = {}
for r in rows:
    by_type.setdefault(r["event_type"], {})[r["outcome"]] = r["n"]
print(f"total outcomes labelled: {total}  (plan target >300; <30 = no stats at all)")
type_gate = {}
for et, oc in sorted(by_type.items()):
    labelled = oc.get("true_positive", 0) + oc.get("false_positive", 0)
    ok = labelled >= 30
    type_gate[et] = {"labelled_tp_fp": labelled, "ge_30": ok, "counts": oc}
    print(f"  {et:24} TP+FP={labelled:<4} {'OK' if ok else 'INSUFFICIENT (<30)'}  {oc}")
report["T11_1"] = {"total": total, "by_type": type_gate}

# --- T11.3 snapshot completeness ---------------------------------------
_print_header("T11.3 snapshot completeness (4 types; span target >=90d)")
EXPECTED_TYPES = ("trends", "cross_pillar", "supply_chain", "graph")
rows = _q("""SELECT snapshot_type, COUNT(*) n,
                    MIN(captured_at) first, MAX(captured_at) last,
                    julianday(MAX(captured_at)) - julianday(MIN(captured_at)) span_days
             FROM system_snapshots GROUP BY snapshot_type""")
present = {r["snapshot_type"]: r for r in rows}
snap = {}
for t in EXPECTED_TYPES:
    r = present.get(t)
    if r:
        span = round(r["span_days"] or 0, 1)
        print(f"  {t:14} n={r['n']:<5} span={span}d  [{r['first']} .. {r['last']}]")
        snap[t] = {"n": r["n"], "span_days": span, "first": r["first"], "last": r["last"]}
    else:
        print(f"  {t:14} MISSING — no snapshots of this type")
        snap[t] = None
report["T11_3"] = snap

# --- T11.4 quality precision (SQL) vs get_quality_metrics() ------------
_print_header("T11.4 quality precision per event_type (SQL vs function)")
sql_rows = _q("""SELECT event_type,
                        COUNT(*) FILTER (WHERE outcome='true_positive') tp,
                        COUNT(*) FILTER (WHERE outcome='false_positive') fp
                 FROM event_outcomes
                 WHERE outcome IN ('true_positive','false_positive')
                 GROUP BY event_type""")
sql_prec = {}
for r in sql_rows:
    denom = r["tp"] + r["fp"]
    sql_prec[r["event_type"]] = round(r["tp"] / denom, 3) if denom else None
func = db.get_quality_metrics(days=100000)  # effectively all-time
func_prec = {et: b.get("precision") for et, b in func["by_type"].items()}
match = sql_prec == {k: v for k, v in func_prec.items() if k in sql_prec}
print(f"  SQL precision      : {sql_prec}")
print(f"  function precision : {func_prec}")
print(f"  match: {match}  (note: get_quality_metrics filters by marked_at window)")
report["T11_4"] = {"sql": sql_prec, "function": func_prec, "match": match}

# --- P2 idempotency / duplicates ---------------------------------------
_print_header("P2 idempotency — duplicate detection")
art_dups = _q("SELECT COUNT(*) - COUNT(DISTINCT url) d FROM articles")[0]["d"]
oc_dups = _q("SELECT COUNT(*) - COUNT(DISTINCT event_type || '|' || event_id) d "
             "FROM event_outcomes")[0]["d"]
print(f"  article URL duplicates        : {art_dups}  (target 0)")
print(f"  outcome (type,id) duplicates  : {oc_dups}  (target 0)")
report["P2"] = {"article_url_duplicates": art_dups, "outcome_key_duplicates": oc_dups}

# --- T11.2 determinism --------------------------------------------------
_print_header(f"T11.2 backtest determinism (replay last {args.det_days}d twice)")
end = datetime.now(timezone.utc)
start = end - timedelta(days=args.det_days)
r1 = replay_window(start.isoformat(), end.isoformat())
r2 = replay_window(start.isoformat(), end.isoformat())
det = json.dumps(r1, sort_keys=True, default=str) == json.dumps(r2, sort_keys=True, default=str)
print(f"  identical across two runs: {det}  "
      f"({r1['summary'].get('tick_count', 0)} ticks, "
      f"{r1['summary'].get('total_articles_observed', 0)} articles observed)")
report["T11_2"] = {"deterministic": det, "summary": r1["summary"]}

# --- leakage test (critical) -------------------------------------------
_print_header("Leakage test (critical, binary) — onda_11_leakage_test.py")
leak = subprocess.run([sys.executable, os.path.join(_HERE, "onda_11_leakage_test.py")],
                      capture_output=True, text=True)
leak_pass = leak.returncode == 0
print((leak.stdout or "").strip() or (leak.stderr or "").strip())
print(f"  RESULT: {'PASS' if leak_pass else 'FAIL'}")
report["leakage_test"] = {"pass": leak_pass}

# --- JSON blob for pasting back ----------------------------------------
print("\n" + "=" * 8 + " JSON (paste this back) " + "=" * 8)
print(json.dumps(report, indent=2, default=str))
