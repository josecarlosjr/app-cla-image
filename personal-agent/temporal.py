"""Temporal pattern detection — acceleration & divergence (F5a).

Pure SQL + Python. Zero LLM cost.

- Acceleration: category getting new articles at an unusually high (or low) rate
  compared to its 7-day baseline.
- Divergence: significant change in the number of distinct sources covering a
  category — signals broadening or narrowing media attention.

Called from feeds.py after each fetch cycle; results exposed via /api/temporal
and consumed by notifications.py for proactive alerts.
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from database import (
    record_temporal_snapshots,
    get_temporal_snapshots,
    prune_temporal_snapshots,
)

logger = logging.getLogger(__name__)

ACCELERATION_THRESHOLD = 2.0
DECELERATION_THRESHOLD = 0.3
DIVERGENCE_THRESHOLD = 0.4
MIN_BASELINE_BUCKETS = 12
MIN_ABSOLUTE_INCREASE = 3
WINDOW_HOURS = 12
BASELINE_DAYS = 7


def record_article_stats(new_articles: list[dict]) -> None:
    """Record hourly snapshot from newly inserted articles."""
    if not new_articles:
        return

    bucket = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")

    by_cat: dict[str, dict] = {}
    for a in new_articles:
        cat = a.get("category", "")
        if not cat:
            continue
        if cat not in by_cat:
            by_cat[cat] = {"count": 0, "sources": set()}
        by_cat[cat]["count"] += 1
        by_cat[cat]["sources"].add(a.get("source", ""))

    snapshots = [
        {
            "category": cat,
            "bucket": bucket,
            "article_count": info["count"],
            "source_count": len(info["sources"]),
        }
        for cat, info in by_cat.items()
    ]

    record_temporal_snapshots(snapshots)
    prune_temporal_snapshots(days=30)
    logger.info("Temporal: recorded stats for %d categories.", len(snapshots))


def detect_acceleration(
    window_hours: int = WINDOW_HOURS,
    baseline_days: int = BASELINE_DAYS,
) -> list[dict]:
    """Detect categories with unusual article velocity."""
    total_hours = baseline_days * 24
    snapshots = get_temporal_snapshots(hours=total_hours)
    if not snapshots:
        return []

    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
    ).strftime("%Y-%m-%dT%H")

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for s in snapshots:
        by_cat[s["category"]].append(s)

    results = []
    for cat, snaps in by_cat.items():
        recent = [s for s in snaps if s["bucket"] >= cutoff]
        baseline = [s for s in snaps if s["bucket"] < cutoff]

        baseline_buckets = len(set(s["bucket"] for s in baseline))
        if baseline_buckets < MIN_BASELINE_BUCKETS:
            continue

        current_total = sum(s["article_count"] for s in recent)

        baseline_total = sum(s["article_count"] for s in baseline)
        baseline_rate = (baseline_total / baseline_buckets) * window_hours
        if baseline_rate < 1:
            baseline_rate = 1.0

        ratio = current_total / baseline_rate
        absolute_diff = current_total - baseline_rate

        status = "normal"
        if ratio >= ACCELERATION_THRESHOLD and absolute_diff >= MIN_ABSOLUTE_INCREASE:
            status = "accelerating"
        elif baseline_rate >= 3 and ratio <= DECELERATION_THRESHOLD:
            status = "decelerating"

        results.append({
            "category": cat,
            "current_articles": current_total,
            "baseline_rate": round(baseline_rate, 1),
            "ratio": round(ratio, 2),
            "status": status,
            "window_hours": window_hours,
        })

    results.sort(key=lambda x: x["ratio"], reverse=True)
    return results


def detect_divergence(
    window_hours: int = WINDOW_HOURS,
    baseline_days: int = BASELINE_DAYS,
) -> list[dict]:
    """Detect unusual source distribution changes per category."""
    total_hours = baseline_days * 24
    snapshots = get_temporal_snapshots(hours=total_hours)
    if not snapshots:
        return []

    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
    ).strftime("%Y-%m-%dT%H")

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for s in snapshots:
        by_cat[s["category"]].append(s)

    results = []
    for cat, snaps in by_cat.items():
        recent = [s for s in snaps if s["bucket"] >= cutoff]
        baseline = [s for s in snaps if s["bucket"] < cutoff]

        if not recent or len(baseline) < MIN_BASELINE_BUCKETS:
            continue

        recent_avg = sum(s["source_count"] for s in recent) / len(recent)
        baseline_avg = sum(s["source_count"] for s in baseline) / len(baseline)

        if baseline_avg < 1:
            continue

        source_ratio = recent_avg / baseline_avg
        divergence_score = abs(source_ratio - 1.0)

        status = "normal"
        detail = ""
        if divergence_score >= DIVERGENCE_THRESHOLD:
            status = "diverging"
            if source_ratio > 1:
                detail = (
                    f"{recent_avg:.0f} fontes ativas "
                    f"(vs {baseline_avg:.0f} habitual) — cobertura ampliada"
                )
            else:
                detail = (
                    f"{recent_avg:.0f} fontes ativas "
                    f"(vs {baseline_avg:.0f} habitual) — cobertura reduzida"
                )

        results.append({
            "category": cat,
            "recent_sources_avg": round(recent_avg, 1),
            "baseline_sources_avg": round(baseline_avg, 1),
            "source_ratio": round(source_ratio, 2),
            "divergence": round(divergence_score, 2),
            "status": status,
            "detail": detail,
        })

    results.sort(key=lambda x: x["divergence"], reverse=True)
    return results


def get_temporal_summary() -> dict:
    """Combined temporal analysis for API and notifications."""
    accel = detect_acceleration()
    diverg = detect_divergence()

    alerts: list[dict] = []
    for a in accel:
        if a["status"] == "accelerating":
            alerts.append({
                "type": "acceleration",
                "category": a["category"],
                "ratio": a["ratio"],
                "message": (
                    f"{a['category']}: {a['current_articles']} artigos em "
                    f"{a['window_hours']}h ({a['ratio']}x do normal)"
                ),
            })
        elif a["status"] == "decelerating":
            alerts.append({
                "type": "deceleration",
                "category": a["category"],
                "ratio": a["ratio"],
                "message": (
                    f"{a['category']}: apenas {a['current_articles']} artigos em "
                    f"{a['window_hours']}h ({a['ratio']}x — abaixo do normal)"
                ),
            })

    for d in diverg:
        if d["status"] == "diverging":
            alerts.append({
                "type": "divergence",
                "category": d["category"],
                "divergence": d["divergence"],
                "message": d["detail"],
            })

    return {
        "acceleration": accel,
        "divergence": diverg,
        "alerts": alerts,
        "window_hours": WINDOW_HOURS,
        "baseline_days": BASELINE_DAYS,
    }
