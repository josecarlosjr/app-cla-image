"""Cross-pillar correlation engine — consolidate events across pillars.

The app emits 3 kinds of events: patterns (cross-source clusters), supply
chain spikes (sudden mention surges with sentiment), and temporal alerts
(acceleration/deceleration/divergence). Historically each fires its own
Telegram notification, even when they describe the same underlying
phenomenon — e.g., a Chinese export ban shows up in geopolitica (pattern),
cadeia (gallium spike), and tecnologia (semi pattern) within hours.

This module collects all recent events tagged by pillar, groups them by
temporal proximity, and emits a single consolidated chain when 3+ pillars
are involved. Members are deduplicated via members_hash so the same chain
is not re-alerted on every cron tick.

Zero LLM cost — pure aggregation.
"""

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone

from database import (
    get_patterns,
    insert_cross_pillar_chain,
    chain_exists,
    prune_cross_pillar_chains,
)
from pillars import (
    PILLAR_LABELS,
    CATEGORY_TO_PILLAR,
    categories_to_pillars,
)

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_HOURS = 168  # 7 days
MIN_PILLARS_FOR_CHAIN = 3
SUPPRESSION_LOOKBACK_HOURS = 24


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _collect_pattern_events(hours: int) -> list[dict]:
    events = []
    for p in get_patterns(hours=hours):
        pillars = categories_to_pillars(p.get("categories", []))
        if not pillars:
            continue
        # Pick first matching pillar (priority order); pattern can imply only one chain seat
        pillar = sorted(pillars)[0]
        events.append({
            "kind": "pattern",
            "id": f"pattern_{p['id']}",
            "pillar": pillar,
            "category": (p.get("categories") or ["?"])[0],
            "timestamp": p.get("timestamp", _now()),
            "label": (p.get("analysis") or "")[:140].replace("\n", " ").strip(),
            "confidence": p.get("confidence", "MEDIA"),
            "source_count": p.get("num_sources", 0),
        })
    return events


def _collect_supply_chain_events(hours: int) -> list[dict]:
    try:
        from supply_chain_analyzer import analyze
    except ImportError:
        return []

    events = []
    try:
        result = analyze()
    except Exception as e:
        logger.warning("supply_chain_analyzer.analyze failed: %s", e)
        return []

    now = _now()
    for spike in result.get("spikes", []):
        events.append({
            "kind": "spike",
            "id": f"sc_spike_{spike['node_id']}",
            "pillar": "cadeia",
            "category": "minerais",
            "timestamp": now,
            "label": (
                f"spike: {spike['node_id']} ({spike['ratio']}x da media, "
                f"sinal: {spike['dominant_signal']})"
            ),
            "ratio": spike["ratio"],
            "signal": spike["dominant_signal"],
        })

    for chain in result.get("correlated_chains", []):
        events.append({
            "kind": "correlated_chain",
            "id": f"sc_correlated_chain_{chain['root']}",
            "pillar": "cadeia",
            "category": "minerais",
            "timestamp": now,
            "label": f"cadeia correlacionada de {chain['chain_length']} nos a partir de {chain['root']}",
        })

    return events


def _collect_temporal_events() -> list[dict]:
    try:
        from temporal import get_temporal_summary
    except ImportError:
        return []

    events = []
    now = _now()
    try:
        summary = get_temporal_summary()
    except Exception as e:
        logger.warning("temporal.get_temporal_summary failed: %s", e)
        return []

    for alert in summary.get("alerts", []):
        cat = alert.get("category", "")
        pillar = CATEGORY_TO_PILLAR.get(cat)
        if not pillar:
            continue
        events.append({
            "kind": "temporal",
            "id": f"temporal_{alert['type']}_{cat}",
            "pillar": pillar,
            "category": cat,
            "timestamp": now,
            "label": alert.get("message", ""),
            "alert_type": alert["type"],
        })
    return events


def collect_recent_events(hours: int = DEFAULT_WINDOW_HOURS) -> list[dict]:
    events = []
    events.extend(_collect_pattern_events(hours))
    events.extend(_collect_supply_chain_events(hours))
    events.extend(_collect_temporal_events())
    return events


def _members_hash(events: list[dict]) -> str:
    ids = sorted(e["id"] for e in events)
    return hashlib.md5("|".join(ids).encode()).hexdigest()[:16]


def detect_chains(
    *,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    min_pillars: int = MIN_PILLARS_FOR_CHAIN,
) -> list[dict]:
    """Return cross-pillar chains active in the recent window.

    For MVP, a single chain spans every active event in the window when
    3+ pillars are represented. Future: split by sub-window or topical
    clustering once we have entity normalisation.
    """
    events = collect_recent_events(hours=window_hours)
    if not events:
        return []

    by_pillar: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_pillar[e["pillar"]].append(e)

    if len(by_pillar) < min_pillars:
        return []

    timestamps = [e["timestamp"] for e in events if e.get("timestamp")]
    chain = {
        "members_hash": _members_hash(events),
        "window_start": min(timestamps) if timestamps else _now(),
        "window_end": max(timestamps) if timestamps else _now(),
        "pillars": sorted(by_pillar.keys()),
        "events": events,
        "events_by_pillar": {k: v for k, v in by_pillar.items()},
        "total_events": len(events),
    }
    return [chain]


def format_chain_alert(chain: dict) -> str:
    lines = [
        f"🔗 *EVENTO CROSS-PILLAR DETECTADO*",
        (
            f"Janela: {chain['total_events']} sinais em "
            f"{len(chain['pillars'])} pilares"
        ),
        "",
    ]
    for pillar in chain["pillars"]:
        events = chain["events_by_pillar"][pillar]
        label = PILLAR_LABELS.get(pillar, pillar)
        lines.append(f"*{label}* ({len(events)})")
        for e in events[:3]:
            kind_marker = {
                "pattern": "•",
                "spike": "🔴",
                "correlated_chain": "🔗",
                "temporal": "📊",
            }.get(e["kind"], "•")
            label_text = (e.get("label") or "").strip()
            if label_text:
                lines.append(f"  {kind_marker} {label_text[:120]}")
        if len(events) > 3:
            lines.append(f"  ...e mais {len(events) - 3}")
        lines.append("")
    return "\n".join(lines).rstrip()


def detect_and_persist_chains(
    *,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    min_pillars: int = MIN_PILLARS_FOR_CHAIN,
    suppression_hours: int = SUPPRESSION_LOOKBACK_HOURS,
) -> list[dict]:
    """Detect, dedupe via members_hash, persist, and return new chains.

    Already-alerted chains within `suppression_hours` are filtered out
    so the same combination of events is not re-sent on every cron tick.
    """
    chains = detect_chains(window_hours=window_hours, min_pillars=min_pillars)
    new_chains = []
    for chain in chains:
        if chain_exists(chain["members_hash"], since_hours=suppression_hours):
            logger.info("Chain %s suppressed (already alerted)", chain["members_hash"])
            continue
        chain_id = insert_cross_pillar_chain(chain)
        chain["id"] = chain_id
        new_chains.append(chain)

    prune_cross_pillar_chains(days=60)
    return new_chains


def get_suppressed_event_ids(*, hours: int = SUPPRESSION_LOOKBACK_HOURS) -> set[str]:
    """Return event IDs already covered by a recently emitted chain.

    Used by notifications to skip individual alerts that are part of a
    consolidated chain alert.
    """
    from database import get_cross_pillar_chains
    suppressed: set[str] = set()
    for chain in get_cross_pillar_chains(hours=hours):
        for event in chain.get("events", []):
            event_id = event.get("id")
            if event_id:
                suppressed.add(event_id)
    return suppressed
