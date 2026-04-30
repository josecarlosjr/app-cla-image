"""Supply chain anomaly detection — graph propagation + Telegram alerts.

Runs as part of the notifications CronJob (every 4h). Detects:

1. **Spike**: a node's mention count in 24h > 2x its 7-day daily average
2. **Negative signal**: dominant sentiment is shortage/price_up/disruption
3. **Chain propagation**: if a mineral shows spike+negative → all dependents
   (components, products) inherit a risk signal
4. **Correlated chain**: 3+ consecutive nodes in a dependency path show
   correlated signals within 7 days → high-confidence alert

Zero LLM cost — pure SQL + Python graph traversal.
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from database import (
    get_supply_chain_mention_counts,
    get_supply_chain_mentions,
)
from supply_chain import (
    ensure_seeded,
    get_full_graph,
    get_dependents,
    get_impact_chain,
)

logger = logging.getLogger(__name__)

SPIKE_THRESHOLD = 2.0
MIN_MENTIONS_24H = 3
NEGATIVE_SENTIMENTS = {"shortage", "price_up", "disruption"}
POSITIVE_SENTIMENTS = {"surplus", "price_down", "expansion"}
CORRELATED_CHAIN_MIN = 3


def _get_node_names() -> dict[str, str]:
    graph = get_full_graph()
    return {n["id"]: n["name"] for n in graph["nodes"]}


def _detect_spikes() -> list[dict]:
    counts_24h = get_supply_chain_mention_counts(hours=24)
    counts_7d = get_supply_chain_mention_counts(hours=168)

    spikes = []
    for node_id, data_24h in counts_24h.items():
        total_24h = data_24h["total"]
        if total_24h < MIN_MENTIONS_24H:
            continue

        data_7d = counts_7d.get(node_id, {"total": 0})
        daily_avg_7d = data_7d["total"] / 7.0 if data_7d["total"] > 0 else 0

        if daily_avg_7d > 0 and total_24h / daily_avg_7d >= SPIKE_THRESHOLD:
            ratio = total_24h / daily_avg_7d

            sentiments = data_24h.get("sentiments", {})
            neg_count = sum(sentiments.get(s, 0) for s in NEGATIVE_SENTIMENTS)
            pos_count = sum(sentiments.get(s, 0) for s in POSITIVE_SENTIMENTS)
            dominant = "negative" if neg_count > pos_count else (
                "positive" if pos_count > neg_count else "neutral"
            )

            spikes.append({
                "node_id": node_id,
                "total_24h": total_24h,
                "daily_avg_7d": round(daily_avg_7d, 1),
                "ratio": round(ratio, 1),
                "dominant_signal": dominant,
                "sentiments": sentiments,
            })

    return sorted(spikes, key=lambda s: s["ratio"], reverse=True)


def _propagate_risk(spikes: list[dict]) -> list[dict]:
    negative_spikes = [s for s in spikes if s["dominant_signal"] == "negative"]
    if not negative_spikes:
        return []

    propagated = []
    for spike in negative_spikes:
        dependents = get_dependents(spike["node_id"])
        if dependents:
            propagated.append({
                "source_node": spike["node_id"],
                "affected_nodes": dependents,
                "reason": spike,
            })

    return propagated


def _detect_correlated_chains() -> list[dict]:
    counts_7d = get_supply_chain_mention_counts(hours=168)

    active_nodes = set()
    for node_id, data in counts_7d.items():
        if data["total"] >= MIN_MENTIONS_24H:
            sentiments = data.get("sentiments", {})
            neg = sum(sentiments.get(s, 0) for s in NEGATIVE_SENTIMENTS)
            if neg >= 2:
                active_nodes.add(node_id)

    if len(active_nodes) < CORRELATED_CHAIN_MIN:
        return []

    chains = []
    for node_id in active_nodes:
        impact = get_impact_chain(node_id, max_depth=4)
        chain_nodes = [node_id] + [step["to"] for step in impact]
        correlated = [n for n in chain_nodes if n in active_nodes]

        if len(correlated) >= CORRELATED_CHAIN_MIN:
            chains.append({
                "root": node_id,
                "correlated_nodes": correlated,
                "chain_length": len(correlated),
                "full_path": chain_nodes,
            })

    seen = set()
    unique_chains = []
    for chain in sorted(chains, key=lambda c: c["chain_length"], reverse=True):
        key = frozenset(chain["correlated_nodes"])
        if key not in seen:
            seen.add(key)
            unique_chains.append(chain)

    return unique_chains


def analyze() -> dict:
    ensure_seeded()

    node_names = _get_node_names()
    spikes = _detect_spikes()
    propagated = _propagate_risk(spikes)
    correlated = _detect_correlated_chains()

    alerts = []

    for spike in spikes:
        name = node_names.get(spike["node_id"], spike["node_id"])
        signal_emoji = {
            "negative": "🔴", "positive": "🟢", "neutral": "🟡",
        }.get(spike["dominant_signal"], "⚪")

        alert_text = (
            f"{signal_emoji} *SPIKE:* _{name}_ "
            f"({spike['total_24h']} mencoes em 24h, "
            f"{spike['ratio']}x a media de 7d)"
        )

        sentiments = spike.get("sentiments", {})
        top_sentiments = sorted(sentiments.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_sentiments:
            sent_str = ", ".join(f"{s}: {c}" for s, c in top_sentiments)
            alert_text += f"\nSinais: {sent_str}"

        alerts.append({"type": "spike", "node_id": spike["node_id"], "text": alert_text})

    for prop in propagated:
        source_name = node_names.get(prop["source_node"], prop["source_node"])
        affected = [node_names.get(n, n) for n in prop["affected_nodes"]]
        alert_text = (
            f"⚠️ *RISCO NA CADEIA:* Pressao em _{source_name}_ "
            f"pode afetar: {', '.join(affected)}"
        )
        alerts.append({"type": "propagation", "node_id": prop["source_node"], "text": alert_text})

    for chain in correlated:
        root_name = node_names.get(chain["root"], chain["root"])
        chain_names = [node_names.get(n, n) for n in chain["correlated_nodes"]]
        alert_text = (
            f"🔗 *CADEIA CORRELACIONADA ({chain['chain_length']} nos):* "
            f"{' → '.join(chain_names)}\n"
            f"Sinais negativos simultaneos detectados na cadeia "
            f"a partir de _{root_name}_"
        )
        alerts.append({"type": "correlated_chain", "node_id": chain["root"], "text": alert_text})

    logger.info(
        "Supply chain analysis: %d spikes, %d propagations, %d correlated chains.",
        len(spikes), len(propagated), len(correlated),
    )

    return {
        "spikes": spikes,
        "propagated_risks": propagated,
        "correlated_chains": correlated,
        "alerts": alerts,
    }
