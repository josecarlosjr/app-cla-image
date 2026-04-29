"""Proactive notifications — detect situations requiring user attention.

Runs as a CronJob (every 4h). Checks:
- Job candidatures with no update in >7 days -> follow-up reminder
- Saved notes marked as 'todo' -> pending tasks
- New high-confidence patterns matching user's known interests (facts)
- Crypto watchlist (extracted from facts) moving significantly

Uses user facts to personalise. Anti-spam via notifications_state.json.
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx

import database as db

DATA_DIR = os.getenv("DATA_DIR", "/data")
STATE_FILE = os.path.join(DATA_DIR, "notifications_state.json")
MEMORY_FILE = os.path.join(DATA_DIR, "memory.json")
JOBS_FILE = os.path.join(DATA_DIR, "jobs_tracker.json")
NOTES_DIR = os.path.join(DATA_DIR, "notes")
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

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_ALLOWED_USER_ID")

COOLDOWN_HOURS = {
    "job_stale": 48,
    "pattern_alta": 12,
    "note_todo": 24,
    "temporal": 12,
}
JOB_STALE_DAYS = 7
JOB_ACTIVE_STATUSES = {"applied", "interview", "pending"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: str, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return default
    return default


def _save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _can_notify(state: dict, key: str, cooldown_hours: int) -> bool:
    last = state.get("last_sent", {}).get(key)
    if not last:
        return True
    last_time = datetime.fromisoformat(last)
    return datetime.now(timezone.utc) - last_time > timedelta(hours=cooldown_hours)


def _mark_sent(state: dict, key: str):
    state.setdefault("last_sent", {})[key] = datetime.now(timezone.utc).isoformat()


async def _send_telegram(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        for i in range(0, len(message), 4096):
            await client.post(
                url,
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": message[i : i + 4096],
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )


# ---------------------------------------------------------------------------
# Checkers
# ---------------------------------------------------------------------------

def _check_stale_jobs(state: dict) -> list[str]:
    jobs = _load_json(JOBS_FILE, [])
    if not isinstance(jobs, list):
        return []

    alerts = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=JOB_STALE_DAYS)

    for job in jobs:
        if job.get("status", "").lower() not in JOB_ACTIVE_STATUSES:
            continue
        try:
            updated = datetime.fromisoformat(job.get("updated", ""))
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
        except (ValueError, KeyError):
            continue

        if updated < cutoff:
            key = f"job_stale_{job['id']}"
            if _can_notify(state, key, COOLDOWN_HOURS["job_stale"]):
                days_stale = (datetime.now(timezone.utc) - updated).days
                alerts.append(
                    f"Candidatura parada ha *{days_stale} dias*: "
                    f"*{job.get('role', '?')}* @ *{job.get('company', '?')}* "
                    f"(status: {job.get('status', '?')}). Enviar follow-up?"
                )
                _mark_sent(state, key)

    return alerts


def _check_todo_notes(state: dict) -> list[str]:
    if not os.path.isdir(NOTES_DIR):
        return []

    alerts = []
    for filename in sorted(os.listdir(NOTES_DIR)):
        if not filename.endswith(".md"):
            continue
        path = os.path.join(NOTES_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            continue

        if "todo" not in content.lower() and "a fazer" not in content.lower():
            continue

        key = f"note_todo_{filename}"
        if _can_notify(state, key, COOLDOWN_HOURS["note_todo"]):
            title = filename.replace(".md", "").replace("_", " ")
            alerts.append(f"Nota pendente: *{title}*")
            _mark_sent(state, key)

    return alerts


def _check_high_confidence_patterns(state: dict, user_facts: list[str]) -> list[str]:
    patterns = db.get_patterns()

    user_interest_keywords = set()
    for fact in user_facts:
        for word in fact.lower().split():
            if len(word) > 4:
                user_interest_keywords.add(word)

    alerts = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    for pattern in patterns:
        if pattern.get("confidence") != "ALTA":
            continue

        try:
            ts = datetime.fromisoformat(pattern.get("timestamp", ""))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
        except (ValueError, KeyError):
            continue

        analysis = pattern.get("analysis", "").lower()
        matches = user_interest_keywords & set(analysis.split())
        if not matches and user_interest_keywords:
            continue

        key = f"pattern_{pattern.get('id', pattern.get('timestamp', ''))}"
        if _can_notify(state, key, COOLDOWN_HOURS["pattern_alta"]):
            cats = ", ".join(pattern.get("categories", []))
            alerts.append(
                f"Padrao de *alta confianca* relevante pra voce ({cats}):\n\n"
                f"{pattern.get('analysis', '')[:600]}"
            )
            _mark_sent(state, key)

    return alerts


def _check_temporal_alerts(state: dict) -> list[str]:
    from temporal import get_temporal_summary

    summary = get_temporal_summary()
    alerts = []
    for alert in summary.get("alerts", []):
        key = f"temporal_{alert['type']}_{alert['category']}"
        if _can_notify(state, key, COOLDOWN_HOURS["temporal"]):
            emoji = {"acceleration": "🔺", "deceleration": "🔻", "divergence": "🔀"}.get(
                alert["type"], "📊"
            )
            alerts.append(f"{emoji} *TEMPORAL:* {alert['message']}")
            _mark_sent(state, key)
    return alerts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    logger.info("Notifications checker starting...")
    state = _load_json(STATE_FILE, {"last_sent": {}})

    memory = _load_json(MEMORY_FILE, {"facts": []})
    user_facts = memory.get("facts", []) if isinstance(memory, dict) else []

    all_alerts: list[str] = []
    all_alerts.extend(_check_stale_jobs(state))
    all_alerts.extend(_check_todo_notes(state))
    all_alerts.extend(_check_high_confidence_patterns(state, user_facts))
    all_alerts.extend(_check_temporal_alerts(state))

    if not all_alerts:
        logger.info("No proactive notifications to send.")
        _save_json(STATE_FILE, state)
        return

    header = f"*NOTIFICACOES PROATIVAS* ({len(all_alerts)})\n\n"
    body = "\n\n---\n\n".join(all_alerts)
    message = header + body

    await _send_telegram(message)
    _save_json(STATE_FILE, state)

    logger.info("Sent %d proactive notifications.", len(all_alerts))


if __name__ == "__main__":
    asyncio.run(main())
