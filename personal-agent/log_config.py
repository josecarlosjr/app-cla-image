"""Centralized logging with RotatingFileHandler.

All modules should call ``setup_logging()`` once at import time instead
of configuring ``logging.basicConfig`` individually.  The rotating handler
keeps disk usage bounded to ~30 MB (10 MB x 3 backups).

Also exposes :func:`log_event` for emitting structured single-line JSON
events alongside the existing text logs — designed for scraping from
``kubectl logs`` with ``jq``.
"""

import json
import os
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

DATA_DIR = os.getenv("DATA_DIR", "/data")
LOG_FILE = os.path.join(DATA_DIR, "agent.log")

_configured = False

MAX_LOG_BYTES = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 3


def setup_logging() -> None:
    global _configured
    if _configured:
        return
    _configured = True

    os.makedirs(DATA_DIR, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT,
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    root.addHandler(stream_handler)


# ---------------------------------------------------------------------------
# Structured event logging (Onda 11 opt #8 — observabilidade P3)
# ---------------------------------------------------------------------------
#
# A separate logger so callers can later route structured events to their own
# handler / sink without touching the text logs. Each call emits a single
# JSON line on the root handlers (kubectl-friendly), e.g.:
#
#   2026-06-15 ... [INFO] pia.event: {"ts": "...", "event": "backtest_run",
#                                     "duration_ms": 42, "run_id": 17, ...}
#
# Parse with: ``kubectl logs ... | grep 'pia.event' | awk -F': ' '{print $4}' | jq .``

_event_logger = logging.getLogger("pia.event")


def log_event(event: str, **fields) -> None:
    """Emit a single-line JSON structured event.

    Always sets ``ts`` (UTC ISO) and ``event``. Caller supplies the rest
    as kwargs. Values are serialised with ``default=str``, so dicts, ints,
    floats, strings, lists of those, and datetime-like objects all work.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    _event_logger.info(json.dumps(record, default=str, ensure_ascii=False))
