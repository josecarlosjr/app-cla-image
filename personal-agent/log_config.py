"""Centralized logging with RotatingFileHandler.

All modules should call ``setup_logging()`` once at import time instead
of configuring ``logging.basicConfig`` individually.  The rotating handler
keeps disk usage bounded to ~30 MB (10 MB x 3 backups).
"""

import os
import logging
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
