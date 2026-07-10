"""
HackerAI - Unified Logging
Centralized logging untuk semua tools.
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime

from .config import LOG_DIR, LOG_LEVEL, VERBOSE

LOG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logger(name: str, level: str = None) -> logging.Logger:
    """Factory: create/return logger dengan format konsisten.

    Args:
        name: Nama logger (biasanya __name__)
        level: Log level override (default: dari env HAI_LOG_LEVEL atau INFO)

    Returns:
        logging.Logger instance
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # sudah di-setup sebelumnya

    level = (level or LOG_LEVEL).upper()
    logger.setLevel(getattr(logging, level, logging.INFO))

    # ── Formatter ──────────────────────────────────────
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── File handler ───────────────────────────────────
    log_file = LOG_DIR / f"hackerai_{datetime.now().strftime('%Y%m%d')}.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # ── Console handler ────────────────────────────────
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if VERBOSE else logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


def get_logger(name: str = None) -> logging.Logger:
    """Dapatkan logger yang sudah ada atau buat baru dengan default level."""
    return setup_logger(name or "__main__")
