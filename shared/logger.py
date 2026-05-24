"""
Single logger config used by every bot.

Usage:
    from shared.logger import get_logger
    log = get_logger(__name__)
    log.info("hello")
"""
from __future__ import annotations

import logging
import sys
from .config import settings

_configured = False


def get_logger(name: str) -> logging.Logger:
    global _configured
    if not _configured:
        logging.basicConfig(
            level=settings.LOG_LEVEL,
            format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
            datefmt="%H:%M:%S",
            stream=sys.stdout,
        )
        _configured = True
    return logging.getLogger(name)
