"""Structured JSON logging for AgentHub."""

from __future__ import annotations

import logging
import os
import sys

from pythonjsonlogger.json import JsonFormatter


def setup_logging() -> None:
    """Configure root logger with JSON formatter for production."""
    level = os.environ.get("AGENTHUB_LOG_LEVEL", "INFO").upper()

    handler = logging.StreamHandler(sys.stdout)
    formatter = JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        rename_fields={"asctime": "timestamp", "levelname": "level", "name": "logger"},
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level, logging.INFO))

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger."""
    return logging.getLogger(f"agenthub.{name}")
