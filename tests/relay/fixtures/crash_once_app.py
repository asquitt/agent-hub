from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.api.app import app
from src.relay.defaults import RELAY_SERVICE

_MARKER_ENV = "AGENTHUB_RELAY_CRASH_ONCE_MARKER"
_CRASH_EXIT_CODE = 91


def _configure_crash_once() -> None:
    raw_marker = os.environ.get(_MARKER_ENV, "").strip()
    if not raw_marker:
        raise RuntimeError(f"{_MARKER_ENV} is required")
    marker = Path(raw_marker)
    if marker.exists():
        return

    def crash_after_remote_result(_result: dict[str, Any]) -> None:
        marker.write_text("remote-result-observed\n", encoding="utf-8")
        os._exit(_CRASH_EXIT_CODE)

    RELAY_SERVICE._after_remote_result = crash_after_remote_result


_configure_crash_once()

__all__ = ["app"]
