from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVENTS = ROOT / "data" / "cost" / "events.json"
_IO_LOCK = threading.RLock()


def _path_events() -> Path:
    return Path(os.getenv("AGENTHUB_COST_EVENTS_PATH", str(DEFAULT_EVENTS)))


def _ensure(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("[]\n", encoding="utf-8")


def _safe_load_rows(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return []
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return rows if isinstance(rows, list) else []


def _atomic_save_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def load_events() -> list[dict[str, Any]]:
    path = _path_events()
    with _IO_LOCK:
        _ensure(path)
        return _safe_load_rows(path)


def save_events(rows: list[dict[str, Any]]) -> None:
    path = _path_events()
    with _IO_LOCK:
        _ensure(path)
        _atomic_save_rows(path, rows)


def append_event(row: dict[str, Any]) -> None:
    path = _path_events()
    with _IO_LOCK:
        _ensure(path)
        rows = _safe_load_rows(path)
        rows.append(row)
        _atomic_save_rows(path, rows)
