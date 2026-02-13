from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_LOCK = threading.Lock()


def _lock_for(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_LOCK:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


def _ensure_json_list_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("[]\n", encoding="utf-8")


def read_json_list(path: Path) -> list[dict[str, Any]]:
    lock = _lock_for(path)
    with lock:
        _ensure_json_list_file(path)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            return []
        return [row for row in loaded if isinstance(row, dict)]


def write_json_list(path: Path, rows: list[dict[str, Any]]) -> None:
    lock = _lock_for(path)
    with lock:
        _ensure_json_list_file(path)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        tmp_path.replace(path)


def append_json_list_row(path: Path, row: dict[str, Any]) -> None:
    rows = read_json_list(path)
    rows.append(row)
    write_json_list(path, rows)
