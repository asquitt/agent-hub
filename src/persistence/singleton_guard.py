from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path
from typing import IO

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK_PATH = ROOT / "data" / "agenthub-singleton.lock"

_lock_handle: IO[str] | None = None
_lock_path: Path | None = None
_lock_refcount = 0
_state_lock = threading.RLock()


def _declared_count(name: str) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return 1
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def acquire_singleton_guard() -> None:
    """Fail closed when the SQLite deployment is started more than once."""
    global _lock_handle, _lock_path, _lock_refcount

    for name in (
        "AGENTHUB_API_WORKERS",
        "WEB_CONCURRENCY",
        "AGENTHUB_API_REPLICAS",
        "AGENTHUB_REPLICAS",
    ):
        if _declared_count(name) != 1:
            raise RuntimeError(f"unsupported SQLite topology: {name} must equal 1")

    path = Path(os.environ.get("AGENTHUB_SINGLETON_LOCK_PATH", str(DEFAULT_LOCK_PATH)))
    with _state_lock:
        if _lock_handle is not None:
            if _lock_path != path:
                raise RuntimeError(
                    "singleton lock path cannot change while AgentHub is running"
                )
            _lock_refcount += 1
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise RuntimeError(
                "unsupported SQLite topology: another AgentHub process owns the data lock"
            ) from exc

        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        _lock_handle = handle
        _lock_path = path
        _lock_refcount = 1


def release_singleton_guard() -> None:
    global _lock_handle, _lock_path, _lock_refcount
    with _state_lock:
        if _lock_handle is None:
            _lock_refcount = 0
            return
        _lock_refcount -= 1
        if _lock_refcount > 0:
            return
        try:
            fcntl.flock(_lock_handle.fileno(), fcntl.LOCK_UN)
        finally:
            _lock_handle.close()
            _lock_handle = None
            _lock_path = None
            _lock_refcount = 0
