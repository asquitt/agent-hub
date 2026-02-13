from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.common.json_store import read_json_list

_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_LOCK = threading.Lock()
_CONNECTIONS: dict[str, sqlite3.Connection] = {}
_CACHE: dict[tuple[str, str, str], list[dict[str, Any]]] = {}


def _lock_for(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_LOCK:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


def _connect(db_path: Path) -> sqlite3.Connection:
    resolved = str(db_path.resolve())
    with _LOCKS_LOCK:
        conn = _CONNECTIONS.get(resolved)
    if conn is not None:
        return conn

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS collection_store (
            scope TEXT NOT NULL,
            collection_name TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (scope, collection_name)
        )
        """
    )
    with _LOCKS_LOCK:
        existing = _CONNECTIONS.get(resolved)
        if existing is not None:
            conn.close()
            return existing
        _CONNECTIONS[resolved] = conn
    return conn


def _normalize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if isinstance(row, dict)]


def _clone_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _seed_from_legacy_if_needed(
    conn: sqlite3.Connection,
    *,
    scope: str,
    collection_name: str,
    legacy_path: Path | None,
) -> list[dict[str, Any]] | None:
    if legacy_path is None or not legacy_path.exists():
        return None

    seeded_rows = _normalize_rows(read_json_list(legacy_path))
    if not seeded_rows:
        return None

    payload_json = json.dumps(seeded_rows, separators=(",", ":"))
    with conn:
        conn.execute(
            """
            INSERT INTO collection_store(scope, collection_name, payload_json)
            VALUES (?, ?, ?)
            ON CONFLICT(scope, collection_name) DO UPDATE SET
              payload_json = excluded.payload_json,
              updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            """,
            (scope, collection_name, payload_json),
        )
    return seeded_rows


def _cache_key(*, db_path: Path, scope: str, collection_name: str) -> tuple[str, str, str]:
    return (str(db_path.resolve()), scope, collection_name)


def read_collection(
    *,
    db_path: Path,
    scope: str,
    collection_name: str,
    legacy_path: Path | None = None,
) -> list[dict[str, Any]]:
    lock = _lock_for(db_path)
    with lock:
        key = _cache_key(db_path=db_path, scope=scope, collection_name=collection_name)
        cached = _CACHE.get(key)
        if cached is not None:
            return _clone_rows(cached)

        conn = _connect(db_path)
        row = conn.execute(
            """
            SELECT payload_json
            FROM collection_store
            WHERE scope = ? AND collection_name = ?
            """,
            (scope, collection_name),
        ).fetchone()

        if row is None:
            seeded = _seed_from_legacy_if_needed(
                conn,
                scope=scope,
                collection_name=collection_name,
                legacy_path=legacy_path,
            )
            if seeded is not None:
                normalized_seeded = _normalize_rows(seeded)
                _CACHE[key] = _clone_rows(normalized_seeded)
                return _clone_rows(normalized_seeded)
            _CACHE[key] = []
            return []

        loaded = json.loads(str(row["payload_json"]))
        if not isinstance(loaded, list):
            _CACHE[key] = []
            return []
        normalized = _normalize_rows(loaded)
        _CACHE[key] = _clone_rows(normalized)
        return _clone_rows(normalized)


def write_collection(
    *,
    db_path: Path,
    scope: str,
    collection_name: str,
    rows: list[dict[str, Any]],
) -> None:
    lock = _lock_for(db_path)
    with lock:
        key = _cache_key(db_path=db_path, scope=scope, collection_name=collection_name)
        conn = _connect(db_path)
        normalized = _normalize_rows(rows)
        payload_json = json.dumps(normalized, separators=(",", ":"))
        with conn:
            conn.execute(
                """
                INSERT INTO collection_store(scope, collection_name, payload_json)
                VALUES (?, ?, ?)
                ON CONFLICT(scope, collection_name) DO UPDATE SET
                  payload_json = excluded.payload_json,
                  updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                """,
                (scope, collection_name, payload_json),
            )
        _CACHE[key] = _clone_rows(normalized)


def append_collection_row(
    *,
    db_path: Path,
    scope: str,
    collection_name: str,
    row: dict[str, Any],
    legacy_path: Path | None = None,
) -> None:
    lock = _lock_for(db_path)
    with lock:
        key = _cache_key(db_path=db_path, scope=scope, collection_name=collection_name)
        conn = _connect(db_path)
        current = conn.execute(
            """
            SELECT payload_json
            FROM collection_store
            WHERE scope = ? AND collection_name = ?
            """,
            (scope, collection_name),
        ).fetchone()

        if current is None:
            existing = _seed_from_legacy_if_needed(
                conn,
                scope=scope,
                collection_name=collection_name,
                legacy_path=legacy_path,
            ) or []
        else:
            loaded = json.loads(str(current["payload_json"]))
            existing = _normalize_rows(loaded if isinstance(loaded, list) else [])

        existing.append(dict(row))
        payload_json = json.dumps(existing, separators=(",", ":"))
        with conn:
            conn.execute(
                """
                INSERT INTO collection_store(scope, collection_name, payload_json)
                VALUES (?, ?, ?)
                ON CONFLICT(scope, collection_name) DO UPDATE SET
                  payload_json = excluded.payload_json,
                  updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                """,
                (scope, collection_name, payload_json),
            )
        _CACHE[key] = _clone_rows(existing)
