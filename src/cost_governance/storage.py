from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COST_EVENTS = ROOT / "data" / "cost" / "events.json"
DEFAULT_DB = ROOT / "data" / "billing" / "billing.db"


def _path_legacy_events() -> Path:
    return Path(os.getenv("AGENTHUB_COST_EVENTS_PATH", str(DEFAULT_COST_EVENTS)))


def _path_db() -> Path:
    if os.getenv("AGENTHUB_COST_DB_PATH"):
        return Path(str(os.getenv("AGENTHUB_COST_DB_PATH")))
    if os.getenv("AGENTHUB_BILLING_DB_PATH"):
        return Path(str(os.getenv("AGENTHUB_BILLING_DB_PATH")))
    return Path(str(DEFAULT_DB))


class MeteringStorage:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._state: tuple[str, str] | None = None

    def _desired_state(self, db_path: str | Path | None = None) -> tuple[str, str]:
        resolved_db = str(Path(db_path) if db_path is not None else _path_db())
        return (resolved_db, str(_path_legacy_events()))

    def _connect(self, db_path: Path) -> sqlite3.Connection:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _reconfigure_locked(self, db_path: Path) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = self._connect(db_path)
        apply_scope_migrations(self._conn, "billing")
        self._state = self._desired_state(db_path=db_path)
        self._bootstrap_legacy_events()

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = self._desired_state()
            if self._conn is not None and desired == self._state:
                return
            self._reconfigure_locked(Path(desired[0]))

    def _bootstrap_legacy_events(self) -> None:
        assert self._conn is not None
        existing = int(self._conn.execute("SELECT COUNT(*) AS count FROM billing_metering_events").fetchone()["count"])
        if existing > 0:
            return
        legacy_path = _path_legacy_events()
        if not legacy_path.exists():
            return
        raw = legacy_path.read_text(encoding="utf-8")
        if not raw.strip():
            return
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            return
        if not isinstance(rows, list):
            return
        with self._conn:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                payload = dict(row)
                payload.setdefault("event_id", str(uuid.uuid4()))
                payload.setdefault("timestamp", "")
                payload.setdefault("actor", "unknown")
                payload.setdefault("operation", "unknown")
                payload.setdefault("cost_usd", 0.0)
                payload.setdefault("metadata", {})
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO billing_metering_events(
                        event_id, timestamp, actor, operation, cost_usd, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(payload["event_id"]),
                        str(payload["timestamp"]),
                        str(payload["actor"]),
                        str(payload["operation"]),
                        round(float(payload["cost_usd"]), 6),
                        json.dumps(payload.get("metadata", {}), sort_keys=True),
                    ),
                )

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)[0]))

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)[0]))
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM billing_metering_events")

    def append_event(self, row: dict[str, Any]) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            payload = dict(row)
            payload["event_id"] = str(payload.get("event_id") or uuid.uuid4())
            payload["timestamp"] = str(payload.get("timestamp") or "")
            payload["actor"] = str(payload.get("actor") or "unknown")
            payload["operation"] = str(payload.get("operation") or "unknown")
            payload["cost_usd"] = round(float(payload.get("cost_usd", 0.0)), 6)
            payload["metadata"] = payload.get("metadata", {})
            if not isinstance(payload["metadata"], dict):
                payload["metadata"] = {}
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO billing_metering_events(
                        event_id, timestamp, actor, operation, cost_usd, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["event_id"],
                        payload["timestamp"],
                        payload["actor"],
                        payload["operation"],
                        payload["cost_usd"],
                        json.dumps(payload["metadata"], sort_keys=True),
                    ),
                )
            return payload

    def load_events(self) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT event_id, timestamp, actor, operation, cost_usd, metadata_json
                FROM billing_metering_events
                ORDER BY timestamp, event_id
                """
            ).fetchall()
            return [
                {
                    "event_id": str(row["event_id"]),
                    "timestamp": str(row["timestamp"]),
                    "actor": str(row["actor"]),
                    "operation": str(row["operation"]),
                    "cost_usd": round(float(row["cost_usd"]), 6),
                    "metadata": json.loads(str(row["metadata_json"])),
                }
                for row in rows
            ]

    def save_events(self, rows: list[dict[str, Any]]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM billing_metering_events")
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    payload = dict(row)
                    payload["event_id"] = str(payload.get("event_id") or uuid.uuid4())
                    payload["timestamp"] = str(payload.get("timestamp") or "")
                    payload["actor"] = str(payload.get("actor") or "unknown")
                    payload["operation"] = str(payload.get("operation") or "unknown")
                    payload["cost_usd"] = round(float(payload.get("cost_usd", 0.0)), 6)
                    metadata = payload.get("metadata", {})
                    if not isinstance(metadata, dict):
                        metadata = {}
                    self._conn.execute(
                        """
                        INSERT INTO billing_metering_events(
                            event_id, timestamp, actor, operation, cost_usd, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            payload["event_id"],
                            payload["timestamp"],
                            payload["actor"],
                            payload["operation"],
                            payload["cost_usd"],
                            json.dumps(metadata, sort_keys=True),
                        ),
                    )


_STORAGE = MeteringStorage()


def load_events() -> list[dict[str, Any]]:
    return _STORAGE.load_events()


def save_events(rows: list[dict[str, Any]]) -> None:
    _STORAGE.save_events(rows)


def append_event(row: dict[str, Any]) -> dict[str, Any]:
    return _STORAGE.append_event(row)


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)
