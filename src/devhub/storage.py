from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "devhub" / "devhub.db"


def _path_db() -> Path:
    return Path(os.getenv("AGENTHUB_DEVHUB_DB_PATH", str(DEFAULT_DB)))


class DevHubStorage:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._state: str | None = None

    def _desired_state(self, db_path: str | Path | None = None) -> str:
        return str(Path(db_path) if db_path is not None else _path_db())

    def _connect(self, db_path: Path) -> sqlite3.Connection:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = self._desired_state()
            if self._conn is not None and desired == self._state:
                return
            self._reconfigure_locked(Path(desired))

    def _reconfigure_locked(self, db_path: Path) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = self._connect(db_path)
        apply_scope_migrations(self._conn, "devhub")
        self._state = self._desired_state(db_path=db_path)

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)))

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)))
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM devhub_promotions")
                self._conn.execute("DELETE FROM devhub_release_decisions")
                self._conn.execute("DELETE FROM devhub_release_reviews")

    def upsert_review(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            payload = json.dumps(row, sort_keys=True)
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO devhub_release_reviews(
                        review_id, agent_id, version, requested_by, status,
                        approvals_required, approvals_count, rejections_count,
                        created_at, updated_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(review_id) DO UPDATE SET
                        status = excluded.status,
                        approvals_required = excluded.approvals_required,
                        approvals_count = excluded.approvals_count,
                        rejections_count = excluded.rejections_count,
                        updated_at = excluded.updated_at,
                        payload_json = excluded.payload_json
                    """,
                    (
                        str(row["review_id"]),
                        str(row["agent_id"]),
                        str(row["version"]),
                        str(row["requested_by"]),
                        str(row["status"]),
                        int(row["approvals_required"]),
                        int(row["approvals_count"]),
                        int(row["rejections_count"]),
                        str(row["created_at"]),
                        str(row["updated_at"]),
                        payload,
                    ),
                )

    def get_review(self, review_id: str) -> dict[str, Any] | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT payload_json FROM devhub_release_reviews WHERE review_id = ?",
                (review_id,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(str(row["payload_json"]))

    def list_reviews(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            if agent_id is None:
                rows = self._conn.execute(
                    "SELECT payload_json FROM devhub_release_reviews ORDER BY updated_at DESC, review_id"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT payload_json
                    FROM devhub_release_reviews
                    WHERE agent_id = ?
                    ORDER BY updated_at DESC, review_id
                    """,
                    (agent_id,),
                ).fetchall()
            return [json.loads(str(row["payload_json"])) for row in rows]

    def insert_decision(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO devhub_release_decisions(review_id, actor, decision, note, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            str(row["review_id"]),
                            str(row["actor"]),
                            str(row["decision"]),
                            row.get("note"),
                            str(row["created_at"]),
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise ValueError("actor already submitted decision for this review") from exc

    def list_decisions(self, review_id: str) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT review_id, actor, decision, note, created_at
                FROM devhub_release_decisions
                WHERE review_id = ?
                ORDER BY created_at, decision_id
                """,
                (review_id,),
            ).fetchall()
            return [
                {
                    "review_id": str(row["review_id"]),
                    "actor": str(row["actor"]),
                    "decision": str(row["decision"]),
                    "note": row["note"],
                    "created_at": str(row["created_at"]),
                }
                for row in rows
            ]

    def insert_promotion(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            payload = json.dumps(row, sort_keys=True)
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO devhub_promotions(
                        promotion_id, review_id, agent_id, version, promoted_by, status, created_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(row["promotion_id"]),
                        str(row["review_id"]),
                        str(row["agent_id"]),
                        str(row["version"]),
                        str(row["promoted_by"]),
                        str(row["status"]),
                        str(row["created_at"]),
                        payload,
                    ),
                )

    def get_promotion_by_review(self, review_id: str) -> dict[str, Any] | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT payload_json FROM devhub_promotions WHERE review_id = ?",
                (review_id,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(str(row["payload_json"]))

    def list_promotions(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            if agent_id is None:
                rows = self._conn.execute(
                    "SELECT payload_json FROM devhub_promotions ORDER BY created_at DESC, promotion_id"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT payload_json
                    FROM devhub_promotions
                    WHERE agent_id = ?
                    ORDER BY created_at DESC, promotion_id
                    """,
                    (agent_id,),
                ).fetchall()
            return [json.loads(str(row["payload_json"])) for row in rows]


_STORAGE = DevHubStorage()


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def upsert_review(row: dict[str, Any]) -> None:
    _STORAGE.upsert_review(row)


def get_review(review_id: str) -> dict[str, Any] | None:
    return _STORAGE.get_review(review_id)


def list_reviews(agent_id: str | None = None) -> list[dict[str, Any]]:
    return _STORAGE.list_reviews(agent_id=agent_id)


def insert_decision(row: dict[str, Any]) -> None:
    _STORAGE.insert_decision(row)


def list_decisions(review_id: str) -> list[dict[str, Any]]:
    return _STORAGE.list_decisions(review_id=review_id)


def insert_promotion(row: dict[str, Any]) -> None:
    _STORAGE.insert_promotion(row)


def get_promotion_by_review(review_id: str) -> dict[str, Any] | None:
    return _STORAGE.get_promotion_by_review(review_id=review_id)


def list_promotions(agent_id: str | None = None) -> list[dict[str, Any]]:
    return _STORAGE.list_promotions(agent_id=agent_id)
