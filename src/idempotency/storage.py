from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "idempotency" / "idempotency.db"


def _path_db() -> Path:
    return Path(os.getenv("AGENTHUB_IDEMPOTENCY_DB_PATH", str(DEFAULT_DB)))


class IdempotencyStorage:
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

    def _reconfigure_locked(self, db_path: Path) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = self._connect(db_path)
        apply_scope_migrations(self._conn, "idempotency")
        self._state = self._desired_state(db_path=db_path)

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = self._desired_state()
            if self._conn is not None and desired == self._state:
                return
            self._reconfigure_locked(Path(desired))

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)))

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)))
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM idempotency_requests")

    def reserve(
        self,
        *,
        tenant_id: str,
        actor: str,
        method: str,
        route: str,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                try:
                    self._conn.execute(
                        """
                        INSERT INTO idempotency_requests(
                            tenant_id,
                            actor,
                            method,
                            route,
                            idempotency_key,
                            request_hash,
                            status
                        ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
                        """,
                        (tenant_id, actor, method, route, idempotency_key, request_hash),
                    )
                    return {"state": "reserved"}
                except sqlite3.IntegrityError:
                    row = self._conn.execute(
                        """
                        SELECT request_hash, status, http_status, content_type, headers_json, response_body_b64
                        FROM idempotency_requests
                        WHERE tenant_id = ? AND actor = ? AND method = ? AND route = ? AND idempotency_key = ?
                        """,
                        (tenant_id, actor, method, route, idempotency_key),
                    ).fetchone()
                    if row is None:
                        return {"state": "reserved"}
                    if str(row["request_hash"]) != request_hash:
                        return {"state": "mismatch"}
                    if row["response_body_b64"] is None:
                        return {"state": "pending"}
                    headers_payload = {}
                    if row["headers_json"] is not None:
                        loaded = json.loads(str(row["headers_json"]))
                        if isinstance(loaded, dict):
                            headers_payload = {str(k): str(v) for k, v in loaded.items()}
                    return {
                        "state": "response",
                        "response": {
                            "status_code": int(row["http_status"] or 200),
                            "content_type": str(row["content_type"] or "application/json"),
                            "headers": headers_payload,
                            "body": base64.b64decode(str(row["response_body_b64"]).encode("ascii")),
                        },
                    }

    def finalize(
        self,
        *,
        tenant_id: str,
        actor: str,
        method: str,
        route: str,
        idempotency_key: str,
        status_code: int,
        content_type: str,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            filtered_headers = {}
            for name, value in headers.items():
                lower = name.lower()
                if lower in {"date", "server", "content-length"}:
                    continue
                filtered_headers[name] = value
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE idempotency_requests
                    SET status = 'completed',
                        http_status = ?,
                        content_type = ?,
                        headers_json = ?,
                        response_body_b64 = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE tenant_id = ? AND actor = ? AND method = ? AND route = ? AND idempotency_key = ?
                    """,
                    (
                        int(status_code),
                        str(content_type),
                        json.dumps(filtered_headers, sort_keys=True),
                        base64.b64encode(body).decode("ascii"),
                        tenant_id,
                        actor,
                        method,
                        route,
                        idempotency_key,
                    ),
                )

    def clear(self, *, tenant_id: str, actor: str, method: str, route: str, idempotency_key: str) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    DELETE FROM idempotency_requests
                    WHERE tenant_id = ? AND actor = ? AND method = ? AND route = ? AND idempotency_key = ?
                    """,
                    (tenant_id, actor, method, route, idempotency_key),
                )


_STORAGE = IdempotencyStorage()


def reserve(
    *,
    tenant_id: str,
    actor: str,
    method: str,
    route: str,
    idempotency_key: str,
    request_hash: str,
) -> dict[str, Any]:
    return _STORAGE.reserve(
        tenant_id=tenant_id,
        actor=actor,
        method=method,
        route=route,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
    )


def finalize(
    *,
    tenant_id: str,
    actor: str,
    method: str,
    route: str,
    idempotency_key: str,
    status_code: int,
    content_type: str,
    headers: dict[str, str],
    body: bytes,
) -> None:
    _STORAGE.finalize(
        tenant_id=tenant_id,
        actor=actor,
        method=method,
        route=route,
        idempotency_key=idempotency_key,
        status_code=status_code,
        content_type=content_type,
        headers=headers,
        body=body,
    )


def clear(*, tenant_id: str, actor: str, method: str, route: str, idempotency_key: str) -> None:
    _STORAGE.clear(
        tenant_id=tenant_id,
        actor=actor,
        method=method,
        route=route,
        idempotency_key=idempotency_key,
    )


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)
