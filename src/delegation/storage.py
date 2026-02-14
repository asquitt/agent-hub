from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RECORDS = ROOT / "data" / "delegations" / "records.json"
DEFAULT_BALANCES = ROOT / "data" / "delegations" / "balances.json"
DEFAULT_DB = ROOT / "data" / "delegations" / "delegation.db"


def _path_records() -> Path:
    return Path(os.getenv("AGENTHUB_DELEGATION_RECORDS_PATH", str(DEFAULT_RECORDS)))


def _path_balances() -> Path:
    return Path(os.getenv("AGENTHUB_DELEGATION_BALANCES_PATH", str(DEFAULT_BALANCES)))


def _path_db() -> Path:
    return Path(os.getenv("AGENTHUB_DELEGATION_DB_PATH", str(DEFAULT_DB)))


class DelegationStorage:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._state: tuple[str, str, str] | None = None

    def _desired_state(self, db_path: str | Path | None = None) -> tuple[str, str, str]:
        resolved_db = str(Path(db_path) if db_path is not None else _path_db())
        return (resolved_db, str(_path_records()), str(_path_balances()))

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
            state = self._desired_state()
            if self._conn is not None and state == self._state:
                return
            self._reconfigure_locked(Path(state[0]))

    def _reconfigure_locked(self, db_path: Path) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = self._connect(db_path)
        apply_scope_migrations(self._conn, "delegation")
        self._state = self._desired_state(db_path=db_path)
        self._bootstrap_from_legacy_files()

    def _bootstrap_from_legacy_files(self) -> None:
        assert self._conn is not None
        record_count = int(
            self._conn.execute("SELECT COUNT(*) AS count FROM delegation_records").fetchone()["count"]
        )
        balance_count = int(
            self._conn.execute("SELECT COUNT(*) AS count FROM delegation_balances").fetchone()["count"]
        )
        if record_count > 0 or balance_count > 0:
            return

        records_path = _path_records()
        balances_path = _path_balances()
        records: list[dict[str, Any]] = []
        balances: dict[str, float] = {}

        if records_path.exists():
            loaded = json.loads(records_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                records = [dict(row) for row in loaded if isinstance(row, dict)]

        if balances_path.exists():
            loaded = json.loads(balances_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                for row in loaded:
                    if not isinstance(row, dict):
                        continue
                    balances[str(row.get("agent_id"))] = float(row.get("balance_usd", 0.0))

        if not records and not balances:
            return

        with self._conn:
            for row in records:
                delegation_id = str(row.get("delegation_id", ""))
                if not delegation_id:
                    continue
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO delegation_records(
                        delegation_id,
                        requester_agent_id,
                        delegate_agent_id,
                        status,
                        created_at,
                        updated_at,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        delegation_id,
                        str(row.get("requester_agent_id", "")),
                        str(row.get("delegate_agent_id", "")),
                        str(row.get("status", "unknown")),
                        str(row.get("created_at", "")),
                        str(row.get("updated_at", "")),
                        json.dumps(row, sort_keys=True),
                    ),
                )

            for agent_id, balance in sorted(balances.items()):
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO delegation_balances(agent_id, balance_usd)
                    VALUES (?, ?)
                    """,
                    (agent_id, float(balance)),
                )

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            desired = self._desired_state(db_path=db_path)
            self._reconfigure_locked(Path(desired[0]))

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            desired = self._desired_state(db_path=db_path)
            self._reconfigure_locked(Path(desired[0]))
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM delegation_records")
                self._conn.execute("DELETE FROM delegation_balances")
                self._conn.execute("DELETE FROM delegation_idempotency")
                self._conn.execute("DELETE FROM delegation_queue_state")

    def load_records(self) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT payload_json
                FROM delegation_records
                ORDER BY updated_at DESC, delegation_id
                """
            ).fetchall()
            return [json.loads(str(row["payload_json"])) for row in rows]

    def append_record(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            delegation_id = str(row.get("delegation_id", ""))
            if not delegation_id:
                raise ValueError("delegation_id is required")
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO delegation_records(
                        delegation_id,
                        requester_agent_id,
                        delegate_agent_id,
                        status,
                        created_at,
                        updated_at,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        delegation_id,
                        str(row.get("requester_agent_id", "")),
                        str(row.get("delegate_agent_id", "")),
                        str(row.get("status", "unknown")),
                        str(row.get("created_at", "")),
                        str(row.get("updated_at", "")),
                        json.dumps(row, sort_keys=True),
                    ),
                )

    def get_record(self, delegation_id: str) -> dict[str, Any] | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT payload_json FROM delegation_records WHERE delegation_id = ?",
                (delegation_id,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(str(row["payload_json"]))

    def load_balances(self) -> dict[str, float]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute("SELECT agent_id, balance_usd FROM delegation_balances ORDER BY agent_id").fetchall()
            return {str(row["agent_id"]): float(row["balance_usd"]) for row in rows}

    def save_balances(self, balances: dict[str, float]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM delegation_balances")
                for agent_id, balance in sorted(balances.items()):
                    self._conn.execute(
                        "INSERT INTO delegation_balances(agent_id, balance_usd) VALUES (?, ?)",
                        (agent_id, float(balance)),
                    )

    def deduct_balance(self, agent_id: str, amount: float) -> float:
        """Atomically deduct from balance. Returns new balance. Raises if insufficient."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                row = self._conn.execute(
                    "SELECT balance_usd FROM delegation_balances WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()
                current = float(row["balance_usd"]) if row else 1000.0
                if current < amount:
                    raise ValueError("insufficient balance")
                new_balance = round(current - amount, 6)
                self._conn.execute(
                    "INSERT OR REPLACE INTO delegation_balances(agent_id, balance_usd) VALUES (?, ?)",
                    (agent_id, new_balance),
                )
                return new_balance

    def credit_balance(self, agent_id: str, amount: float) -> float:
        """Atomically credit balance. Returns new balance."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                row = self._conn.execute(
                    "SELECT balance_usd FROM delegation_balances WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()
                current = float(row["balance_usd"]) if row else 0.0
                new_balance = round(current + amount, 6)
                self._conn.execute(
                    "INSERT OR REPLACE INTO delegation_balances(agent_id, balance_usd) VALUES (?, ?)",
                    (agent_id, new_balance),
                )
                return new_balance

    def reserve_idempotency(self, owner: str, idempotency_key: str, request_hash: str) -> dict[str, Any]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                try:
                    self._conn.execute(
                        """
                        INSERT INTO delegation_idempotency(owner, idempotency_key, request_hash, status, response_json)
                        VALUES (?, ?, ?, 'pending', NULL)
                        """,
                        (owner, idempotency_key, request_hash),
                    )
                    return {"state": "reserved"}
                except sqlite3.IntegrityError:
                    row = self._conn.execute(
                        """
                        SELECT request_hash, status, response_json
                        FROM delegation_idempotency
                        WHERE owner = ? AND idempotency_key = ?
                        """,
                        (owner, idempotency_key),
                    ).fetchone()
                    if row is None:
                        return {"state": "reserved"}
                    stored_hash = str(row["request_hash"])
                    if stored_hash != request_hash:
                        return {"state": "mismatch"}
                    if row["response_json"]:
                        return {"state": "response", "response": json.loads(str(row["response_json"]))}
                    return {"state": "pending"}

    def finalize_idempotency(self, owner: str, idempotency_key: str, response: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE delegation_idempotency
                    SET status = 'completed',
                        response_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE owner = ? AND idempotency_key = ?
                    """,
                    (json.dumps(response, sort_keys=True), owner, idempotency_key),
                )

    def clear_idempotency(self, owner: str, idempotency_key: str) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    "DELETE FROM delegation_idempotency WHERE owner = ? AND idempotency_key = ?",
                    (owner, idempotency_key),
                )

    def get_idempotency_response(self, owner: str, idempotency_key: str) -> dict[str, Any] | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT response_json
                FROM delegation_idempotency
                WHERE owner = ? AND idempotency_key = ? AND response_json IS NOT NULL
                """,
                (owner, idempotency_key),
            ).fetchone()
            if row is None:
                return None
            return json.loads(str(row["response_json"]))

    def upsert_queue_state(self, delegation_id: str, status: str, increment_attempt: bool = False, last_error: str | None = None) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                existing = self._conn.execute(
                    "SELECT attempt_count FROM delegation_queue_state WHERE delegation_id = ?",
                    (delegation_id,),
                ).fetchone()
                attempt_count = int(existing["attempt_count"]) if existing else 0
                if increment_attempt:
                    attempt_count += 1
                self._conn.execute(
                    """
                    INSERT INTO delegation_queue_state(delegation_id, status, attempt_count, last_error, updated_at)
                    VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    ON CONFLICT(delegation_id) DO UPDATE SET
                        status = excluded.status,
                        attempt_count = excluded.attempt_count,
                        last_error = excluded.last_error,
                        updated_at = excluded.updated_at
                    """,
                    (delegation_id, status, attempt_count, last_error),
                )

    def get_queue_state(self, delegation_id: str) -> dict[str, Any] | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT delegation_id, status, attempt_count, last_error, updated_at
                FROM delegation_queue_state
                WHERE delegation_id = ?
                """,
                (delegation_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "delegation_id": str(row["delegation_id"]),
                "status": str(row["status"]),
                "attempt_count": int(row["attempt_count"]),
                "last_error": row["last_error"],
                "updated_at": str(row["updated_at"]),
            }


_STORAGE = DelegationStorage()


def load_records() -> list[dict[str, Any]]:
    return _STORAGE.load_records()


def append_record(row: dict[str, Any]) -> None:
    _STORAGE.append_record(row)


def get_record(delegation_id: str) -> dict[str, Any] | None:
    return _STORAGE.get_record(delegation_id)


def load_balances() -> dict[str, float]:
    return _STORAGE.load_balances()


def save_balances(balances: dict[str, float]) -> None:
    _STORAGE.save_balances(balances)


def deduct_balance(agent_id: str, amount: float) -> float:
    return _STORAGE.deduct_balance(agent_id, amount)


def credit_balance(agent_id: str, amount: float) -> float:
    return _STORAGE.credit_balance(agent_id, amount)


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)


def reserve_idempotency(owner: str, idempotency_key: str, request_hash: str) -> dict[str, Any]:
    return _STORAGE.reserve_idempotency(owner=owner, idempotency_key=idempotency_key, request_hash=request_hash)


def finalize_idempotency(owner: str, idempotency_key: str, response: dict[str, Any]) -> None:
    _STORAGE.finalize_idempotency(owner=owner, idempotency_key=idempotency_key, response=response)


def clear_idempotency(owner: str, idempotency_key: str) -> None:
    _STORAGE.clear_idempotency(owner=owner, idempotency_key=idempotency_key)


def get_idempotency_response(owner: str, idempotency_key: str) -> dict[str, Any] | None:
    return _STORAGE.get_idempotency_response(owner=owner, idempotency_key=idempotency_key)


def upsert_queue_state(delegation_id: str, status: str, increment_attempt: bool = False, last_error: str | None = None) -> None:
    _STORAGE.upsert_queue_state(
        delegation_id=delegation_id,
        status=status,
        increment_attempt=increment_attempt,
        last_error=last_error,
    )


def get_queue_state(delegation_id: str) -> dict[str, Any] | None:
    return _STORAGE.get_queue_state(delegation_id)
