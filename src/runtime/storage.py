from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations
from src.runtime.constants import DEFAULT_PROFILE_PRESETS, VALID_NETWORK_MODES, VALID_SANDBOX_STATES
from src.runtime.types import (
    ResourceLimits,
    SandboxExecution,
    SandboxInstance,
    SandboxLogEntry,
    SandboxMetricSnapshot,
    SandboxProfile,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "runtime" / "runtime.db"


def _path_db() -> Path:
    return Path(os.getenv("AGENTHUB_RUNTIME_DB_PATH", str(DEFAULT_DB)))


class RuntimeStorage:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._db_path: str | None = None
        self._seeded = False

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
            desired = str(_path_db())
            if self._conn is not None and self._db_path == desired:
                return
            self._reconfigure_locked(Path(desired))

    def _reconfigure_locked(self, db_path: Path) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = self._connect(db_path)
        apply_scope_migrations(self._conn, "sandbox")
        self._db_path = str(db_path)
        self._seeded = False

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            resolved = str(Path(db_path) if db_path is not None else _path_db())
            self._reconfigure_locked(Path(resolved))

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            resolved = str(Path(db_path) if db_path is not None else _path_db())
            self._reconfigure_locked(Path(resolved))
            assert self._conn is not None
            with self._conn:
                for table in [
                    "sandbox_metrics",
                    "sandbox_logs",
                    "sandbox_executions",
                    "sandbox_instances",
                    "sandbox_profiles",
                ]:
                    try:
                        self._conn.execute(f"DELETE FROM {table}")  # noqa: S608
                    except Exception:
                        pass
            self._seeded = False

    def _seed_default_profiles(self) -> None:
        if self._seeded:
            return
        assert self._conn is not None
        for preset in DEFAULT_PROFILE_PRESETS.values():
            existing = self._conn.execute(
                "SELECT 1 FROM sandbox_profiles WHERE name = ?", (preset["name"],)
            ).fetchone()
            if existing:
                continue
            profile_id = f"prof-{uuid.uuid4().hex[:12]}"
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO sandbox_profiles(
                        profile_id, name, description, cpu_cores, memory_mb,
                        timeout_seconds, network_mode, disk_io_mb, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        profile_id,
                        preset["name"],
                        preset["description"],
                        preset["cpu_cores"],
                        preset["memory_mb"],
                        preset["timeout_seconds"],
                        preset["network_mode"],
                        preset["disk_io_mb"],
                        "system",
                    ),
                )
        self._seeded = True

    # --- Profile CRUD ---

    def insert_profile(
        self,
        *,
        name: str,
        description: str,
        cpu_cores: float,
        memory_mb: int,
        timeout_seconds: int,
        network_mode: str,
        disk_io_mb: int,
        created_by: str,
    ) -> SandboxProfile:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._seed_default_profiles()
            profile_id = f"prof-{uuid.uuid4().hex[:12]}"
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO sandbox_profiles(
                            profile_id, name, description, cpu_cores, memory_mb,
                            timeout_seconds, network_mode, disk_io_mb, created_by
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            profile_id,
                            name,
                            description,
                            cpu_cores,
                            memory_mb,
                            timeout_seconds,
                            network_mode,
                            disk_io_mb,
                            created_by,
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"profile already exists: {name}") from exc
            return self._get_profile_locked(profile_id)

    def get_profile(self, profile_id: str) -> SandboxProfile:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._seed_default_profiles()
            return self._get_profile_locked(profile_id)

    def get_profile_by_name(self, name: str) -> SandboxProfile | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._seed_default_profiles()
            row = self._conn.execute(
                "SELECT * FROM sandbox_profiles WHERE name = ?", (name,)
            ).fetchone()
            if row is None:
                return None
            return _row_to_profile(row)

    def _get_profile_locked(self, profile_id: str) -> SandboxProfile:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM sandbox_profiles WHERE profile_id = ?", (profile_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"profile not found: {profile_id}")
        return _row_to_profile(row)

    def list_profiles(self) -> list[SandboxProfile]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._seed_default_profiles()
            rows = self._conn.execute(
                "SELECT * FROM sandbox_profiles ORDER BY name"
            ).fetchall()
            return [_row_to_profile(row) for row in rows]

    def delete_profile(self, profile_id: str) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    "DELETE FROM sandbox_profiles WHERE profile_id = ?", (profile_id,)
                )
                if result.rowcount == 0:
                    raise KeyError(f"profile not found: {profile_id}")

    # --- Instance CRUD ---

    def insert_instance(
        self,
        *,
        sandbox_id: str,
        profile_id: str | None,
        agent_id: str,
        owner: str,
        status: str,
        cpu_cores: float,
        memory_mb: int,
        timeout_seconds: int,
        network_mode: str,
        disk_io_mb: int,
        delegation_id: str | None = None,
        lease_id: str | None = None,
    ) -> SandboxInstance:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO sandbox_instances(
                        sandbox_id, profile_id, agent_id, owner, status,
                        cpu_cores, memory_mb, timeout_seconds, network_mode, disk_io_mb,
                        delegation_id, lease_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sandbox_id, profile_id, agent_id, owner, status,
                        cpu_cores, memory_mb, timeout_seconds, network_mode, disk_io_mb,
                        delegation_id, lease_id,
                    ),
                )
            return self._get_instance_locked(sandbox_id)

    def get_instance(self, sandbox_id: str) -> SandboxInstance:
        self._ensure_ready()
        with self._lock:
            return self._get_instance_locked(sandbox_id)

    def _get_instance_locked(self, sandbox_id: str) -> SandboxInstance:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM sandbox_instances WHERE sandbox_id = ?", (sandbox_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"sandbox not found: {sandbox_id}")
        return _row_to_instance(row)

    def update_instance_status(
        self,
        sandbox_id: str,
        status: str,
        *,
        started_at: str | None = None,
        terminated_at: str | None = None,
        termination_reason: str | None = None,
    ) -> SandboxInstance:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE sandbox_instances
                    SET status = ?,
                        started_at = COALESCE(?, started_at),
                        terminated_at = COALESCE(?, terminated_at),
                        termination_reason = COALESCE(?, termination_reason),
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE sandbox_id = ?
                    """,
                    (status, started_at, terminated_at, termination_reason, sandbox_id),
                )
            return self._get_instance_locked(sandbox_id)

    def list_instances(
        self,
        *,
        owner: str | None = None,
        agent_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[SandboxInstance]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            clauses: list[str] = []
            params: list[object] = []
            if owner is not None:
                clauses.append("owner = ?")
                params.append(owner)
            if agent_id is not None:
                clauses.append("agent_id = ?")
                params.append(agent_id)
            if status is not None:
                clauses.append("status = ?")
                params.append(status)
            where = " AND ".join(clauses) if clauses else "1=1"
            params.append(limit)
            rows = self._conn.execute(
                f"SELECT * FROM sandbox_instances WHERE {where} ORDER BY created_at DESC LIMIT ?",  # noqa: S608
                params,
            ).fetchall()
            return [_row_to_instance(row) for row in rows]

    # --- Execution CRUD ---

    def insert_execution(
        self,
        *,
        execution_id: str,
        sandbox_id: str,
        agent_id: str,
        owner: str,
        status: str,
        input_hash: str,
    ) -> SandboxExecution:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO sandbox_executions(
                        execution_id, sandbox_id, agent_id, owner, status, input_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (execution_id, sandbox_id, agent_id, owner, status, input_hash),
                )
            return self._get_execution_locked(execution_id)

    def get_execution(self, execution_id: str) -> SandboxExecution:
        self._ensure_ready()
        with self._lock:
            return self._get_execution_locked(execution_id)

    def _get_execution_locked(self, execution_id: str) -> SandboxExecution:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM sandbox_executions WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"execution not found: {execution_id}")
        return _row_to_execution(row)

    def update_execution(
        self,
        execution_id: str,
        *,
        status: str | None = None,
        output_hash: str | None = None,
        completed_at: str | None = None,
        duration_ms: float | None = None,
        exit_code: int | None = None,
        error_message: str | None = None,
    ) -> SandboxExecution:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            sets: list[str] = []
            params: list[object] = []
            if status is not None:
                sets.append("status = ?")
                params.append(status)
            if output_hash is not None:
                sets.append("output_hash = ?")
                params.append(output_hash)
            if completed_at is not None:
                sets.append("completed_at = ?")
                params.append(completed_at)
            if duration_ms is not None:
                sets.append("duration_ms = ?")
                params.append(duration_ms)
            if exit_code is not None:
                sets.append("exit_code = ?")
                params.append(exit_code)
            if error_message is not None:
                sets.append("error_message = ?")
                params.append(error_message)
            if not sets:
                return self._get_execution_locked(execution_id)
            params.append(execution_id)
            with self._conn:
                self._conn.execute(
                    f"UPDATE sandbox_executions SET {', '.join(sets)} WHERE execution_id = ?",  # noqa: S608
                    params,
                )
            return self._get_execution_locked(execution_id)

    def list_executions(
        self,
        *,
        sandbox_id: str | None = None,
        agent_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[SandboxExecution]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            clauses: list[str] = []
            params: list[object] = []
            if sandbox_id is not None:
                clauses.append("sandbox_id = ?")
                params.append(sandbox_id)
            if agent_id is not None:
                clauses.append("agent_id = ?")
                params.append(agent_id)
            if status is not None:
                clauses.append("status = ?")
                params.append(status)
            where = " AND ".join(clauses) if clauses else "1=1"
            params.append(limit)
            rows = self._conn.execute(
                f"SELECT * FROM sandbox_executions WHERE {where} ORDER BY started_at DESC LIMIT ?",  # noqa: S608
                params,
            ).fetchall()
            return [_row_to_execution(row) for row in rows]

    # --- Log methods ---

    def insert_log(
        self,
        *,
        sandbox_id: str,
        execution_id: str | None,
        level: str,
        message: str,
    ) -> SandboxLogEntry:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            log_id = f"log-{uuid.uuid4().hex[:12]}"
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO sandbox_logs(log_id, sandbox_id, execution_id, level, message)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (log_id, sandbox_id, execution_id, level, message),
                )
            row = self._conn.execute(
                "SELECT * FROM sandbox_logs WHERE log_id = ?", (log_id,)
            ).fetchone()
            assert row is not None
            return _row_to_log(row)

    def list_logs(
        self, sandbox_id: str, *, execution_id: str | None = None, limit: int = 200
    ) -> list[SandboxLogEntry]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            if execution_id:
                rows = self._conn.execute(
                    "SELECT * FROM sandbox_logs WHERE sandbox_id = ? AND execution_id = ? ORDER BY timestamp LIMIT ?",
                    (sandbox_id, execution_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM sandbox_logs WHERE sandbox_id = ? ORDER BY timestamp LIMIT ?",
                    (sandbox_id, limit),
                ).fetchall()
            return [_row_to_log(row) for row in rows]

    # --- Metric methods ---

    def insert_metric(
        self,
        *,
        sandbox_id: str,
        execution_id: str | None,
        cpu_used: float,
        memory_used_mb: int,
        disk_io_mb: float,
        network_bytes: int,
    ) -> SandboxMetricSnapshot:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            metric_id = f"met-{uuid.uuid4().hex[:12]}"
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO sandbox_metrics(
                        metric_id, sandbox_id, execution_id,
                        cpu_used, memory_used_mb, disk_io_mb, network_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (metric_id, sandbox_id, execution_id, cpu_used, memory_used_mb, disk_io_mb, network_bytes),
                )
            row = self._conn.execute(
                "SELECT * FROM sandbox_metrics WHERE metric_id = ?", (metric_id,)
            ).fetchone()
            assert row is not None
            return _row_to_metric(row)

    def list_metrics(
        self, sandbox_id: str, *, execution_id: str | None = None, limit: int = 100
    ) -> list[SandboxMetricSnapshot]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            if execution_id:
                rows = self._conn.execute(
                    "SELECT * FROM sandbox_metrics WHERE sandbox_id = ? AND execution_id = ? ORDER BY timestamp LIMIT ?",
                    (sandbox_id, execution_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM sandbox_metrics WHERE sandbox_id = ? ORDER BY timestamp LIMIT ?",
                    (sandbox_id, limit),
                ).fetchall()
            return [_row_to_metric(row) for row in rows]


# --- Singleton ---

_STORAGE = RuntimeStorage()
RUNTIME_STORAGE = _STORAGE


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


# --- Row converters ---


def _row_to_profile(row: sqlite3.Row) -> SandboxProfile:
    return SandboxProfile(
        profile_id=str(row["profile_id"]),
        name=str(row["name"]),
        description=str(row["description"]),
        resource_limits=ResourceLimits(
            cpu_cores=float(row["cpu_cores"]),
            memory_mb=int(row["memory_mb"]),
            timeout_seconds=int(row["timeout_seconds"]),
            network_mode=str(row["network_mode"]),
            disk_io_mb=int(row["disk_io_mb"]),
        ),
        created_by=str(row["created_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _row_to_instance(row: sqlite3.Row) -> SandboxInstance:
    return SandboxInstance(
        sandbox_id=str(row["sandbox_id"]),
        profile_id=row["profile_id"],
        agent_id=str(row["agent_id"]),
        owner=str(row["owner"]),
        status=str(row["status"]),
        resource_limits=ResourceLimits(
            cpu_cores=float(row["cpu_cores"]),
            memory_mb=int(row["memory_mb"]),
            timeout_seconds=int(row["timeout_seconds"]),
            network_mode=str(row["network_mode"]),
            disk_io_mb=int(row["disk_io_mb"]),
        ),
        delegation_id=row["delegation_id"],
        lease_id=row["lease_id"],
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        started_at=row["started_at"],
        terminated_at=row["terminated_at"],
        termination_reason=row["termination_reason"],
    )


def _row_to_execution(row: sqlite3.Row) -> SandboxExecution:
    return SandboxExecution(
        execution_id=str(row["execution_id"]),
        sandbox_id=str(row["sandbox_id"]),
        agent_id=str(row["agent_id"]),
        owner=str(row["owner"]),
        status=str(row["status"]),
        input_hash=str(row["input_hash"]),
        output_hash=row["output_hash"],
        started_at=str(row["started_at"]),
        completed_at=row["completed_at"],
        duration_ms=float(row["duration_ms"]) if row["duration_ms"] is not None else None,
        exit_code=int(row["exit_code"]) if row["exit_code"] is not None else None,
        error_message=row["error_message"],
    )


def _row_to_log(row: sqlite3.Row) -> SandboxLogEntry:
    return SandboxLogEntry(
        log_id=str(row["log_id"]),
        sandbox_id=str(row["sandbox_id"]),
        execution_id=row["execution_id"],
        level=str(row["level"]),
        message=str(row["message"]),
        timestamp=str(row["timestamp"]),
    )


def _row_to_metric(row: sqlite3.Row) -> SandboxMetricSnapshot:
    return SandboxMetricSnapshot(
        metric_id=str(row["metric_id"]),
        sandbox_id=str(row["sandbox_id"]),
        execution_id=row["execution_id"],
        cpu_used=float(row["cpu_used"]),
        memory_used_mb=int(row["memory_used_mb"]),
        disk_io_mb=float(row["disk_io_mb"]),
        network_bytes=int(row["network_bytes"]),
        timestamp=str(row["timestamp"]),
    )
