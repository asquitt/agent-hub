"""Sub-Agent Spawn Controls — policies and limits on agent-initiated agent creation.

Enforces spawn limits, depth restrictions, and scope inheritance rules
when agents create sub-agents during execution.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

_log = logging.getLogger("agenthub.spawn_controls")

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "runtime" / "runtime.db"


def _db_path() -> Path:
    return Path(os.getenv("AGENTHUB_RUNTIME_DB_PATH", str(DEFAULT_DB)))


# Default spawn limits
DEFAULT_MAX_SPAWN_DEPTH = 3
DEFAULT_MAX_CONCURRENT_SPAWNS = 5
DEFAULT_MAX_TOTAL_SPAWNS = 20


class SpawnControlStore:
    """SQLite-backed spawn control policy and tracking."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._db_path: str | None = None

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = str(_db_path())
            if self._conn is not None and self._db_path == desired:
                return
            if self._conn is not None:
                self._conn.close()
            db = Path(desired)
            db.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(db), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
            self._init_tables()
            self._db_path = desired

    def _init_tables(self) -> None:
        assert self._conn is not None
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS spawn_policies (
                agent_id TEXT PRIMARY KEY,
                max_depth INTEGER NOT NULL DEFAULT 3,
                max_concurrent INTEGER NOT NULL DEFAULT 5,
                max_total INTEGER NOT NULL DEFAULT 20,
                allowed_agent_types_json TEXT NOT NULL DEFAULT '[]',
                scope_inheritance TEXT NOT NULL DEFAULT 'attenuate',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE IF NOT EXISTS spawn_records (
                spawn_id TEXT PRIMARY KEY,
                parent_agent_id TEXT NOT NULL,
                child_agent_id TEXT NOT NULL,
                sandbox_id TEXT NOT NULL,
                depth INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                scopes_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                terminated_at TEXT DEFAULT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_spawn_records_parent
                ON spawn_records(parent_agent_id);
            CREATE INDEX IF NOT EXISTS idx_spawn_records_sandbox
                ON spawn_records(sandbox_id);
        """)

    def set_spawn_policy(
        self,
        *,
        agent_id: str,
        max_depth: int = DEFAULT_MAX_SPAWN_DEPTH,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT_SPAWNS,
        max_total: int = DEFAULT_MAX_TOTAL_SPAWNS,
        allowed_agent_types: list[str] | None = None,
        scope_inheritance: str = "attenuate",
    ) -> dict[str, Any]:
        """Set spawn control policy for an agent."""
        if scope_inheritance not in ("attenuate", "inherit", "none"):
            raise ValueError(f"invalid scope_inheritance: {scope_inheritance}")
        self._ensure_ready()
        types = allowed_agent_types or []
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO spawn_policies
                        (agent_id, max_depth, max_concurrent, max_total,
                         allowed_agent_types_json, scope_inheritance)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (agent_id, max_depth, max_concurrent, max_total,
                     json.dumps(types), scope_inheritance),
                )
        return {
            "agent_id": agent_id,
            "max_depth": max_depth,
            "max_concurrent": max_concurrent,
            "max_total": max_total,
            "allowed_agent_types": types,
            "scope_inheritance": scope_inheritance,
        }

    def check_spawn_allowed(
        self,
        *,
        parent_agent_id: str,
        child_agent_type: str = "",
        current_depth: int = 0,
    ) -> dict[str, Any]:
        """Check if a spawn is allowed under current policy and limits."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None

            # Get policy (or use defaults)
            row = self._conn.execute(
                "SELECT * FROM spawn_policies WHERE agent_id = ?",
                (parent_agent_id,),
            ).fetchone()

            max_depth = int(row["max_depth"]) if row else DEFAULT_MAX_SPAWN_DEPTH
            max_concurrent = int(row["max_concurrent"]) if row else DEFAULT_MAX_CONCURRENT_SPAWNS
            max_total = int(row["max_total"]) if row else DEFAULT_MAX_TOTAL_SPAWNS
            allowed_types = json.loads(row["allowed_agent_types_json"]) if row else []

            # Check depth
            if current_depth >= max_depth:
                return {
                    "allowed": False,
                    "reason": "max_depth_exceeded",
                    "message": f"spawn depth {current_depth} >= max {max_depth}",
                }

            # Check concurrent spawns
            active_count = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM spawn_records WHERE parent_agent_id = ? AND status = 'active'",
                (parent_agent_id,),
            ).fetchone()
            concurrent = int(active_count["cnt"]) if active_count else 0

            if concurrent >= max_concurrent:
                return {
                    "allowed": False,
                    "reason": "max_concurrent_exceeded",
                    "message": f"concurrent spawns {concurrent} >= max {max_concurrent}",
                }

            # Check total spawns
            total_count = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM spawn_records WHERE parent_agent_id = ?",
                (parent_agent_id,),
            ).fetchone()
            total = int(total_count["cnt"]) if total_count else 0

            if total >= max_total:
                return {
                    "allowed": False,
                    "reason": "max_total_exceeded",
                    "message": f"total spawns {total} >= max {max_total}",
                }

            # Check agent type
            if allowed_types and child_agent_type and child_agent_type not in allowed_types:
                return {
                    "allowed": False,
                    "reason": "agent_type_not_allowed",
                    "message": f"agent type '{child_agent_type}' not in allowed types",
                }

            return {
                "allowed": True,
                "current_depth": current_depth,
                "concurrent_spawns": concurrent,
                "total_spawns": total,
            }

    def record_spawn(
        self,
        *,
        parent_agent_id: str,
        child_agent_id: str,
        sandbox_id: str,
        depth: int = 1,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record a spawn event."""
        self._ensure_ready()
        spawn_id = f"spawn-{uuid.uuid4().hex[:12]}"
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO spawn_records
                        (spawn_id, parent_agent_id, child_agent_id, sandbox_id, depth, scopes_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (spawn_id, parent_agent_id, child_agent_id, sandbox_id,
                     depth, json.dumps(scopes or [])),
                )
        return {"spawn_id": spawn_id, "parent_agent_id": parent_agent_id, "child_agent_id": child_agent_id}

    def terminate_spawn(self, spawn_id: str) -> dict[str, Any]:
        """Mark a spawn as terminated."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE spawn_records
                    SET status = 'terminated',
                        terminated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE spawn_id = ?
                    """,
                    (spawn_id,),
                )
        return {"spawn_id": spawn_id, "status": "terminated"}

    def reset_for_tests(self) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                for table in ["spawn_records", "spawn_policies"]:
                    try:
                        self._conn.execute(f"DELETE FROM {table}")  # noqa: S608
                    except sqlite3.Error:
                        pass


SPAWN_STORE = SpawnControlStore()
