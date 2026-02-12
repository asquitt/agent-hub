from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = ROOT / "data" / "registry" / "registry.db"


@dataclass
class VersionRecord:
    version: str
    manifest: dict[str, Any]
    eval_summary: dict[str, Any] = field(default_factory=lambda: {"tier1": "pending", "tier2": "pending", "tier3": "pending"})


@dataclass
class AgentRecord:
    agent_id: str
    tenant_id: str
    namespace: str
    slug: str
    owner: str
    status: str = "active"
    versions: list[VersionRecord] = field(default_factory=list)


class RegistryStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self.db_path = Path()
        # Backward-compatible attributes retained for tests and external imports.
        self.namespaces: dict[str, str] = {}
        self.agents: dict[str, AgentRecord] = {}
        self.idempotency_cache: dict[tuple[str, str], Any] = {}
        self.reconfigure(db_path=db_path)

    def _resolve_db_path(self, db_path: str | Path | None = None) -> Path:
        if db_path is not None:
            return Path(db_path)
        return Path(os.getenv("AGENTHUB_REGISTRY_DB_PATH", str(DEFAULT_DB_PATH)))

    def _connect(self, db_path: Path) -> sqlite3.Connection:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            resolved = self._resolve_db_path(db_path=db_path)
            if self._conn is not None:
                self._conn.close()
            self.db_path = resolved
            self._conn = self._connect(resolved)
            apply_scope_migrations(self._conn, "registry")
            self.idempotency_cache.clear()

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self.reconfigure(db_path=db_path)
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM registry_agent_versions")
                self._conn.execute("DELETE FROM registry_agents")
                self._conn.execute("DELETE FROM registry_namespaces")
            self.idempotency_cache.clear()
            self.namespaces.clear()
            self.agents.clear()

    def _load_versions(self, agent_id: str) -> list[VersionRecord]:
        assert self._conn is not None
        rows = self._conn.execute(
            """
            SELECT version, manifest_json, eval_summary_json
            FROM registry_agent_versions
            WHERE agent_id = ?
            ORDER BY created_at, version
            """,
            (agent_id,),
        ).fetchall()
        versions: list[VersionRecord] = []
        for row in rows:
            versions.append(
                VersionRecord(
                    version=str(row["version"]),
                    manifest=json.loads(str(row["manifest_json"])),
                    eval_summary=json.loads(str(row["eval_summary_json"])),
                )
            )
        return versions

    def reserve_namespace(self, namespace: str, owner: str, tenant_id: str = "tenant-default") -> None:
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT owner, tenant_id FROM registry_namespaces WHERE namespace = ?",
                (namespace,),
            ).fetchone()
            if row is None:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO registry_namespaces(namespace, owner, tenant_id) VALUES (?, ?, ?)",
                        (namespace, owner, tenant_id),
                    )
                self.namespaces[f"{tenant_id}:{namespace}"] = owner
                return
            if str(row["owner"]) != owner or str(row["tenant_id"]) != tenant_id:
                raise PermissionError("namespace already reserved by another owner")
            self.namespaces[f"{tenant_id}:{namespace}"] = owner

    def register_agent(
        self,
        namespace: str,
        manifest: dict[str, Any],
        owner: str,
        tenant_id: str = "tenant-default",
    ) -> AgentRecord:
        with self._lock:
            assert self._conn is not None
            slug = manifest["identity"]["id"]
            version = manifest["identity"]["version"]
            agent_id = f"{namespace}:{slug}"
            existing = self._conn.execute(
                "SELECT 1 FROM registry_agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if existing is not None:
                raise ValueError("agent already exists")

            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO registry_agents(agent_id, tenant_id, namespace, slug, owner, status)
                    VALUES (?, ?, ?, ?, ?, 'active')
                    """,
                    (agent_id, tenant_id, namespace, slug, owner),
                )
                self._conn.execute(
                    """
                    INSERT INTO registry_agent_versions(agent_id, version, manifest_json)
                    VALUES (?, ?, ?)
                    """,
                    (agent_id, version, json.dumps(manifest, sort_keys=True)),
                )
            record = AgentRecord(
                agent_id=agent_id,
                tenant_id=tenant_id,
                namespace=namespace,
                slug=slug,
                owner=owner,
                status="active",
                versions=[VersionRecord(version=version, manifest=manifest)],
            )
            self.agents[agent_id] = record
            return record

    def list_agents(
        self,
        namespace: str | None = None,
        status: str | None = None,
        tenant_id: str | None = None,
    ) -> list[AgentRecord]:
        with self._lock:
            assert self._conn is not None
            query = "SELECT agent_id, tenant_id, namespace, slug, owner, status FROM registry_agents WHERE 1=1"
            params: list[str] = []
            if tenant_id is not None:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            if namespace is not None:
                query += " AND namespace = ?"
                params.append(namespace)
            if status is not None:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY agent_id"

            rows = self._conn.execute(query, tuple(params)).fetchall()
            records: list[AgentRecord] = []
            for row in rows:
                agent_id = str(row["agent_id"])
                records.append(
                    AgentRecord(
                        agent_id=agent_id,
                        tenant_id=str(row["tenant_id"]),
                        namespace=str(row["namespace"]),
                        slug=str(row["slug"]),
                        owner=str(row["owner"]),
                        status=str(row["status"]),
                        versions=self._load_versions(agent_id),
                    )
                )
            return records

    def get_agent(self, agent_id: str, tenant_id: str | None = None) -> AgentRecord:
        with self._lock:
            assert self._conn is not None
            if tenant_id is None:
                row = self._conn.execute(
                    """
                    SELECT agent_id, tenant_id, namespace, slug, owner, status
                    FROM registry_agents
                    WHERE agent_id = ?
                    """,
                    (agent_id,),
                ).fetchone()
            else:
                row = self._conn.execute(
                    """
                    SELECT agent_id, tenant_id, namespace, slug, owner, status
                    FROM registry_agents
                    WHERE agent_id = ? AND tenant_id = ?
                    """,
                    (agent_id, tenant_id),
                ).fetchone()
            if row is None:
                raise KeyError("agent not found")
            return AgentRecord(
                agent_id=str(row["agent_id"]),
                tenant_id=str(row["tenant_id"]),
                namespace=str(row["namespace"]),
                slug=str(row["slug"]),
                owner=str(row["owner"]),
                status=str(row["status"]),
                versions=self._load_versions(agent_id),
            )

    def update_agent(
        self,
        agent_id: str,
        manifest: dict[str, Any],
        owner: str,
        tenant_id: str | None = None,
    ) -> AgentRecord:
        with self._lock:
            agent = self.get_agent(agent_id, tenant_id=tenant_id)
            if agent.owner != owner:
                raise PermissionError("owner mismatch")

            version = manifest["identity"]["version"]
            if any(v.version == version for v in agent.versions):
                raise ValueError("version already exists")

            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO registry_agent_versions(agent_id, version, manifest_json)
                    VALUES (?, ?, ?)
                    """,
                    (agent_id, version, json.dumps(manifest, sort_keys=True)),
                )
                self._conn.execute(
                    """
                    UPDATE registry_agents
                    SET status = 'active', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ?
                    """,
                    (agent_id,),
                )

            return self.get_agent(agent_id, tenant_id=tenant_id)

    def delete_agent(self, agent_id: str, owner: str, tenant_id: str | None = None) -> AgentRecord:
        with self._lock:
            agent = self.get_agent(agent_id, tenant_id=tenant_id)
            if agent.owner != owner:
                raise PermissionError("owner mismatch")
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE registry_agents
                    SET status = 'deprecated', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ?
                    """,
                    (agent_id,),
                )
            return self.get_agent(agent_id, tenant_id=tenant_id)

    def list_versions(self, agent_id: str, tenant_id: str | None = None) -> list[VersionRecord]:
        with self._lock:
            _ = self.get_agent(agent_id, tenant_id=tenant_id)
            return self._load_versions(agent_id)

    def get_version(self, agent_id: str, version: str, tenant_id: str | None = None) -> VersionRecord:
        with self._lock:
            assert self._conn is not None
            _ = self.get_agent(agent_id, tenant_id=tenant_id)
            row = self._conn.execute(
                """
                SELECT version, manifest_json, eval_summary_json
                FROM registry_agent_versions
                WHERE agent_id = ? AND version = ?
                """,
                (agent_id, version),
            ).fetchone()
            if row is None:
                raise KeyError("version not found")
            return VersionRecord(
                version=str(row["version"]),
                manifest=json.loads(str(row["manifest_json"])),
                eval_summary=json.loads(str(row["eval_summary_json"])),
            )


STORE = RegistryStore()
