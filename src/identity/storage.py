from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import uuid4

from src.identity.constants import (
    CRED_STATUS_ACTIVE,
    CRED_STATUS_REVOKED,
    CRED_STATUS_ROTATED,
    STATUS_ACTIVE,
    VALID_IDENTITY_STATUSES,
)
from src.identity.types import ActiveSessions, AgentCredential, AgentIdentity
from src.persistence import apply_scope_migrations
from src.identity.authority_fence import serialized_authority_mutation

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "identity" / "identity.db"
TENANCY_ACTIVE = "active"
TENANCY_QUARANTINED = "quarantined"
_AUTH_GENERATION_KEY = "_agenthub_auth_generation"


def _path_db() -> Path:
    return Path(os.getenv("AGENTHUB_IDENTITY_DB_PATH", str(DEFAULT_DB)))


@runtime_checkable
class ResourceAuthContext(Protocol):
    @property
    def owner(self) -> str: ...

    @property
    def tenant_id(self) -> str: ...

    @property
    def agent_id(self) -> str | None: ...


def require_resource_actor(actor: object) -> ResourceAuthContext:
    if isinstance(actor, str) and not isinstance(actor, ResourceAuthContext):
        raise PermissionError("typed authentication context required")
    if not isinstance(actor, ResourceAuthContext):
        raise PermissionError("typed authentication context required")
    if not isinstance(actor.owner, str) or not actor.owner.strip():
        raise PermissionError("authentication context is incomplete")
    if not isinstance(actor.tenant_id, str) or not actor.tenant_id.strip():
        raise PermissionError("authentication context is incomplete")
    if actor.agent_id is not None and not isinstance(actor.agent_id, str):
        raise PermissionError("authentication context is incomplete")
    return actor


def _require_actor_agent(actor: ResourceAuthContext, agent_id: str) -> None:
    if actor.agent_id is not None and actor.agent_id != agent_id:
        raise KeyError(f"agent identity not found: {agent_id}")


class IdentityStorage:
    _MAX_QUERY_ROWS = 10_000

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._db_path: str | None = None

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
        apply_scope_migrations(self._conn, "identity")
        self._db_path = str(db_path)

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
                # Test teardown is the only supported bypass for the append-only audit triggers.
                self._conn.execute(
                    "DROP TRIGGER IF EXISTS identity_quarantine_assignments_no_update"
                )
                self._conn.execute(
                    "DROP TRIGGER IF EXISTS identity_quarantine_assignments_no_delete"
                )
                # Delete in FK-safe order: children before parents
                for table in [
                    "agent_attestations",
                    "identity_quarantine_assignments",
                    "verifiable_credentials",
                    "capability_token_roots",
                    "agent_dids",
                    "revocation_events",
                    "delegation_tokens",
                    "agent_credentials",
                    "trusted_domains",
                    "agent_identities",
                ]:
                    try:
                        self._conn.execute(f"DELETE FROM {table}")  # noqa: S608
                    except sqlite3.Error:
                        pass  # Table may not exist if migrations haven't run yet
                self._conn.execute(
                    """
                    DELETE FROM _schema_migrations
                    WHERE scope = 'identity' AND migration_name = '0007_quarantine_assignment.sql'
                    """
                )
            apply_scope_migrations(self._conn, "identity")

    # --- Agent Identity CRUD ---

    def register_identity(
        self,
        *,
        agent_id: str,
        owner: str,
        tenant_id: str = "tenant-default",
        credential_type: str,
        public_key_pem: str | None = None,
        metadata: dict[str, str] | None = None,
        human_principal_id: str | None = None,
        configuration_checksum: str | None = None,
    ) -> AgentIdentity:
        self._ensure_ready()
        normalized_tenant_id = str(tenant_id).strip()
        if not normalized_tenant_id:
            raise ValueError("tenant_id is required")
        stored_metadata = dict(metadata or {})
        stored_metadata[_AUTH_GENERATION_KEY] = uuid4().hex
        with self._lock:
            assert self._conn is not None
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO agent_identities(
                            agent_id, owner, tenant_id, tenancy_status, credential_type, status,
                            public_key_pem, metadata_json, human_principal_id, configuration_checksum
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            agent_id,
                            owner,
                            normalized_tenant_id,
                            TENANCY_ACTIVE,
                            credential_type,
                            STATUS_ACTIVE,
                            public_key_pem,
                            json.dumps(stored_metadata, sort_keys=True),
                            human_principal_id,
                            configuration_checksum,
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"agent identity already exists: {agent_id}") from exc
            return self._get_identity_locked(agent_id)

    def register_identity_for_actor(
        self,
        *,
        actor: ResourceAuthContext,
        agent_id: str,
        credential_type: str,
        public_key_pem: str | None = None,
        metadata: dict[str, str] | None = None,
        human_principal_id: str | None = None,
        configuration_checksum: str | None = None,
    ) -> AgentIdentity:
        context = require_resource_actor(actor)
        if context.agent_id is not None and context.agent_id != agent_id:
            raise PermissionError("agent-bound principal cannot register another agent")
        return self.register_identity(
            agent_id=agent_id,
            owner=context.owner,
            tenant_id=context.tenant_id,
            credential_type=credential_type,
            public_key_pem=public_key_pem,
            metadata=metadata,
            human_principal_id=human_principal_id,
            configuration_checksum=configuration_checksum,
        )

    def get_identity(self, agent_id: str) -> AgentIdentity:
        self._ensure_ready()
        with self._lock:
            return self._get_identity_locked(agent_id)

    def get_identity_for_actor(
        self, agent_id: str, actor: ResourceAuthContext
    ) -> AgentIdentity:
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT * FROM agent_identities
                WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                  AND tenancy_status = ?
                """,
                (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            return _row_to_identity(row)

    def get_peer_identity_for_actor(
        self,
        agent_id: str,
        actor: ResourceAuthContext,
    ) -> AgentIdentity:
        """Resolve a peer in the actor's tenant for an explicitly authorized relationship."""
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT * FROM agent_identities
                WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                  AND tenancy_status = ?
                """,
                (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            return _row_to_identity(row)

    def _get_identity_locked(self, agent_id: str) -> AgentIdentity:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT * FROM agent_identities
            WHERE agent_id = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
            """,
            (agent_id, TENANCY_ACTIVE),
        ).fetchone()
        if row is None:
            raise KeyError(f"agent identity not found: {agent_id}")
        return _row_to_identity(row)

    def get_identity_auth_snapshot(
        self,
        agent_id: str,
        *,
        ensure_generation: bool = False,
    ) -> tuple[AgentIdentity, str | None, str | None]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT * FROM agent_identities
                WHERE agent_id = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
                """,
                (agent_id, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")

            stored_metadata = _stored_metadata(row["metadata_json"])
            generation = stored_metadata.get(_AUTH_GENERATION_KEY)
            if not isinstance(generation, str) or not generation:
                generation = None
            if generation is None and ensure_generation:
                generation = uuid4().hex
                stored_metadata[_AUTH_GENERATION_KEY] = generation
                with self._conn:
                    self._conn.execute(
                        "UPDATE agent_identities SET metadata_json = ? WHERE agent_id = ?",
                        (json.dumps(stored_metadata, sort_keys=True), agent_id),
                    )
            tenant_id = str(row["tenant_id"]) if row["tenant_id"] is not None else None
            return _row_to_identity(row), generation, tenant_id

    @serialized_authority_mutation
    def update_identity_status(self, agent_id: str, status: str) -> AgentIdentity:
        if status not in VALID_IDENTITY_STATUSES:
            raise ValueError(f"invalid status: {status}")
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT metadata_json FROM agent_identities
                WHERE agent_id = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
                """,
                (agent_id, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            stored_metadata = _stored_metadata(row["metadata_json"])
            stored_metadata[_AUTH_GENERATION_KEY] = uuid4().hex
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET status = ?, metadata_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
                    """,
                    (
                        status,
                        json.dumps(stored_metadata, sort_keys=True),
                        agent_id,
                        TENANCY_ACTIVE,
                    ),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    @serialized_authority_mutation
    def update_identity_status_for_actor(
        self,
        agent_id: str,
        status: str,
        actor: ResourceAuthContext,
    ) -> AgentIdentity:
        if status not in VALID_IDENTITY_STATUSES:
            raise ValueError(f"invalid status: {status}")
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT metadata_json FROM agent_identities
                WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                  AND tenancy_status = ?
                """,
                (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            stored_metadata = _stored_metadata(row["metadata_json"])
            stored_metadata[_AUTH_GENERATION_KEY] = uuid4().hex
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET status = ?, metadata_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                      AND tenancy_status = ?
                    """,
                    (
                        status,
                        json.dumps(stored_metadata, sort_keys=True),
                        agent_id,
                        context.owner,
                        context.tenant_id,
                        TENANCY_ACTIVE,
                    ),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    def list_identities(self, owner: str) -> list[AgentIdentity]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT * FROM agent_identities
                WHERE owner = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (owner, TENANCY_ACTIVE, self._MAX_QUERY_ROWS),
            ).fetchall()
            return [_row_to_identity(row) for row in rows]

    def list_identities_for_actor(
        self, actor: ResourceAuthContext
    ) -> list[AgentIdentity]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT * FROM agent_identities
                WHERE owner = ? AND tenant_id = ? AND tenancy_status = ?
                  AND (? IS NULL OR agent_id = ?)
                ORDER BY created_at DESC LIMIT ?
                """,
                (
                    context.owner,
                    context.tenant_id,
                    TENANCY_ACTIVE,
                    context.agent_id,
                    context.agent_id,
                    self._MAX_QUERY_ROWS,
                ),
            ).fetchall()
            return [_row_to_identity(row) for row in rows]

    def list_quarantined_identities_for_actor(
        self,
        actor: ResourceAuthContext,
    ) -> list[AgentIdentity]:
        context = require_resource_actor(actor)
        if context.agent_id is not None:
            raise PermissionError("owner-level operator required")
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT * FROM agent_identities
                WHERE owner = ? AND tenancy_status = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (context.owner, TENANCY_QUARANTINED, self._MAX_QUERY_ROWS),
            ).fetchall()
            return [_row_to_identity(row) for row in rows]

    def assign_quarantined_identity_for_actor(
        self,
        *,
        actor: ResourceAuthContext,
        agent_id: str,
        selected_tenant_id: str,
    ) -> AgentIdentity:
        context = require_resource_actor(actor)
        if context.agent_id is not None:
            raise PermissionError("owner-level operator required")
        selected_tenant = selected_tenant_id.strip()
        if not selected_tenant:
            raise ValueError("explicit tenant selection required")
        if selected_tenant != context.tenant_id:
            raise PermissionError("selected tenant does not match authenticated tenant")

        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                legacy_row = self._conn.execute(
                    """
                    SELECT metadata_json FROM agent_identities
                    WHERE agent_id = ? AND owner = ?
                      AND tenant_id IS NULL AND tenancy_status = ?
                    """,
                    (agent_id, context.owner, TENANCY_QUARANTINED),
                ).fetchone()
                if legacy_row is None:
                    raise KeyError(f"quarantined identity not found: {agent_id}")
                stored_metadata = _stored_metadata(legacy_row["metadata_json"])
                stored_metadata[_AUTH_GENERATION_KEY] = uuid4().hex
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET tenant_id = ?, tenancy_status = ?, metadata_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND owner = ?
                      AND tenant_id IS NULL AND tenancy_status = ?
                    """,
                    (
                        selected_tenant,
                        TENANCY_ACTIVE,
                        json.dumps(stored_metadata, sort_keys=True),
                        agent_id,
                        context.owner,
                        TENANCY_QUARANTINED,
                    ),
                )
                if result.rowcount != 1:
                    raise KeyError(f"quarantined identity not found: {agent_id}")
                self._conn.execute(
                    """
                    INSERT INTO identity_quarantine_assignments(
                        assignment_id, agent_id, owner, tenant_id, actor
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid4()),
                        agent_id,
                        context.owner,
                        selected_tenant,
                        context.owner,
                    ),
                )
                row = self._conn.execute(
                    """
                    SELECT * FROM agent_identities
                    WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                      AND tenancy_status = ?
                    """,
                    (agent_id, context.owner, selected_tenant, TENANCY_ACTIVE),
                ).fetchone()
                assert row is not None
                self._conn.commit()
                return _row_to_identity(row)
            except Exception:
                self._conn.rollback()
                raise

    def count_quarantined_identities(self) -> int:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT COUNT(*) AS total FROM agent_identities WHERE tenancy_status = ?",
                (TENANCY_QUARANTINED,),
            ).fetchone()
            assert row is not None
            return int(row["total"])

    def bind_human_principal(
        self, agent_id: str, human_principal_id: str | None
    ) -> AgentIdentity:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET human_principal_id = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
                    """,
                    (human_principal_id, agent_id, TENANCY_ACTIVE),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    def bind_human_principal_for_actor(
        self,
        agent_id: str,
        human_principal_id: str | None,
        actor: ResourceAuthContext,
    ) -> AgentIdentity:
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET human_principal_id = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                      AND tenancy_status = ?
                    """,
                    (
                        human_principal_id,
                        agent_id,
                        context.owner,
                        context.tenant_id,
                        TENANCY_ACTIVE,
                    ),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    @serialized_authority_mutation
    def set_configuration_checksum(
        self, agent_id: str, checksum: str | None
    ) -> AgentIdentity:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT configuration_checksum, metadata_json FROM agent_identities
                WHERE agent_id = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
                """,
                (agent_id, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            metadata = _stored_metadata(row["metadata_json"])
            if row["configuration_checksum"] != checksum:
                metadata[_AUTH_GENERATION_KEY] = uuid4().hex
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities SET configuration_checksum = ?, metadata_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND tenant_id IS NOT NULL AND tenancy_status = ?
                    """,
                    (
                        checksum,
                        json.dumps(metadata, sort_keys=True),
                        agent_id,
                        TENANCY_ACTIVE,
                    ),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    @serialized_authority_mutation
    def set_configuration_checksum_for_actor(
        self,
        agent_id: str,
        checksum: str | None,
        actor: ResourceAuthContext,
    ) -> AgentIdentity:
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT configuration_checksum, metadata_json FROM agent_identities
                WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                  AND tenancy_status = ?
                """,
                (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            metadata = _stored_metadata(row["metadata_json"])
            if row["configuration_checksum"] != checksum:
                metadata[_AUTH_GENERATION_KEY] = uuid4().hex
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities SET configuration_checksum = ?, metadata_json = ?,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                      AND tenancy_status = ?
                    """,
                    (
                        checksum,
                        json.dumps(metadata, sort_keys=True),
                        agent_id,
                        context.owner,
                        context.tenant_id,
                        TENANCY_ACTIVE,
                    ),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    # --- Credential CRUD ---

    def insert_credential(
        self,
        *,
        credential_id: str,
        agent_id: str,
        credential_hash: str,
        scopes: list[str],
        issued_at_epoch: int,
        expires_at_epoch: int,
        rotation_parent_id: str | None = None,
    ) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO agent_credentials(
                        credential_id, agent_id, credential_hash, scopes_json,
                        issued_at_epoch, expires_at_epoch, rotation_parent_id, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential_id,
                        agent_id,
                        credential_hash,
                        json.dumps(sorted(scopes)),
                        issued_at_epoch,
                        expires_at_epoch,
                        rotation_parent_id,
                        CRED_STATUS_ACTIVE,
                    ),
                )

    def insert_credential_for_actor(
        self,
        *,
        actor: ResourceAuthContext,
        credential_id: str,
        agent_id: str,
        credential_hash: str,
        scopes: list[str],
        issued_at_epoch: int,
        expires_at_epoch: int,
        rotation_parent_id: str | None = None,
    ) -> None:
        """Authorize the identity and insert the credential in one transaction."""
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                identity = self._conn.execute(
                    """
                    SELECT status FROM agent_identities
                    WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                      AND tenancy_status = ?
                    """,
                    (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE),
                ).fetchone()
                if identity is None:
                    raise KeyError(f"agent identity not found: {agent_id}")
                if str(identity["status"]) != STATUS_ACTIVE:
                    raise PermissionError(
                        f"agent identity is {identity['status']}, cannot issue credential"
                    )
                self._conn.execute(
                    """
                    INSERT INTO agent_credentials(
                        credential_id, agent_id, credential_hash, scopes_json,
                        issued_at_epoch, expires_at_epoch, rotation_parent_id, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential_id,
                        agent_id,
                        credential_hash,
                        json.dumps(sorted(scopes)),
                        issued_at_epoch,
                        expires_at_epoch,
                        rotation_parent_id,
                        CRED_STATUS_ACTIVE,
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def get_credential(self, credential_id: str) -> AgentCredential:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT * FROM agent_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"credential not found: {credential_id}")
            return _row_to_credential(row)

    def get_credential_for_actor(
        self,
        credential_id: str,
        actor: ResourceAuthContext,
    ) -> AgentCredential:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT credential.*
                FROM agent_credentials AS credential
                JOIN agent_identities AS identity ON identity.agent_id = credential.agent_id
                WHERE credential.credential_id = ?
                  AND identity.owner = ?
                  AND identity.tenant_id = ?
                  AND identity.tenancy_status = ?
                  AND (? IS NULL OR identity.agent_id = ?)
                """,
                (
                    credential_id,
                    context.owner,
                    context.tenant_id,
                    TENANCY_ACTIVE,
                    context.agent_id,
                    context.agent_id,
                ),
            ).fetchone()
            if row is None:
                raise KeyError(f"credential not found: {credential_id}")
            return _row_to_credential(row)

    def rotate_credential_for_actor(
        self,
        *,
        actor: ResourceAuthContext,
        credential_id: str,
        new_credential_id: str,
        credential_hash: str,
        scopes: list[str] | None,
        issued_at_epoch: int,
        expires_at_epoch: int,
    ) -> AgentCredential:
        """Authorize and rotate a credential without a fetch-then-mutate gap."""
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    """
                    SELECT credential.*
                    FROM agent_credentials AS credential
                    JOIN agent_identities AS identity ON identity.agent_id = credential.agent_id
                    WHERE credential.credential_id = ?
                      AND identity.owner = ?
                      AND identity.tenant_id = ?
                      AND identity.tenancy_status = ?
                      AND (? IS NULL OR identity.agent_id = ?)
                    """,
                    (
                        credential_id,
                        context.owner,
                        context.tenant_id,
                        TENANCY_ACTIVE,
                        context.agent_id,
                        context.agent_id,
                    ),
                ).fetchone()
                if row is None:
                    raise KeyError(f"credential not found: {credential_id}")
                old_credential = _row_to_credential(row)
                if old_credential["status"] != CRED_STATUS_ACTIVE:
                    raise ValueError(
                        f"cannot rotate credential in status: {old_credential['status']}"
                    )
                normalized_scopes = (
                    old_credential["scopes"] if scopes is None else sorted(scopes)
                )
                result = self._conn.execute(
                    """
                    UPDATE agent_credentials
                    SET status = ?
                    WHERE credential_id = ? AND status = ?
                    """,
                    (CRED_STATUS_ROTATED, credential_id, CRED_STATUS_ACTIVE),
                )
                if result.rowcount != 1:
                    raise ValueError(
                        "credential is no longer active (concurrent modification)"
                    )
                self._conn.execute(
                    """
                    INSERT INTO agent_credentials(
                        credential_id, agent_id, credential_hash, scopes_json,
                        issued_at_epoch, expires_at_epoch, rotation_parent_id, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_credential_id,
                        old_credential["agent_id"],
                        credential_hash,
                        json.dumps(normalized_scopes),
                        issued_at_epoch,
                        expires_at_epoch,
                        credential_id,
                        CRED_STATUS_ACTIVE,
                    ),
                )
                self._conn.commit()
                return old_credential
            except Exception:
                self._conn.rollback()
                raise

    def revoke_credential_for_actor(
        self,
        credential_id: str,
        actor: ResourceAuthContext,
        reason: str,
    ) -> AgentCredential:
        """Authorize and revoke a credential in one transaction."""
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    """
                    SELECT credential.*
                    FROM agent_credentials AS credential
                    JOIN agent_identities AS identity ON identity.agent_id = credential.agent_id
                    WHERE credential.credential_id = ?
                      AND identity.owner = ?
                      AND identity.tenant_id = ?
                      AND identity.tenancy_status = ?
                      AND (? IS NULL OR identity.agent_id = ?)
                    """,
                    (
                        credential_id,
                        context.owner,
                        context.tenant_id,
                        TENANCY_ACTIVE,
                        context.agent_id,
                        context.agent_id,
                    ),
                ).fetchone()
                if row is None:
                    raise KeyError(f"credential not found: {credential_id}")
                credential = _row_to_credential(row)
                if credential["status"] == CRED_STATUS_REVOKED:
                    self._conn.commit()
                    return credential
                self._conn.execute(
                    """
                    UPDATE agent_credentials
                    SET status = ?,
                        revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        revocation_reason = ?
                    WHERE credential_id = ?
                    """,
                    (CRED_STATUS_REVOKED, reason, credential_id),
                )
                updated = self._conn.execute(
                    "SELECT * FROM agent_credentials WHERE credential_id = ?",
                    (credential_id,),
                ).fetchone()
                assert updated is not None
                self._conn.commit()
                return _row_to_credential(updated)
            except Exception:
                self._conn.rollback()
                raise

    def find_credential_by_hash(self, credential_hash: str) -> AgentCredential | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT credential.*
                FROM agent_credentials AS credential
                JOIN agent_identities AS identity ON identity.agent_id = credential.agent_id
                WHERE credential.credential_hash = ? AND credential.status = ?
                  AND identity.tenant_id IS NOT NULL AND identity.tenancy_status = ?
                """,
                (credential_hash, CRED_STATUS_ACTIVE, TENANCY_ACTIVE),
            ).fetchone()
            if row is None:
                return None
            return _row_to_credential(row)

    def update_credential_status(
        self,
        credential_id: str,
        status: str,
        reason: str | None = None,
    ) -> AgentCredential:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                revoked_at = (
                    "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
                    if status == "revoked"
                    else None
                )
                if revoked_at:
                    self._conn.execute(
                        """
                        UPDATE agent_credentials
                        SET status = ?, revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                            revocation_reason = ?
                        WHERE credential_id = ?
                        """,
                        (status, reason, credential_id),
                    )
                else:
                    self._conn.execute(
                        "UPDATE agent_credentials SET status = ? WHERE credential_id = ?",
                        (status, credential_id),
                    )
            return self.get_credential(credential_id)

    def update_credential_status_if_active(
        self,
        credential_id: str,
        new_status: str,
        reason: str | None = None,
    ) -> AgentCredential:
        """Atomically update status only if currently active (optimistic lock)."""
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                if new_status == "revoked":
                    result = self._conn.execute(
                        """
                        UPDATE agent_credentials
                        SET status = ?, revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                            revocation_reason = ?
                        WHERE credential_id = ? AND status = ?
                        """,
                        (new_status, reason, credential_id, CRED_STATUS_ACTIVE),
                    )
                else:
                    result = self._conn.execute(
                        "UPDATE agent_credentials SET status = ? WHERE credential_id = ? AND status = ?",
                        (new_status, credential_id, CRED_STATUS_ACTIVE),
                    )
                if result.rowcount == 0:
                    raise ValueError(
                        "credential is no longer active (concurrent modification)"
                    )
            return self.get_credential(credential_id)

    def list_active_credentials(self, agent_id: str) -> list[AgentCredential]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT * FROM agent_credentials
                WHERE agent_id = ? AND status = ?
                ORDER BY issued_at_epoch DESC
                LIMIT ?
                """,
                (agent_id, CRED_STATUS_ACTIVE, self._MAX_QUERY_ROWS),
            ).fetchall()
            return [_row_to_credential(row) for row in rows]

    def list_active_credentials_for_actor(
        self,
        agent_id: str,
        actor: ResourceAuthContext,
    ) -> list[AgentCredential]:
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            identity = self._conn.execute(
                """
                SELECT 1 FROM agent_identities
                WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                  AND tenancy_status = ?
                """,
                (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE),
            ).fetchone()
            if identity is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            rows = self._conn.execute(
                """
                SELECT * FROM agent_credentials
                WHERE agent_id = ? AND status = ?
                ORDER BY issued_at_epoch DESC
                LIMIT ?
                """,
                (agent_id, CRED_STATUS_ACTIVE, self._MAX_QUERY_ROWS),
            ).fetchall()
            return [_row_to_credential(row) for row in rows]

    def revoke_all_credentials(self, agent_id: str, reason: str) -> int:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_credentials
                    SET status = 'revoked',
                        revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        revocation_reason = ?
                    WHERE agent_id = ? AND status = ?
                    """,
                    (reason, agent_id, CRED_STATUS_ACTIVE),
                )
                return result.rowcount

    # --- Capability token, DID, and VC authority ---

    def _authority_identity_locked(
        self,
        agent_id: str,
        context: ResourceAuthContext,
    ) -> tuple[sqlite3.Row, str]:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT * FROM agent_identities
            WHERE agent_id = ? AND owner = ? AND tenant_id = ?
              AND tenancy_status = ? AND status = ?
            """,
            (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE, STATUS_ACTIVE),
        ).fetchone()
        if row is None:
            boundary_row = self._conn.execute(
                """
                SELECT 1 FROM agent_identities
                WHERE agent_id = ? AND owner = ? AND tenant_id = ? AND tenancy_status = ?
                """,
                (agent_id, context.owner, context.tenant_id, TENANCY_ACTIVE),
            ).fetchone()
            if boundary_row is not None:
                raise PermissionError(f"agent identity is not active: {agent_id}")
            raise KeyError(f"agent identity not found: {agent_id}")
        metadata = _stored_metadata(row["metadata_json"])
        generation = metadata.get(_AUTH_GENERATION_KEY)
        if not isinstance(generation, str) or not generation:
            generation = uuid4().hex
            metadata[_AUTH_GENERATION_KEY] = generation
            self._conn.execute(
                "UPDATE agent_identities SET metadata_json = ? WHERE agent_id = ?",
                (json.dumps(metadata, sort_keys=True), agent_id),
            )
        return row, generation

    @staticmethod
    def _require_scope_authority(
        context: ResourceAuthContext, scopes: list[str]
    ) -> list[str]:
        normalized = sorted(
            {str(scope).strip() for scope in scopes if str(scope).strip()}
        )
        if not normalized:
            raise ValueError("at least one capability scope is required")
        allows_scope = getattr(context, "allows_scope", None)
        if not callable(allows_scope):
            raise PermissionError("authentication context cannot authorize scopes")
        unauthorized = [scope for scope in normalized if not allows_scope(scope)]
        if unauthorized:
            raise PermissionError("requested capability scopes exceed issuer authority")
        return normalized

    def create_capability_token_root_for_actor(
        self,
        *,
        actor: ResourceAuthContext,
        token_id: str,
        issuer_agent_id: str,
        subject_agent_id: str,
        audience: str,
        resource: str,
        issued_at_epoch: float,
        expires_at_epoch: float,
        scopes: list[str],
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        if context.agent_id is not None and context.agent_id != issuer_agent_id:
            raise PermissionError(
                "agent-bound principal cannot issue for another agent"
            )
        normalized_audience = str(audience).strip()
        normalized_resource = str(resource).strip()
        if not normalized_audience or not normalized_resource:
            raise ValueError("audience and resource are required")
        if float(expires_at_epoch) <= float(issued_at_epoch):
            raise ValueError("capability token expiry must follow issuance")
        normalized_scopes = self._require_scope_authority(context, scopes)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                _, issuer_generation = self._authority_identity_locked(
                    issuer_agent_id, context
                )
                _, subject_generation = self._authority_identity_locked(
                    subject_agent_id, context
                )
                self._conn.execute(
                    """
                    INSERT INTO capability_token_roots(
                        token_id, owner, tenant_id, issuer_agent_id, subject_agent_id,
                        issuer_generation, subject_generation, audience, resource,
                        scopes_json, issued_at_epoch, expires_at_epoch
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        token_id,
                        context.owner,
                        context.tenant_id,
                        issuer_agent_id,
                        subject_agent_id,
                        issuer_generation,
                        subject_generation,
                        normalized_audience,
                        normalized_resource,
                        json.dumps(normalized_scopes),
                        float(issued_at_epoch),
                        float(expires_at_epoch),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise ValueError(
                    f"capability token already exists: {token_id}"
                ) from exc
            except Exception:
                self._conn.rollback()
                raise
        return self.get_capability_token_root_for_actor(token_id, context)

    def _capability_root_for_actor_locked(
        self,
        token_id: str,
        context: ResourceAuthContext,
    ) -> sqlite3.Row:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT root.*,
                   issuer.status AS issuer_status,
                   issuer.tenancy_status AS issuer_tenancy_status,
                   issuer.metadata_json AS issuer_metadata_json,
                   subject.status AS subject_status,
                   subject.tenancy_status AS subject_tenancy_status,
                   subject.metadata_json AS subject_metadata_json
            FROM capability_token_roots AS root
            JOIN agent_identities AS issuer ON issuer.agent_id = root.issuer_agent_id
            JOIN agent_identities AS subject ON subject.agent_id = root.subject_agent_id
            WHERE root.token_id = ? AND root.owner = ? AND root.tenant_id = ?
              AND (? IS NULL OR root.issuer_agent_id = ? OR root.subject_agent_id = ?)
            """,
            (
                token_id,
                context.owner,
                context.tenant_id,
                context.agent_id,
                context.agent_id,
                context.agent_id,
            ),
        ).fetchone()
        if row is None:
            raise KeyError(f"capability token not found: {token_id}")
        return row

    def get_capability_token_root_for_actor(
        self,
        token_id: str,
        actor: ResourceAuthContext,
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            row = self._capability_root_for_actor_locked(token_id, context)
            return _row_to_capability_root(row)

    def list_capability_token_roots_for_actor(
        self,
        actor: ResourceAuthContext,
        active_only: bool = True,
    ) -> list[dict[str, object]]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            clauses = ["root.owner = ?", "root.tenant_id = ?"]
            params: list[object] = [context.owner, context.tenant_id]
            if context.agent_id is not None:
                clauses.append(
                    "(root.issuer_agent_id = ? OR root.subject_agent_id = ?)"
                )
                params.extend([context.agent_id, context.agent_id])
            if active_only:
                clauses.append("root.revoked = 0")
            params.append(self._MAX_QUERY_ROWS)
            rows = self._conn.execute(
                f"""
                SELECT root.*,
                       issuer.status AS issuer_status,
                       issuer.tenancy_status AS issuer_tenancy_status,
                       issuer.metadata_json AS issuer_metadata_json,
                       subject.status AS subject_status,
                       subject.tenancy_status AS subject_tenancy_status,
                       subject.metadata_json AS subject_metadata_json
                FROM capability_token_roots AS root
                JOIN agent_identities AS issuer ON issuer.agent_id = root.issuer_agent_id
                JOIN agent_identities AS subject ON subject.agent_id = root.subject_agent_id
                WHERE {" AND ".join(clauses)}
                ORDER BY root.issued_at_epoch DESC LIMIT ?
                """,  # noqa: S608
                params,
            ).fetchall()
            return [_row_to_capability_root(row) for row in rows]

    def revoke_capability_token_root_for_actor(
        self,
        token_id: str,
        actor: ResourceAuthContext,
        reason: str,
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._capability_root_for_actor_locked(token_id, context)
                if (
                    context.agent_id is not None
                    and context.agent_id != row["issuer_agent_id"]
                ):
                    raise KeyError(f"capability token not found: {token_id}")
                self._conn.execute(
                    """
                    UPDATE capability_token_roots
                    SET revoked = 1,
                        revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                        revocation_reason = COALESCE(revocation_reason, ?)
                    WHERE token_id = ?
                    """,
                    (reason, token_id),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.get_capability_token_root_for_actor(token_id, context)

    def create_did_for_actor(
        self,
        *,
        actor: ResourceAuthContext,
        agent_id: str,
        did: str,
        document: dict[str, object],
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        if context.agent_id is not None and context.agent_id != agent_id:
            raise PermissionError(
                "agent-bound principal cannot create another agent DID"
            )
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                _, generation = self._authority_identity_locked(agent_id, context)
                existing = self._conn.execute(
                    "SELECT * FROM agent_dids WHERE did = ? AND owner = ? AND tenant_id = ?",
                    (did, context.owner, context.tenant_id),
                ).fetchone()
                if existing is not None:
                    if bool(existing["deactivated"]):
                        raise ValueError("deactivated DID cannot be recreated")
                    self._conn.commit()
                    return _row_to_did(existing)
                self._conn.execute(
                    """
                    INSERT INTO agent_dids(
                        did, owner, tenant_id, agent_id, identity_generation, document_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        did,
                        context.owner,
                        context.tenant_id,
                        agent_id,
                        generation,
                        json.dumps(document, sort_keys=True, separators=(",", ":")),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise ValueError(f"DID already exists for agent: {agent_id}") from exc
            except Exception:
                self._conn.rollback()
                raise
        return self.resolve_did_for_actor(did, context)

    def _did_for_actor_locked(
        self, did: str, context: ResourceAuthContext
    ) -> sqlite3.Row:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT did_record.*,
                   identity.status AS identity_status,
                   identity.tenancy_status AS identity_tenancy_status,
                   identity.metadata_json AS identity_metadata_json
            FROM agent_dids AS did_record
            JOIN agent_identities AS identity ON identity.agent_id = did_record.agent_id
            WHERE did_record.did = ? AND did_record.owner = ? AND did_record.tenant_id = ?
              AND (? IS NULL OR did_record.agent_id = ?)
            """,
            (did, context.owner, context.tenant_id, context.agent_id, context.agent_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"DID not found: {did}")
        return row

    def resolve_did_for_actor(
        self,
        did: str,
        actor: ResourceAuthContext,
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            return _row_to_did(self._did_for_actor_locked(did, context))

    def resolve_peer_did_for_actor(
        self,
        did: str,
        actor: ResourceAuthContext,
    ) -> dict[str, object]:
        """Resolve a same-boundary DID after a service authorizes the relationship."""
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT did_record.*,
                       identity.status AS identity_status,
                       identity.tenancy_status AS identity_tenancy_status,
                       identity.metadata_json AS identity_metadata_json
                FROM agent_dids AS did_record
                JOIN agent_identities AS identity ON identity.agent_id = did_record.agent_id
                WHERE did_record.did = ? AND did_record.owner = ? AND did_record.tenant_id = ?
                """,
                (did, context.owner, context.tenant_id),
            ).fetchone()
            if row is None:
                raise KeyError(f"DID not found: {did}")
            return _row_to_did(row)

    def list_dids_for_actor(
        self,
        actor: ResourceAuthContext,
        active_only: bool = True,
    ) -> list[dict[str, object]]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            clauses = ["did_record.owner = ?", "did_record.tenant_id = ?"]
            params: list[object] = [context.owner, context.tenant_id]
            if context.agent_id is not None:
                clauses.append("did_record.agent_id = ?")
                params.append(context.agent_id)
            if active_only:
                clauses.append("did_record.deactivated = 0")
            params.append(self._MAX_QUERY_ROWS)
            rows = self._conn.execute(
                f"""
                SELECT did_record.*,
                       identity.status AS identity_status,
                       identity.tenancy_status AS identity_tenancy_status,
                       identity.metadata_json AS identity_metadata_json
                FROM agent_dids AS did_record
                JOIN agent_identities AS identity ON identity.agent_id = did_record.agent_id
                WHERE {" AND ".join(clauses)}
                ORDER BY did_record.created_at DESC LIMIT ?
                """,  # noqa: S608
                params,
            ).fetchall()
            return [_row_to_did(row) for row in rows]

    def deactivate_did_for_actor(
        self,
        did: str,
        actor: ResourceAuthContext,
        reason: str,
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._did_for_actor_locked(did, context)
                self._conn.execute(
                    """
                    UPDATE agent_dids
                    SET deactivated = 1,
                        deactivated_at = COALESCE(
                            deactivated_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        ),
                        deactivation_reason = COALESCE(deactivation_reason, ?),
                        updated_at = CASE WHEN deactivated = 0
                            THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') ELSE updated_at END
                    WHERE did = ?
                    """,
                    (reason, did),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.resolve_did_for_actor(did, context)

    def create_verifiable_credential_for_actor(
        self,
        *,
        actor: ResourceAuthContext,
        record: dict[str, object],
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        vc_id = str(record.get("vc_id", "")).strip()
        issuer_did = str(record.get("issuer_did", "")).strip()
        subject_did = str(record.get("subject_did", "")).strip()
        credential_type = str(record.get("credential_type", "")).strip()
        issued_at_value = record.get("issued_at")
        expires_at_value = record.get("expires_at")
        if (
            isinstance(issued_at_value, bool)
            or not isinstance(issued_at_value, (int, float))
            or isinstance(expires_at_value, bool)
            or not isinstance(expires_at_value, (int, float))
        ):
            raise ValueError("verifiable credential timestamps are required")
        issued_at = float(issued_at_value)
        expires_at = float(expires_at_value)
        if not vc_id or not issuer_did or not subject_did or not credential_type:
            raise ValueError("verifiable credential authority fields are required")
        if expires_at <= issued_at:
            raise ValueError("verifiable credential expiry must follow issuance")
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                issuer = self._conn.execute(
                    """
                    SELECT did_record.*, identity.status AS identity_status,
                           identity.tenancy_status AS identity_tenancy_status,
                           identity.metadata_json AS identity_metadata_json
                    FROM agent_dids AS did_record
                    JOIN agent_identities AS identity ON identity.agent_id = did_record.agent_id
                    WHERE did_record.did = ? AND did_record.owner = ? AND did_record.tenant_id = ?
                      AND did_record.deactivated = 0 AND identity.status = ?
                      AND identity.tenancy_status = ?
                    """,
                    (
                        issuer_did,
                        context.owner,
                        context.tenant_id,
                        STATUS_ACTIVE,
                        TENANCY_ACTIVE,
                    ),
                ).fetchone()
                subject = self._conn.execute(
                    """
                    SELECT did_record.*, identity.status AS identity_status,
                           identity.tenancy_status AS identity_tenancy_status,
                           identity.metadata_json AS identity_metadata_json
                    FROM agent_dids AS did_record
                    JOIN agent_identities AS identity ON identity.agent_id = did_record.agent_id
                    WHERE did_record.did = ? AND did_record.owner = ? AND did_record.tenant_id = ?
                      AND did_record.deactivated = 0 AND identity.status = ?
                      AND identity.tenancy_status = ?
                    """,
                    (
                        subject_did,
                        context.owner,
                        context.tenant_id,
                        STATUS_ACTIVE,
                        TENANCY_ACTIVE,
                    ),
                ).fetchone()
                if issuer is None:
                    raise KeyError(f"issuer DID not found: {issuer_did}")
                if subject is None:
                    raise KeyError(f"subject DID not found: {subject_did}")
                if (
                    context.agent_id is not None
                    and context.agent_id != issuer["agent_id"]
                ):
                    raise PermissionError(
                        "agent-bound principal cannot issue from another DID"
                    )
                issuer_generation = _generation_from_metadata(
                    issuer["identity_metadata_json"]
                )
                subject_generation = _generation_from_metadata(
                    subject["identity_metadata_json"]
                )
                if not issuer_generation or not subject_generation:
                    raise ValueError("DID identity generation is unavailable")
                self._conn.execute(
                    """
                    INSERT INTO verifiable_credentials(
                        vc_id, owner, tenant_id, issuer_did, subject_did,
                        issuer_generation, subject_generation, credential_type,
                        record_json, issued_at_epoch, expires_at_epoch
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vc_id,
                        context.owner,
                        context.tenant_id,
                        issuer_did,
                        subject_did,
                        issuer_generation,
                        subject_generation,
                        credential_type,
                        json.dumps(record, sort_keys=True, separators=(",", ":")),
                        issued_at,
                        expires_at,
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise ValueError(
                    f"verifiable credential already exists: {vc_id}"
                ) from exc
            except Exception:
                self._conn.rollback()
                raise
        return self.get_verifiable_credential_for_actor(vc_id, context)

    def _vc_for_actor_locked(
        self, vc_id: str, context: ResourceAuthContext
    ) -> sqlite3.Row:
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT vc.*,
                   issuer_did.agent_id AS issuer_agent_id,
                   issuer_did.deactivated AS issuer_did_deactivated,
                   subject_did.agent_id AS subject_agent_id,
                   subject_did.deactivated AS subject_did_deactivated,
                   issuer_identity.status AS issuer_identity_status,
                   issuer_identity.tenancy_status AS issuer_tenancy_status,
                   issuer_identity.metadata_json AS issuer_metadata_json,
                   subject_identity.status AS subject_identity_status,
                   subject_identity.tenancy_status AS subject_tenancy_status,
                   subject_identity.metadata_json AS subject_metadata_json
            FROM verifiable_credentials AS vc
            JOIN agent_dids AS issuer_did ON issuer_did.did = vc.issuer_did
            JOIN agent_dids AS subject_did ON subject_did.did = vc.subject_did
            JOIN agent_identities AS issuer_identity
              ON issuer_identity.agent_id = issuer_did.agent_id
            JOIN agent_identities AS subject_identity
              ON subject_identity.agent_id = subject_did.agent_id
            WHERE vc.vc_id = ? AND vc.owner = ? AND vc.tenant_id = ?
              AND (? IS NULL OR issuer_did.agent_id = ? OR subject_did.agent_id = ?)
            """,
            (
                vc_id,
                context.owner,
                context.tenant_id,
                context.agent_id,
                context.agent_id,
                context.agent_id,
            ),
        ).fetchone()
        if row is None:
            raise KeyError(f"VC not found: {vc_id}")
        return row

    def get_verifiable_credential_for_actor(
        self,
        vc_id: str,
        actor: ResourceAuthContext,
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            return _row_to_verifiable_credential(
                self._vc_for_actor_locked(vc_id, context)
            )

    def list_verifiable_credentials_for_actor(
        self,
        actor: ResourceAuthContext,
        *,
        issuer_did: str | None = None,
        subject_did: str | None = None,
        credential_type: str | None = None,
        active_only: bool = True,
    ) -> list[dict[str, object]]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            clauses = ["vc.owner = ?", "vc.tenant_id = ?"]
            params: list[object] = [context.owner, context.tenant_id]
            if context.agent_id is not None:
                clauses.append("(issuer_did.agent_id = ? OR subject_did.agent_id = ?)")
                params.extend([context.agent_id, context.agent_id])
            for column, value in (
                ("vc.issuer_did", issuer_did),
                ("vc.subject_did", subject_did),
                ("vc.credential_type", credential_type),
            ):
                if value:
                    clauses.append(f"{column} = ?")
                    params.append(value)
            if active_only:
                clauses.append("vc.revoked = 0")
                clauses.append(
                    "vc.expires_at_epoch > CAST(strftime('%s', 'now') AS REAL)"
                )
            params.append(self._MAX_QUERY_ROWS)
            rows = self._conn.execute(
                f"""
                SELECT vc.*,
                       issuer_did.agent_id AS issuer_agent_id,
                       issuer_did.deactivated AS issuer_did_deactivated,
                       subject_did.agent_id AS subject_agent_id,
                       subject_did.deactivated AS subject_did_deactivated,
                       issuer_identity.status AS issuer_identity_status,
                       issuer_identity.tenancy_status AS issuer_tenancy_status,
                       issuer_identity.metadata_json AS issuer_metadata_json,
                       subject_identity.status AS subject_identity_status,
                       subject_identity.tenancy_status AS subject_tenancy_status,
                       subject_identity.metadata_json AS subject_metadata_json
                FROM verifiable_credentials AS vc
                JOIN agent_dids AS issuer_did ON issuer_did.did = vc.issuer_did
                JOIN agent_dids AS subject_did ON subject_did.did = vc.subject_did
                JOIN agent_identities AS issuer_identity
                  ON issuer_identity.agent_id = issuer_did.agent_id
                JOIN agent_identities AS subject_identity
                  ON subject_identity.agent_id = subject_did.agent_id
                WHERE {" AND ".join(clauses)}
                ORDER BY vc.issued_at_epoch DESC LIMIT ?
                """,  # noqa: S608
                params,
            ).fetchall()
            return [_row_to_verifiable_credential(row) for row in rows]

    def revoke_verifiable_credential_for_actor(
        self,
        vc_id: str,
        actor: ResourceAuthContext,
        reason: str,
    ) -> dict[str, object]:
        context = require_resource_actor(actor)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._vc_for_actor_locked(vc_id, context)
                if (
                    context.agent_id is not None
                    and context.agent_id != row["issuer_agent_id"]
                ):
                    raise KeyError(f"VC not found: {vc_id}")
                self._conn.execute(
                    """
                    UPDATE verifiable_credentials
                    SET revoked = 1,
                        revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                        revocation_reason = COALESCE(revocation_reason, ?)
                    WHERE vc_id = ?
                    """,
                    (reason, vc_id),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.get_verifiable_credential_for_actor(vc_id, context)

    def revoke_authority_artifacts_for_agent(
        self,
        *,
        agent_id: str,
        actor: ResourceAuthContext,
        reason: str,
    ) -> tuple[int, int]:
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._authority_identity_locked(agent_id, context)
                capability_result = self._conn.execute(
                    """
                    UPDATE capability_token_roots
                    SET revoked = 1,
                        revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        revocation_reason = ?
                    WHERE owner = ? AND tenant_id = ? AND revoked = 0
                      AND (issuer_agent_id = ? OR subject_agent_id = ?)
                    """,
                    (reason, context.owner, context.tenant_id, agent_id, agent_id),
                )
                vc_result = self._conn.execute(
                    """
                    UPDATE verifiable_credentials
                    SET revoked = 1,
                        revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                        revocation_reason = ?
                    WHERE owner = ? AND tenant_id = ? AND revoked = 0
                      AND (
                        issuer_did IN (SELECT did FROM agent_dids WHERE agent_id = ?)
                        OR subject_did IN (SELECT did FROM agent_dids WHERE agent_id = ?)
                      )
                    """,
                    (reason, context.owner, context.tenant_id, agent_id, agent_id),
                )
                self._conn.commit()
                return capability_result.rowcount, vc_result.rowcount
            except Exception:
                self._conn.rollback()
                raise


_STORAGE = IdentityStorage()


def register_agent_identity(
    *,
    agent_id: str,
    owner: str,
    tenant_id: str = "tenant-default",
    credential_type: str,
    public_key_pem: str | None = None,
    metadata: dict[str, str] | None = None,
    human_principal_id: str | None = None,
    configuration_checksum: str | None = None,
) -> AgentIdentity:
    return _STORAGE.register_identity(
        agent_id=agent_id,
        owner=owner,
        tenant_id=tenant_id,
        credential_type=credential_type,
        public_key_pem=public_key_pem,
        metadata=metadata,
        human_principal_id=human_principal_id,
        configuration_checksum=configuration_checksum,
    )


def register_agent_identity_for_actor(
    *,
    actor: ResourceAuthContext,
    agent_id: str,
    credential_type: str,
    public_key_pem: str | None = None,
    metadata: dict[str, str] | None = None,
    human_principal_id: str | None = None,
    configuration_checksum: str | None = None,
) -> AgentIdentity:
    return _STORAGE.register_identity_for_actor(
        actor=actor,
        agent_id=agent_id,
        credential_type=credential_type,
        public_key_pem=public_key_pem,
        metadata=metadata,
        human_principal_id=human_principal_id,
        configuration_checksum=configuration_checksum,
    )


def get_agent_identity(agent_id: str) -> AgentIdentity:
    return _STORAGE.get_identity(agent_id)


def get_agent_identity_for_actor(
    agent_id: str, actor: ResourceAuthContext
) -> AgentIdentity:
    return _STORAGE.get_identity_for_actor(agent_id, actor)


def get_peer_agent_identity_for_actor(
    agent_id: str,
    actor: ResourceAuthContext,
) -> AgentIdentity:
    return _STORAGE.get_peer_identity_for_actor(agent_id, actor)


def get_agent_identity_auth_snapshot(
    agent_id: str,
    *,
    ensure_generation: bool = False,
) -> tuple[AgentIdentity, str | None, str | None]:
    return _STORAGE.get_identity_auth_snapshot(
        agent_id, ensure_generation=ensure_generation
    )


def update_agent_identity_status(agent_id: str, status: str) -> AgentIdentity:
    return _STORAGE.update_identity_status(agent_id, status)


def update_agent_identity_status_for_actor(
    agent_id: str,
    status: str,
    actor: ResourceAuthContext,
) -> AgentIdentity:
    return _STORAGE.update_identity_status_for_actor(agent_id, status, actor)


def list_agent_identities(owner: str) -> list[AgentIdentity]:
    return _STORAGE.list_identities(owner)


def list_agent_identities_for_actor(actor: ResourceAuthContext) -> list[AgentIdentity]:
    return _STORAGE.list_identities_for_actor(actor)


def list_quarantined_agent_identities_for_actor(
    actor: ResourceAuthContext,
) -> list[AgentIdentity]:
    return _STORAGE.list_quarantined_identities_for_actor(actor)


def assign_quarantined_agent_identity_for_actor(
    *,
    actor: ResourceAuthContext,
    agent_id: str,
    selected_tenant_id: str,
) -> AgentIdentity:
    return _STORAGE.assign_quarantined_identity_for_actor(
        actor=actor,
        agent_id=agent_id,
        selected_tenant_id=selected_tenant_id,
    )


def count_quarantined_agent_identities() -> int:
    return _STORAGE.count_quarantined_identities()


def bind_human_principal(
    agent_id: str, human_principal_id: str | None
) -> AgentIdentity:
    return _STORAGE.bind_human_principal(agent_id, human_principal_id)


def bind_human_principal_for_actor(
    agent_id: str,
    human_principal_id: str | None,
    actor: ResourceAuthContext,
) -> AgentIdentity:
    return _STORAGE.bind_human_principal_for_actor(agent_id, human_principal_id, actor)


def set_configuration_checksum(agent_id: str, checksum: str | None) -> AgentIdentity:
    return _STORAGE.set_configuration_checksum(agent_id, checksum)


def set_configuration_checksum_for_actor(
    agent_id: str,
    checksum: str | None,
    actor: ResourceAuthContext,
) -> AgentIdentity:
    return _STORAGE.set_configuration_checksum_for_actor(agent_id, checksum, actor)


def list_active_sessions(agent_id: str) -> ActiveSessions:
    credentials = _STORAGE.list_active_credentials(agent_id)
    return ActiveSessions(agent_id=agent_id, credentials=credentials)


def list_active_sessions_for_actor(
    agent_id: str, actor: ResourceAuthContext
) -> ActiveSessions:
    credentials = _STORAGE.list_active_credentials_for_actor(agent_id, actor)
    return ActiveSessions(agent_id=agent_id, credentials=credentials)


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)


# Expose internal storage for credential operations
IDENTITY_STORAGE = _STORAGE


def _generation_from_metadata(raw: object) -> str | None:
    generation = _stored_metadata(raw).get(_AUTH_GENERATION_KEY)
    return generation if isinstance(generation, str) and generation else None


def _row_to_capability_root(row: sqlite3.Row) -> dict[str, object]:
    issuer_generation = _generation_from_metadata(row["issuer_metadata_json"])
    subject_generation = _generation_from_metadata(row["subject_metadata_json"])
    issuer_active = (
        row["issuer_status"] == STATUS_ACTIVE
        and row["issuer_tenancy_status"] == TENANCY_ACTIVE
    )
    subject_active = (
        row["subject_status"] == STATUS_ACTIVE
        and row["subject_tenancy_status"] == TENANCY_ACTIVE
    )
    generations_current = (
        issuer_generation == row["issuer_generation"]
        and subject_generation == row["subject_generation"]
    )
    return {
        "token_id": str(row["token_id"]),
        "owner": str(row["owner"]),
        "tenant_id": str(row["tenant_id"]),
        "issuer_agent_id": str(row["issuer_agent_id"]),
        "subject_agent_id": str(row["subject_agent_id"]),
        "issuer_generation": str(row["issuer_generation"]),
        "subject_generation": str(row["subject_generation"]),
        "audience": str(row["audience"]),
        "resource": str(row["resource"]),
        "scopes": list(json.loads(str(row["scopes_json"]))),
        "issued_at_epoch": float(row["issued_at_epoch"]),
        "expires_at_epoch": float(row["expires_at_epoch"]),
        "revoked": bool(row["revoked"]),
        "revoked_at": row["revoked_at"],
        "revocation_reason": row["revocation_reason"],
        "issuer_active": issuer_active,
        "subject_active": subject_active,
        "identity_active": issuer_active and subject_active,
        "generations_current": generations_current,
        "created_at": str(row["created_at"]),
    }


def _row_to_did(row: sqlite3.Row) -> dict[str, object]:
    document = dict(json.loads(str(row["document_json"])))
    document["deactivated"] = bool(row["deactivated"])
    if bool(row["deactivated"]):
        document["updated"] = str(row["updated_at"])
    if row["deactivation_reason"] is not None:
        document["deactivation_reason"] = str(row["deactivation_reason"])
    return document


def _row_to_verifiable_credential(row: sqlite3.Row) -> dict[str, object]:
    record = dict(json.loads(str(row["record_json"])))
    issuer_active = (
        not bool(row["issuer_did_deactivated"])
        and row["issuer_identity_status"] == STATUS_ACTIVE
        and row["issuer_tenancy_status"] == TENANCY_ACTIVE
    )
    subject_active = (
        not bool(row["subject_did_deactivated"])
        and row["subject_identity_status"] == STATUS_ACTIVE
        and row["subject_tenancy_status"] == TENANCY_ACTIVE
    )
    generations_current = (
        _generation_from_metadata(row["issuer_metadata_json"])
        == row["issuer_generation"]
        and _generation_from_metadata(row["subject_metadata_json"])
        == row["subject_generation"]
    )
    issuer_generation_current = (
        _generation_from_metadata(row["issuer_metadata_json"])
        == row["issuer_generation"]
    )
    subject_generation_current = (
        _generation_from_metadata(row["subject_metadata_json"])
        == row["subject_generation"]
    )
    record.update(
        {
            "owner": str(row["owner"]),
            "tenant_id": str(row["tenant_id"]),
            "issuer_generation": str(row["issuer_generation"]),
            "subject_generation": str(row["subject_generation"]),
            "issuer_agent_id": str(row["issuer_agent_id"]),
            "subject_agent_id": str(row["subject_agent_id"]),
            "revoked": bool(row["revoked"]),
            "revoked_at": row["revoked_at"],
            "revocation_reason": row["revocation_reason"],
            "issuer_active": issuer_active,
            "subject_active": subject_active,
            "identity_active": issuer_active and subject_active,
            "generations_current": generations_current,
            "issuer_identity_generation_current": issuer_generation_current,
            "subject_identity_generation_current": subject_generation_current,
        }
    )
    return record


def _row_to_identity(row: sqlite3.Row) -> AgentIdentity:
    metadata = _stored_metadata(row["metadata_json"])
    metadata.pop(_AUTH_GENERATION_KEY, None)
    return AgentIdentity(
        agent_id=str(row["agent_id"]),
        owner=str(row["owner"]),
        tenant_id=str(row["tenant_id"]) if row["tenant_id"] is not None else None,
        tenancy_status=str(row["tenancy_status"]),
        credential_type=str(row["credential_type"]),
        status=str(row["status"]),
        public_key_pem=row["public_key_pem"],
        metadata=metadata,
        human_principal_id=row["human_principal_id"],
        configuration_checksum=row["configuration_checksum"],
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _stored_metadata(raw: object) -> dict[str, str]:
    if not raw:
        return {}
    parsed = json.loads(str(raw))
    return {str(key): str(value) for key, value in parsed.items()}


def _row_to_credential(row: sqlite3.Row) -> AgentCredential:
    scopes_raw = row["scopes_json"]
    scopes = json.loads(scopes_raw) if scopes_raw else []
    return AgentCredential(
        credential_id=str(row["credential_id"]),
        agent_id=str(row["agent_id"]),
        scopes=scopes,
        issued_at_epoch=int(row["issued_at_epoch"]),
        expires_at_epoch=int(row["expires_at_epoch"]),
        rotation_parent_id=row["rotation_parent_id"],
        status=str(row["status"]),
        revoked_at=row["revoked_at"],
        revocation_reason=row["revocation_reason"],
        created_at=str(row["created_at"]),
    )
