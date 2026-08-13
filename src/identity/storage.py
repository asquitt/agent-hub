from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable

from src.identity.constants import (
    CRED_STATUS_ACTIVE,
    CRED_STATUS_REVOKED,
    CRED_STATUS_ROTATED,
    STATUS_ACTIVE,
    VALID_IDENTITY_STATUSES,
)
from src.identity.types import ActiveSessions, AgentCredential, AgentIdentity
from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "identity" / "identity.db"


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
        self._ensure_authorization_schema_locked()
        self._db_path = str(db_path)

    def _ensure_authorization_schema_locked(self) -> None:
        """Add the resource tenant discriminator for databases created before S163."""
        assert self._conn is not None
        columns = {
            str(row["name"])
            for row in self._conn.execute("PRAGMA table_info(agent_identities)").fetchall()
        }
        with self._conn:
            if "tenant_id" not in columns:
                self._conn.execute(
                    "ALTER TABLE agent_identities "
                    "ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'tenant-default'"
                )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_identities_owner_tenant "
                "ON agent_identities(owner, tenant_id)"
            )

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
                # Delete in FK-safe order: children before parents
                for table in [
                    "agent_attestations",
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
        with self._lock:
            assert self._conn is not None
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO agent_identities(
                            agent_id, owner, tenant_id, credential_type, status, public_key_pem, metadata_json,
                            human_principal_id, configuration_checksum
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            agent_id,
                            owner,
                            tenant_id,
                            credential_type,
                            STATUS_ACTIVE,
                            public_key_pem,
                            json.dumps(metadata or {}, sort_keys=True),
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

    def get_identity_for_actor(self, agent_id: str, actor: ResourceAuthContext) -> AgentIdentity:
        context = require_resource_actor(actor)
        _require_actor_agent(context, agent_id)
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT * FROM agent_identities
                WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                """,
                (agent_id, context.owner, context.tenant_id),
            ).fetchone()
            if row is None:
                raise KeyError(f"agent identity not found: {agent_id}")
            return _row_to_identity(row)

    def _get_identity_locked(self, agent_id: str) -> AgentIdentity:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM agent_identities WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"agent identity not found: {agent_id}")
        return _row_to_identity(row)

    def update_identity_status(self, agent_id: str, status: str) -> AgentIdentity:
        if status not in VALID_IDENTITY_STATUSES:
            raise ValueError(f"invalid status: {status}")
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ?
                    """,
                    (status, agent_id),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

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
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                    """,
                    (status, agent_id, context.owner, context.tenant_id),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    def list_identities(self, owner: str) -> list[AgentIdentity]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                "SELECT * FROM agent_identities WHERE owner = ? ORDER BY created_at DESC LIMIT ?",
                (owner, self._MAX_QUERY_ROWS),
            ).fetchall()
            return [_row_to_identity(row) for row in rows]

    def bind_human_principal(self, agent_id: str, human_principal_id: str | None) -> AgentIdentity:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET human_principal_id = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ?
                    """,
                    (human_principal_id, agent_id),
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
                    """,
                    (human_principal_id, agent_id, context.owner, context.tenant_id),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

    def set_configuration_checksum(self, agent_id: str, checksum: str | None) -> AgentIdentity:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET configuration_checksum = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ?
                    """,
                    (checksum, agent_id),
                )
                if result.rowcount == 0:
                    raise KeyError(f"agent identity not found: {agent_id}")
            return self._get_identity_locked(agent_id)

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
            with self._conn:
                result = self._conn.execute(
                    """
                    UPDATE agent_identities
                    SET configuration_checksum = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE agent_id = ? AND owner = ? AND tenant_id = ?
                    """,
                    (checksum, agent_id, context.owner, context.tenant_id),
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
                    """,
                    (agent_id, context.owner, context.tenant_id),
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
                  AND (? IS NULL OR identity.agent_id = ?)
                """,
                (
                    credential_id,
                    context.owner,
                    context.tenant_id,
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
                      AND (? IS NULL OR identity.agent_id = ?)
                    """,
                    (
                        credential_id,
                        context.owner,
                        context.tenant_id,
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
                normalized_scopes = old_credential["scopes"] if scopes is None else sorted(scopes)
                result = self._conn.execute(
                    """
                    UPDATE agent_credentials
                    SET status = ?
                    WHERE credential_id = ? AND status = ?
                    """,
                    (CRED_STATUS_ROTATED, credential_id, CRED_STATUS_ACTIVE),
                )
                if result.rowcount != 1:
                    raise ValueError("credential is no longer active (concurrent modification)")
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
                      AND (? IS NULL OR identity.agent_id = ?)
                    """,
                    (
                        credential_id,
                        context.owner,
                        context.tenant_id,
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
                "SELECT * FROM agent_credentials WHERE credential_hash = ? AND status = ?",
                (credential_hash, CRED_STATUS_ACTIVE),
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
                revoked_at = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')" if status == "revoked" else None
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
                    raise ValueError("credential is no longer active (concurrent modification)")
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
                """,
                (agent_id, context.owner, context.tenant_id),
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


def get_agent_identity_for_actor(agent_id: str, actor: ResourceAuthContext) -> AgentIdentity:
    return _STORAGE.get_identity_for_actor(agent_id, actor)


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


def bind_human_principal(agent_id: str, human_principal_id: str | None) -> AgentIdentity:
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


def list_active_sessions_for_actor(agent_id: str, actor: ResourceAuthContext) -> ActiveSessions:
    credentials = _STORAGE.list_active_credentials_for_actor(agent_id, actor)
    return ActiveSessions(agent_id=agent_id, credentials=credentials)


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)


# Expose internal storage for credential operations
IDENTITY_STORAGE = _STORAGE


def _row_to_identity(row: sqlite3.Row) -> AgentIdentity:
    metadata_raw = row["metadata_json"]
    metadata = json.loads(metadata_raw) if metadata_raw else None
    return AgentIdentity(
        agent_id=str(row["agent_id"]),
        owner=str(row["owner"]),
        credential_type=str(row["credential_type"]),
        status=str(row["status"]),
        public_key_pem=row["public_key_pem"],
        metadata=metadata,
        human_principal_id=row["human_principal_id"],
        configuration_checksum=row["configuration_checksum"],
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


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
