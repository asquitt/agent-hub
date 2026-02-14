from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.identity.constants import CRED_STATUS_ACTIVE, STATUS_ACTIVE, VALID_IDENTITY_STATUSES
from src.identity.types import ActiveSessions, AgentCredential, AgentIdentity
from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "identity" / "identity.db"


def _path_db() -> Path:
    return Path(os.getenv("AGENTHUB_IDENTITY_DB_PATH", str(DEFAULT_DB)))


class IdentityStorage:
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
                self._conn.execute("DELETE FROM agent_credentials")
                self._conn.execute("DELETE FROM agent_identities")

    # --- Agent Identity CRUD ---

    def register_identity(
        self,
        *,
        agent_id: str,
        owner: str,
        credential_type: str,
        public_key_pem: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> AgentIdentity:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO agent_identities(
                            agent_id, owner, credential_type, status, public_key_pem, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            agent_id,
                            owner,
                            credential_type,
                            STATUS_ACTIVE,
                            public_key_pem,
                            json.dumps(metadata or {}, sort_keys=True),
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"agent identity already exists: {agent_id}") from exc
            return self._get_identity_locked(agent_id)

    def get_identity(self, agent_id: str) -> AgentIdentity:
        self._ensure_ready()
        with self._lock:
            return self._get_identity_locked(agent_id)

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

    def list_identities(self, owner: str) -> list[AgentIdentity]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                "SELECT * FROM agent_identities WHERE owner = ? ORDER BY created_at DESC",
                (owner,),
            ).fetchall()
            return [_row_to_identity(row) for row in rows]

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

    def list_active_credentials(self, agent_id: str) -> list[AgentCredential]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT * FROM agent_credentials
                WHERE agent_id = ? AND status = ?
                ORDER BY issued_at_epoch DESC
                """,
                (agent_id, CRED_STATUS_ACTIVE),
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
    credential_type: str,
    public_key_pem: str | None = None,
    metadata: dict[str, str] | None = None,
) -> AgentIdentity:
    return _STORAGE.register_identity(
        agent_id=agent_id,
        owner=owner,
        credential_type=credential_type,
        public_key_pem=public_key_pem,
        metadata=metadata,
    )


def get_agent_identity(agent_id: str) -> AgentIdentity:
    return _STORAGE.get_identity(agent_id)


def update_agent_identity_status(agent_id: str, status: str) -> AgentIdentity:
    return _STORAGE.update_identity_status(agent_id, status)


def list_agent_identities(owner: str) -> list[AgentIdentity]:
    return _STORAGE.list_identities(owner)


def list_active_sessions(agent_id: str) -> ActiveSessions:
    credentials = _STORAGE.list_active_credentials(agent_id)
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
