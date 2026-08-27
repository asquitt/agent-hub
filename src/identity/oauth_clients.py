"""OAuth 2.1 dynamic client storage and validation."""
from __future__ import annotations

from collections.abc import Iterable
import hashlib
import hmac
import os
import secrets
import threading
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import read_collection, write_collection
from src.common.time import utc_now_epoch


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "identity" / "identity.db"

_MAX_CLIENTS = 10_000
_COLLECTION_SCOPE = "identity"
_COLLECTION_NAME = "oauth_clients"
_SUPPORTED_GRANT_TYPES = frozenset({"client_credentials"})
_STORE_LOCK = threading.RLock()


def _identity_db_path() -> Path:
    return Path(os.getenv("AGENTHUB_IDENTITY_DB_PATH", str(DEFAULT_DB)))


def _normalize_grant_types(grant_types: list[str] | None) -> list[str]:
    raw_grants = ["client_credentials"] if grant_types is None else grant_types
    if not raw_grants:
        raise ValueError("grant_types must include client_credentials")

    normalized: set[str] = set()
    for grant_type in raw_grants:
        if not isinstance(grant_type, str) or not grant_type.strip():
            raise ValueError("grant_types must contain non-empty strings")
        normalized.add(grant_type.strip())

    unsupported = sorted(normalized - _SUPPORTED_GRANT_TYPES)
    if unsupported:
        raise ValueError(f"unsupported grant_type: {unsupported[0]}")
    return sorted(normalized)


def _normalize_scope(scope: str | None) -> str:
    if scope is None:
        return ""
    if not isinstance(scope, str):
        raise ValueError("scope must be a string")
    return " ".join(sorted(set(scope.split())))


def _scope_allowed(scope: str, authorized_scopes: set[str]) -> bool:
    if "*" in authorized_scopes or scope in authorized_scopes:
        return True
    namespace = scope.split(".", 1)[0]
    return f"{namespace}.*" in authorized_scopes


def _created_at_sort_key(record: dict[str, Any]) -> int:
    created_at = record.get("created_at")
    return created_at if isinstance(created_at, int) and not isinstance(created_at, bool) else -1

def _normalize_redirect_uris(redirect_uris: list[str] | None) -> list[str]:
    if redirect_uris is None:
        return []
    normalized: list[str] = []
    for redirect_uri in redirect_uris:
        if not isinstance(redirect_uri, str) or not redirect_uri.strip():
            raise ValueError("redirect_uris must contain non-empty strings")
        normalized.append(redirect_uri.strip())
    return sorted(set(normalized))


def _normalize_authority(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")
    return value.strip()


def _validated_record(record: dict[str, Any]) -> dict[str, Any] | None:
    client_id = record.get("client_id")
    secret_hash = record.get("client_secret_hash")
    client_name = record.get("client_name")
    owner = record.get("owner")
    tenant_id = record.get("tenant_id")
    created_at = record.get("created_at")
    if not isinstance(client_id, str) or not client_id:
        return None
    if not isinstance(secret_hash, str) or len(secret_hash) != 64:
        return None
    try:
        bytes.fromhex(secret_hash)
    except ValueError:
        return None
    if not isinstance(client_name, str) or not client_name:
        return None
    if not isinstance(owner, str) or not owner.strip():
        return None
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return None
    if not isinstance(created_at, int) or isinstance(created_at, bool):
        return None

    raw_grants = record.get("grant_types")
    raw_scope = record.get("scope")
    raw_redirect_uris = record.get("redirect_uris")
    if not isinstance(raw_grants, list) or not isinstance(raw_scope, str) or not isinstance(raw_redirect_uris, list):
        return None
    if not isinstance(owner, str) or not owner.strip():
        return None
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return None
    try:
        grant_types = _normalize_grant_types(raw_grants)
        scope = _normalize_scope(raw_scope)
        redirect_uris = _normalize_redirect_uris(raw_redirect_uris)
    except ValueError:
        return None

    return {
        "client_id": client_id,
        "client_secret_hash": secret_hash,
        "client_name": client_name,
        "grant_types": grant_types,
        "scope": scope,
        "redirect_uris": redirect_uris,
        "owner": owner.strip(),
        "tenant_id": tenant_id.strip(),
        "created_at": created_at,
    }


def _validated_legacy_record(record: dict[str, Any]) -> dict[str, Any] | None:
    if record.get("owner") not in (None, "") or record.get("tenant_id") not in (None, ""):
        return None
    candidate = {**record, "owner": "legacy-owner", "tenant_id": "tenant-default"}
    validated = _validated_record(candidate)
    if validated is None:
        return None
    validated.pop("owner")
    validated.pop("tenant_id")
    return validated


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "client_id": record["client_id"],
        "client_name": record["client_name"],
        "owner": record["owner"],
        "tenant_id": record["tenant_id"],
        "grant_types": list(record["grant_types"]),
        "scope": record["scope"],
        "redirect_uris": list(record["redirect_uris"]),
    }


class OAuthClientStore:
    """Durable OAuth client registry backed by the identity SQLite database."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else None

    def _path(self) -> Path:
        return self._db_path or _identity_db_path()

    def _read_records(self) -> list[dict[str, Any]]:
        return read_collection(
            db_path=self._path(),
            scope=_COLLECTION_SCOPE,
            collection_name=_COLLECTION_NAME,
        )

    def _find_record(self, client_id: str) -> dict[str, Any] | None:
        matches = [record for record in self._read_records() if record.get("client_id") == client_id]
        if len(matches) != 1:
            return None
        return _validated_record(matches[0])

    def register_client(
        self,
        *,
        client_name: str,
        owner: str,
        tenant_id: str,
        authorized_scopes: Iterable[str],
        grant_types: list[str] | None = None,
        scope: str | None = None,
        redirect_uris: list[str] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(client_name, str) or not client_name.strip():
            raise ValueError("client_name is required")
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("owner is required")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id is required")

        normalized_owner = _normalize_authority(owner, field_name="owner")
        normalized_tenant_id = _normalize_authority(tenant_id, field_name="tenant_id")
        normalized_grants = _normalize_grant_types(grant_types)
        normalized_scope = _normalize_scope(scope)
        registrar_scopes = {str(item).strip() for item in authorized_scopes if str(item).strip()}
        if any(not _scope_allowed(item, registrar_scopes) for item in normalized_scope.split()):
            raise ValueError("requested scope exceeds registrar authority")
        normalized_redirect_uris = _normalize_redirect_uris(redirect_uris)
        client_secret = secrets.token_urlsafe(48)
        secret_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

        with _STORE_LOCK:
            records = self._read_records()
            existing_ids = {record.get("client_id") for record in records}
            client_id = f"client_{secrets.token_hex(16)}"
            while client_id in existing_ids:
                client_id = f"client_{secrets.token_hex(16)}"

            record: dict[str, Any] = {
                "client_id": client_id,
                "client_secret_hash": secret_hash,
                "client_name": client_name.strip(),
                "owner": normalized_owner,
                "tenant_id": normalized_tenant_id,
                "grant_types": normalized_grants,
                "scope": normalized_scope,
                "redirect_uris": normalized_redirect_uris,
                "created_at": utc_now_epoch(),
            }
            records.append(record)
            if len(records) > _MAX_CLIENTS:
                records.sort(key=_created_at_sort_key)
                records = records[-_MAX_CLIENTS:]
            write_collection(
                db_path=self._path(),
                scope=_COLLECTION_SCOPE,
                collection_name=_COLLECTION_NAME,
                rows=records,
            )

        return {**_public_record(record), "client_secret": client_secret}

    def authenticate_client(self, client_id: str, client_secret: str) -> dict[str, Any] | None:
        if not client_id or not client_secret:
            return None
        with _STORE_LOCK:
            record = self._find_record(client_id)
        if record is None:
            return None
        provided_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(provided_hash, record["client_secret_hash"]):
            return None
        return _public_record(record)

    def bind_legacy_client_authority(
        self,
        *,
        client_id: str,
        client_secret: str,
        owner: str,
        tenant_id: str,
        authorized_scopes: Iterable[str],
    ) -> dict[str, Any] | None:
        """Bind owner and tenant to a BASE-shaped record after secret proof."""
        if not client_id or not client_secret:
            return None
        normalized_owner = _normalize_authority(owner, field_name="owner")
        normalized_tenant_id = _normalize_authority(tenant_id, field_name="tenant_id")
        registrar_scopes = {str(item).strip() for item in authorized_scopes if str(item).strip()}
        provided_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

        with _STORE_LOCK:
            records = self._read_records()
            matches = [index for index, record in enumerate(records) if record.get("client_id") == client_id]
            if len(matches) != 1:
                return None
            record_index = matches[0]
            raw_record = records[record_index]

            bound_record = _validated_record(raw_record)
            if bound_record is not None:
                return None

            legacy_record = _validated_legacy_record(raw_record)
            if legacy_record is None or not hmac.compare_digest(provided_hash, legacy_record["client_secret_hash"]):
                return None
            if any(not _scope_allowed(item, registrar_scopes) for item in str(legacy_record["scope"]).split()):
                return None
            authority_binding_id = f"oab_{secrets.token_hex(16)}"
            bound_record = {
                **legacy_record,
                "owner": normalized_owner,
                "tenant_id": normalized_tenant_id,
                "authority_binding": {
                    "event_id": authority_binding_id,
                    "event_type": "oauth.client_authority_bound",
                    "client_id": client_id,
                    "actor": normalized_owner,
                    "tenant_id": normalized_tenant_id,
                    "bound_at_epoch": utc_now_epoch(),
                },
            }
            records[record_index] = bound_record
            write_collection(
                db_path=self._path(),
                scope=_COLLECTION_SCOPE,
                collection_name=_COLLECTION_NAME,
                rows=records,
            )
            return {**_public_record(bound_record), "authority_binding_id": authority_binding_id}

    def get_authority_binding(self, client_id: str) -> dict[str, Any] | None:
        """Return durable evidence for a legacy authority transition."""
        with _STORE_LOCK:
            matches = [record for record in self._read_records() if record.get("client_id") == client_id]
        if len(matches) != 1:
            return None
        binding = matches[0].get("authority_binding")
        if not isinstance(binding, dict):
            return None
        return dict(binding)

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with _STORE_LOCK:
            record = self._find_record(client_id)
        return _public_record(record) if record is not None else None

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        path = Path(db_path) if db_path is not None else self._path()
        with _STORE_LOCK:
            write_collection(
                db_path=path,
                scope=_COLLECTION_SCOPE,
                collection_name=_COLLECTION_NAME,
                rows=[],
            )


OAUTH_CLIENT_STORE = OAuthClientStore()
