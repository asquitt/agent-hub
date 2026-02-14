"""OAuth 2.1 dynamic client storage and validation."""
from __future__ import annotations

import hashlib
import secrets
import threading
from typing import Any

from src.common.time import utc_now_epoch


class OAuthClientStore:
    """In-memory OAuth client registry. Production would use SQLite."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._clients: dict[str, dict[str, Any]] = {}

    def register_client(
        self,
        *,
        client_name: str,
        grant_types: list[str] | None = None,
        scope: str | None = None,
        redirect_uris: list[str] | None = None,
    ) -> dict[str, Any]:
        client_id = f"client_{secrets.token_hex(16)}"
        client_secret = secrets.token_urlsafe(48)
        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        now = utc_now_epoch()

        record: dict[str, Any] = {
            "client_id": client_id,
            "client_secret_hash": secret_hash,
            "client_name": client_name,
            "grant_types": grant_types or ["client_credentials"],
            "scope": scope or "",
            "redirect_uris": redirect_uris or [],
            "created_at": now,
        }

        with self._lock:
            self._clients[client_id] = record

        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "grant_types": record["grant_types"],
            "scope": record["scope"],
            "redirect_uris": record["redirect_uris"],
        }

    def authenticate_client(self, client_id: str, client_secret: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._clients.get(client_id)
        if record is None:
            return None
        provided_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        if provided_hash != record["client_secret_hash"]:
            return None
        return {
            "client_id": record["client_id"],
            "client_name": record["client_name"],
            "grant_types": record["grant_types"],
            "scope": record["scope"],
        }

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._clients.get(client_id)
        if record is None:
            return None
        return {
            "client_id": record["client_id"],
            "client_name": record["client_name"],
            "grant_types": record["grant_types"],
            "scope": record["scope"],
        }

    def reset_for_tests(self) -> None:
        with self._lock:
            self._clients.clear()


OAUTH_CLIENT_STORE = OAuthClientStore()
