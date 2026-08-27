"""Secret Rotation Vault — automated credential lifecycle management.

Provides:
- Encrypted secret storage with versioning
- Automated rotation schedules
- Rotation history and audit trail
- Secret access control per agent
- Rotation alerts for upcoming expirations
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
import time
import uuid
from typing import Any

from src.identity.storage import (
    ResourceAuthContext,
    get_agent_identity_for_actor,
    require_resource_actor,
)

_log = logging.getLogger("agenthub.secret_vault")

# Secret types
SECRET_API_KEY = "api_key"
SECRET_TOKEN = "token"
SECRET_CERTIFICATE = "certificate"
SECRET_PASSWORD = "password"
SECRET_SIGNING_KEY = "signing_key"

VALID_SECRET_TYPES = {SECRET_API_KEY, SECRET_TOKEN, SECRET_CERTIFICATE, SECRET_PASSWORD, SECRET_SIGNING_KEY}

# Rotation status
ROTATION_PENDING = "pending"
ROTATION_ACTIVE = "active"
ROTATION_ROTATED = "rotated"
ROTATION_EXPIRED = "expired"

# In-memory stores
_MAX_RECORDS = 10_000
_secrets: dict[str, dict[str, Any]] = {}  # secret_id -> secret
_rotation_history: list[dict[str, Any]] = []
_lock = threading.RLock()


def _vault_key() -> str:
    key = os.environ.get("AGENTHUB_VAULT_KEY", "")
    if not key:
        raise RuntimeError("AGENTHUB_VAULT_KEY env var is required")
    return key


def store_secret(
    *,
    actor: ResourceAuthContext,
    name: str,
    value: str,
    secret_type: str = SECRET_API_KEY,
    agent_id: str | None = None,
    ttl_seconds: int = 2592000,  # 30 days
    rotation_interval: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store a new secret in the vault."""
    context = require_resource_actor(actor)
    if secret_type not in VALID_SECRET_TYPES:
        raise ValueError(f"invalid secret type: {secret_type}")
    if ttl_seconds < 300 or ttl_seconds > 31536000:  # 5 min to 1 year
        raise ValueError("ttl must be between 300 seconds and 1 year")
    if context.agent_id is not None:
        if agent_id is not None and agent_id != context.agent_id:
            raise PermissionError("agent-bound principal cannot bind a secret to another agent")
        agent_id = context.agent_id
    if agent_id is not None:
        get_agent_identity_for_actor(agent_id, context)

    now = time.time()
    secret_id = f"secret-{uuid.uuid4().hex[:12]}"

    # Hash the value for storage (never store plaintext)
    value_hash = _hash_value(value)

    secret: dict[str, Any] = {
        "secret_id": secret_id,
        "owner": context.owner,
        "tenant_id": context.tenant_id,
        "name": name,
        "secret_type": secret_type,
        "agent_id": agent_id,
        "value_hash": value_hash,
        "version": 1,
        "status": ROTATION_ACTIVE,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "rotation_interval": rotation_interval,
        "next_rotation_at": (now + rotation_interval) if rotation_interval else None,
        "last_rotated_at": None,
        "access_count": 0,
        "last_accessed_at": None,
        "metadata": metadata or {},
    }

    with _lock:
        _secrets[secret_id] = secret
        if len(_secrets) > _MAX_RECORDS:
            oldest = sorted(_secrets, key=lambda k: _secrets[k]["created_at"])
            for k in oldest[: len(oldest) - _MAX_RECORDS]:
                del _secrets[k]

    _log.info("secret stored: id=%s name=%s type=%s", secret_id, name, secret_type)
    return _sanitize(secret)


def get_secret(secret_id: str, *, actor: ResourceAuthContext) -> dict[str, Any]:
    """Get secret metadata (never returns the actual value)."""
    context = require_resource_actor(actor)
    with _lock:
        secret = _get_authorized_secret_locked(secret_id, context)
        if secret["status"] == ROTATION_ACTIVE and time.time() > secret["expires_at"]:
            secret["status"] = ROTATION_EXPIRED
        return _sanitize(secret)


def access_secret(
    secret_id: str,
    *,
    actor: ResourceAuthContext,
    agent_id: str,
) -> dict[str, Any]:
    """Record an access to a secret and return metadata."""
    context = require_resource_actor(actor)
    if context.agent_id is not None and context.agent_id != agent_id:
        raise PermissionError("authenticated agent does not match requested agent")
    with _lock:
        secret = _get_authorized_secret_locked(secret_id, context)
        if secret["status"] != ROTATION_ACTIVE:
            raise ValueError(f"secret is {secret['status']}, not active")
        if time.time() > secret["expires_at"]:
            secret["status"] = ROTATION_EXPIRED
            raise ValueError("secret has expired")

        effective_agent_id = context.agent_id or agent_id
        if secret.get("agent_id") and secret["agent_id"] != effective_agent_id:
            if context.agent_id is not None:
                raise KeyError(f"secret not found: {secret_id}")
            raise ValueError(f"agent {agent_id} not authorized to access this secret")

        secret["access_count"] += 1
        secret["last_accessed_at"] = time.time()
        return _sanitize(secret)


def rotate_secret(
    secret_id: str,
    *,
    actor: ResourceAuthContext,
    new_value: str,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """Rotate a secret with a new value."""
    context = require_resource_actor(actor)
    with _lock:
        secret = _get_authorized_secret_locked(secret_id, context)
        now = time.time()
        old_version = secret["version"]
        remaining_ttl = max(secret["expires_at"] - now, 300)

        _rotation_history.append({
            "rotation_id": f"rot-{uuid.uuid4().hex[:12]}",
            "secret_id": secret_id,
            "owner": context.owner,
            "tenant_id": context.tenant_id,
            "agent_id": secret.get("agent_id"),
            "old_version": old_version,
            "new_version": old_version + 1,
            "rotated_at": now,
        })
        if len(_rotation_history) > _MAX_RECORDS:
            _rotation_history[:] = _rotation_history[-_MAX_RECORDS:]

        secret["value_hash"] = _hash_value(new_value)
        secret["version"] += 1
        secret["last_rotated_at"] = now
        secret["status"] = ROTATION_ACTIVE
        secret["expires_at"] = now + (ttl_seconds if ttl_seconds else remaining_ttl)

        if secret.get("rotation_interval"):
            secret["next_rotation_at"] = now + secret["rotation_interval"]

        _log.info("secret rotated: id=%s v%d->v%d", secret_id, old_version, old_version + 1)
        return _sanitize(secret)


def revoke_secret(secret_id: str, *, actor: ResourceAuthContext) -> dict[str, Any]:
    """Revoke a secret (mark as expired)."""
    context = require_resource_actor(actor)
    with _lock:
        secret = _get_authorized_secret_locked(secret_id, context)
        secret["status"] = ROTATION_EXPIRED
        secret["expires_at"] = time.time()
        _log.warning("secret revoked: id=%s", secret_id)
        return _sanitize(secret)


def list_secrets(
    *,
    actor: ResourceAuthContext,
    agent_id: str | None = None,
    secret_type: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List secrets (metadata only)."""
    context = require_resource_actor(actor)
    with _lock:
        results: list[dict[str, Any]] = []
        for secret in _secrets.values():
            if not _actor_owns_secret(context, secret):
                continue
            if secret["status"] == ROTATION_ACTIVE and time.time() > secret["expires_at"]:
                secret["status"] = ROTATION_EXPIRED
            if agent_id and secret.get("agent_id") != agent_id:
                continue
            if secret_type and secret["secret_type"] != secret_type:
                continue
            if status and secret["status"] != status:
                continue
            results.append(_sanitize(secret))
            if len(results) >= limit:
                break
        return results


def get_rotation_history(
    *,
    actor: ResourceAuthContext,
    secret_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get rotation history."""
    context = require_resource_actor(actor)
    with _lock:
        results: list[dict[str, Any]] = []
        for record in reversed(_rotation_history):
            if record.get("owner") != context.owner or record.get("tenant_id") != context.tenant_id:
                continue
            if context.agent_id is not None and record.get("agent_id") != context.agent_id:
                continue
            if secret_id and record["secret_id"] != secret_id:
                continue
            results.append(dict(record))
            if len(results) >= limit:
                break
        return results


def get_expiring_secrets(
    *,
    actor: ResourceAuthContext,
    within_seconds: int = 86400,
) -> list[dict[str, Any]]:
    """Get secrets expiring within a time window."""
    now = time.time()
    threshold = now + within_seconds
    results: list[dict[str, Any]] = []

    context = require_resource_actor(actor)
    with _lock:
        for secret in _secrets.values():
            if not _actor_owns_secret(context, secret):
                continue
            if secret["status"] != ROTATION_ACTIVE:
                continue
            if secret["expires_at"] <= threshold:
                results.append({
                    **_sanitize(secret),
                    "expires_in_seconds": round(max(0, secret["expires_at"] - now)),
                })

    results.sort(key=lambda x: x["expires_in_seconds"])
    return results


def get_rotation_due(*, actor: ResourceAuthContext) -> list[dict[str, Any]]:
    """Get secrets that are due for rotation."""
    now = time.time()
    results: list[dict[str, Any]] = []

    context = require_resource_actor(actor)
    with _lock:
        for secret in _secrets.values():
            if not _actor_owns_secret(context, secret):
                continue
            if secret["status"] != ROTATION_ACTIVE:
                continue
            if secret.get("next_rotation_at") and secret["next_rotation_at"] <= now:
                results.append({
                    **_sanitize(secret),
                    "overdue_seconds": round(now - secret["next_rotation_at"]),
                })

    results.sort(key=lambda x: x["overdue_seconds"], reverse=True)
    return results


# ── Internal helpers ─────────────────────────────────────────────────

def _hash_value(value: str) -> str:
    """Hash a secret value for storage."""
    return hmac.new(
        _vault_key().encode(), value.encode(), hashlib.sha256
    ).hexdigest()


def _sanitize(secret: dict[str, Any]) -> dict[str, Any]:
    """Return secret without the hash."""
    result = dict(secret)
    result.pop("value_hash", None)
    return result


def _actor_owns_secret(actor: ResourceAuthContext, secret: dict[str, Any]) -> bool:
    if secret.get("owner") != actor.owner or secret.get("tenant_id") != actor.tenant_id:
        return False
    return actor.agent_id is None or secret.get("agent_id") == actor.agent_id


def _get_authorized_secret_locked(
    secret_id: str,
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    secret = _secrets.get(secret_id)
    if secret is None or not _actor_owns_secret(actor, secret):
        # Missing and unauthorized objects deliberately share one response path.
        raise KeyError(f"secret not found: {secret_id}")
    return secret


def reset_for_tests() -> None:
    """Clear all vault data for testing."""
    with _lock:
        _secrets.clear()
        _rotation_history.clear()
