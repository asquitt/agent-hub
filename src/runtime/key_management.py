"""Agent Key Management — API key lifecycle with rotation and usage tracking.

Provides:
- Create API keys bound to agents with scopes and TTL
- Rotate keys (old key invalidated, new key issued)
- Revoke keys immediately
- Track key usage (last used, access count)
- Key expiry enforcement
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.key_management")

# In-memory stores
_MAX_RECORDS = 10_000
_keys: dict[str, dict[str, Any]] = {}  # key_id -> key record
_usage_log: list[dict[str, Any]] = []

# Key statuses
STATUS_ACTIVE = "active"
STATUS_ROTATED = "rotated"
STATUS_REVOKED = "revoked"
STATUS_EXPIRED = "expired"


def _hash_key(raw_key: str) -> str:
    """Hash a raw API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def create_key(
    *,
    agent_id: str,
    name: str = "",
    scopes: list[str] | None = None,
    ttl_seconds: int | None = None,
    created_by: str = "system",
) -> dict[str, Any]:
    """Create a new API key for an agent."""
    key_id = f"key-{uuid.uuid4().hex[:12]}"
    raw_key = f"ahk_{secrets.token_urlsafe(32)}"
    now = time.time()
    expires_at = now + ttl_seconds if ttl_seconds else None

    record: dict[str, Any] = {
        "key_id": key_id,
        "agent_id": agent_id,
        "name": name,
        "key_hash": _hash_key(raw_key),
        "key_prefix": raw_key[:8],
        "scopes": scopes or ["*"],
        "status": STATUS_ACTIVE,
        "created_at": now,
        "created_by": created_by,
        "expires_at": expires_at,
        "last_used_at": None,
        "use_count": 0,
        "rotated_from": None,
    }

    _keys[key_id] = record
    if len(_keys) > _MAX_RECORDS:
        oldest = sorted(_keys, key=lambda k: _keys[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _keys[k]

    # Return the raw key only on creation
    return {
        "key_id": key_id,
        "agent_id": agent_id,
        "name": name,
        "key_prefix": raw_key[:8],
        "raw_key": raw_key,
        "scopes": record["scopes"],
        "status": STATUS_ACTIVE,
        "created_at": now,
        "expires_at": expires_at,
    }


def get_key(key_id: str) -> dict[str, Any]:
    """Get key details (without raw key or hash)."""
    record = _keys.get(key_id)
    if not record:
        raise KeyError(f"key not found: {key_id}")
    _check_expiry(record)
    return _sanitize(record)


def list_keys(
    *,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List API keys."""
    results: list[dict[str, Any]] = []
    for record in _keys.values():
        _check_expiry(record)
        if agent_id and record["agent_id"] != agent_id:
            continue
        if status and record["status"] != status:
            continue
        results.append(_sanitize(record))
        if len(results) >= limit:
            break
    return results


def rotate_key(key_id: str) -> dict[str, Any]:
    """Rotate a key: invalidate old, issue new with same config."""
    record = _keys.get(key_id)
    if not record:
        raise KeyError(f"key not found: {key_id}")
    if record["status"] != STATUS_ACTIVE:
        raise ValueError(f"can only rotate active keys, current status: {record['status']}")

    # Invalidate old key
    record["status"] = STATUS_ROTATED
    record["rotated_at"] = time.time()

    # Create new key with same config
    result = create_key(
        agent_id=record["agent_id"],
        name=record["name"],
        scopes=record["scopes"],
        ttl_seconds=int(record["expires_at"] - time.time()) if record["expires_at"] else None,
        created_by=record["created_by"],
    )
    new_key_id = result["key_id"]
    _keys[new_key_id]["rotated_from"] = key_id

    return {
        "old_key_id": key_id,
        "new_key_id": new_key_id,
        "raw_key": result["raw_key"],
        "key_prefix": result["key_prefix"],
        "rotated_at": record["rotated_at"],
    }


def revoke_key(key_id: str, *, reason: str = "manual") -> dict[str, Any]:
    """Revoke a key immediately."""
    record = _keys.get(key_id)
    if not record:
        raise KeyError(f"key not found: {key_id}")

    record["status"] = STATUS_REVOKED
    record["revoked_at"] = time.time()
    record["revoke_reason"] = reason

    return _sanitize(record)


def record_usage(key_id: str) -> dict[str, Any]:
    """Record that a key was used (for tracking)."""
    record = _keys.get(key_id)
    if not record:
        raise KeyError(f"key not found: {key_id}")

    _check_expiry(record)
    if record["status"] != STATUS_ACTIVE:
        raise ValueError(f"key is not active: {record['status']}")

    now = time.time()
    record["last_used_at"] = now
    record["use_count"] += 1

    entry: dict[str, Any] = {
        "key_id": key_id,
        "agent_id": record["agent_id"],
        "timestamp": now,
        "use_count": record["use_count"],
    }
    _usage_log.append(entry)
    if len(_usage_log) > _MAX_RECORDS:
        _usage_log[:] = _usage_log[-_MAX_RECORDS:]

    return _sanitize(record)


def get_usage_log(
    *,
    key_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get key usage log."""
    results: list[dict[str, Any]] = []
    for entry in reversed(_usage_log):
        if key_id and entry["key_id"] != key_id:
            continue
        if agent_id and entry["agent_id"] != agent_id:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def get_key_stats() -> dict[str, Any]:
    """Get key management statistics."""
    total = len(_keys)
    active = sum(1 for k in _keys.values() if k["status"] == STATUS_ACTIVE)
    revoked = sum(1 for k in _keys.values() if k["status"] == STATUS_REVOKED)
    expired = sum(1 for k in _keys.values() if k["status"] == STATUS_EXPIRED)

    return {
        "total_keys": total,
        "active_keys": active,
        "revoked_keys": revoked,
        "expired_keys": expired,
        "total_usages": len(_usage_log),
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _check_expiry(record: dict[str, Any]) -> None:
    """Auto-expire keys past TTL."""
    if (record["status"] == STATUS_ACTIVE
            and record.get("expires_at")
            and record["expires_at"] < time.time()):
        record["status"] = STATUS_EXPIRED


def _sanitize(record: dict[str, Any]) -> dict[str, Any]:
    """Return key record without sensitive fields."""
    return {
        "key_id": record["key_id"],
        "agent_id": record["agent_id"],
        "name": record["name"],
        "key_prefix": record["key_prefix"],
        "scopes": record["scopes"],
        "status": record["status"],
        "created_at": record["created_at"],
        "created_by": record["created_by"],
        "expires_at": record.get("expires_at"),
        "last_used_at": record.get("last_used_at"),
        "use_count": record["use_count"],
        "rotated_from": record.get("rotated_from"),
    }


def reset_for_tests() -> None:
    """Clear all key management data for testing."""
    _keys.clear()
    _usage_log.clear()
