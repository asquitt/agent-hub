"""Session-Based Ephemeral Access Grants — time-bound, scoped access tokens.

Implements per-session or per-action temporary access that auto-expires:
- Create session grants with TTL and scope restrictions
- Consume grants (single-use or multi-use within TTL)
- Revoke active grants
- Track grant usage with audit trail
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.session_grants")

# Grant states
GRANT_ACTIVE = "active"
GRANT_CONSUMED = "consumed"
GRANT_EXPIRED = "expired"
GRANT_REVOKED = "revoked"

# Grant types
TYPE_SINGLE_USE = "single_use"
TYPE_SESSION = "session"
TYPE_TIME_BOUND = "time_bound"

VALID_GRANT_TYPES = {TYPE_SINGLE_USE, TYPE_SESSION, TYPE_TIME_BOUND}

# In-memory stores
_MAX_RECORDS = 10_000
_grants: dict[str, dict[str, Any]] = {}  # grant_id -> grant
_grant_usage: list[dict[str, Any]] = []  # usage audit log


def create_grant(
    *,
    agent_id: str,
    scopes: list[str],
    grant_type: str = TYPE_TIME_BOUND,
    ttl_seconds: int = 300,
    max_uses: int | None = None,
    resource: str | None = None,
    context: str = "",
    granted_by: str = "system",
) -> dict[str, Any]:
    """Create an ephemeral access grant."""
    if grant_type not in VALID_GRANT_TYPES:
        raise ValueError(f"invalid grant type: {grant_type}")
    if ttl_seconds < 10 or ttl_seconds > 86400:
        raise ValueError("ttl_seconds must be between 10 and 86400")
    if not scopes:
        raise ValueError("at least one scope required")

    grant_id = f"grant-{uuid.uuid4().hex[:12]}"
    now = time.time()

    if grant_type == TYPE_SINGLE_USE:
        max_uses = 1

    grant: dict[str, Any] = {
        "grant_id": grant_id,
        "agent_id": agent_id,
        "scopes": sorted(scopes),
        "grant_type": grant_type,
        "status": GRANT_ACTIVE,
        "resource": resource,
        "context": context,
        "granted_by": granted_by,
        "max_uses": max_uses,
        "use_count": 0,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "last_used_at": None,
    }

    _grants[grant_id] = grant
    if len(_grants) > _MAX_RECORDS:
        oldest = sorted(_grants, key=lambda k: _grants[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _grants[k]

    _log.info(
        "grant created: %s agent=%s type=%s ttl=%ds scopes=%s",
        grant_id, agent_id, grant_type, ttl_seconds, scopes,
    )
    return grant


def consume_grant(
    *,
    grant_id: str,
    action: str = "",
    resource: str | None = None,
) -> dict[str, Any]:
    """Consume a grant (use it). Returns consumption result."""
    grant = _grants.get(grant_id)
    if grant is None:
        raise KeyError(f"grant not found: {grant_id}")

    now = time.time()

    # Auto-expire
    if grant["status"] == GRANT_ACTIVE and now > grant["expires_at"]:
        grant["status"] = GRANT_EXPIRED

    if grant["status"] != GRANT_ACTIVE:
        return {
            "consumed": False,
            "grant_id": grant_id,
            "reason": f"grant is {grant['status']}",
        }

    # Check resource restriction
    if grant.get("resource") and resource and grant["resource"] != resource:
        return {
            "consumed": False,
            "grant_id": grant_id,
            "reason": f"resource mismatch: grant restricts to {grant['resource']}",
        }

    # Record usage
    grant["use_count"] += 1
    grant["last_used_at"] = now

    usage_entry: dict[str, Any] = {
        "grant_id": grant_id,
        "agent_id": grant["agent_id"],
        "action": action,
        "resource": resource,
        "use_number": grant["use_count"],
        "timestamp": now,
    }
    _grant_usage.append(usage_entry)
    if len(_grant_usage) > _MAX_RECORDS:
        _grant_usage[:] = _grant_usage[-_MAX_RECORDS:]

    # Check if consumed (single-use or max uses reached)
    if grant["max_uses"] is not None and grant["use_count"] >= grant["max_uses"]:
        grant["status"] = GRANT_CONSUMED

    return {
        "consumed": True,
        "grant_id": grant_id,
        "scopes": grant["scopes"],
        "use_count": grant["use_count"],
        "remaining_uses": (
            grant["max_uses"] - grant["use_count"]
            if grant["max_uses"] is not None
            else None
        ),
        "expires_at": grant["expires_at"],
    }


def check_grant(
    *,
    agent_id: str,
    scope: str,
    resource: str | None = None,
) -> dict[str, Any]:
    """Check if an agent has an active grant for a scope."""
    now = time.time()
    for grant in _grants.values():
        if grant["agent_id"] != agent_id:
            continue

        # Auto-expire
        if grant["status"] == GRANT_ACTIVE and now > grant["expires_at"]:
            grant["status"] = GRANT_EXPIRED

        if grant["status"] != GRANT_ACTIVE:
            continue

        if scope not in grant["scopes"] and "*" not in grant["scopes"]:
            continue

        if grant.get("resource") and resource and grant["resource"] != resource:
            continue

        return {
            "has_grant": True,
            "grant_id": grant["grant_id"],
            "scopes": grant["scopes"],
            "expires_at": grant["expires_at"],
            "remaining_seconds": round(grant["expires_at"] - now, 1),
        }

    return {
        "has_grant": False,
        "agent_id": agent_id,
        "scope": scope,
    }


def revoke_grant(grant_id: str, *, reason: str = "manual") -> dict[str, Any]:
    """Revoke an active grant."""
    grant = _grants.get(grant_id)
    if grant is None:
        raise KeyError(f"grant not found: {grant_id}")

    if grant["status"] != GRANT_ACTIVE:
        raise ValueError(f"grant is already {grant['status']}")

    grant["status"] = GRANT_REVOKED
    grant["revoked_at"] = time.time()
    grant["revoke_reason"] = reason

    _log.info("grant revoked: %s reason=%s", grant_id, reason)
    return grant


def get_grant(grant_id: str) -> dict[str, Any]:
    """Get a grant by ID."""
    grant = _grants.get(grant_id)
    if grant is None:
        raise KeyError(f"grant not found: {grant_id}")

    # Auto-expire
    if grant["status"] == GRANT_ACTIVE and time.time() > grant["expires_at"]:
        grant["status"] = GRANT_EXPIRED

    return grant


def list_grants(
    *,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List grants with optional filters."""
    now = time.time()
    results: list[dict[str, Any]] = []
    for g in _grants.values():
        # Auto-expire
        if g["status"] == GRANT_ACTIVE and now > g["expires_at"]:
            g["status"] = GRANT_EXPIRED

        if agent_id and g["agent_id"] != agent_id:
            continue
        if status and g["status"] != status:
            continue

        results.append({
            "grant_id": g["grant_id"],
            "agent_id": g["agent_id"],
            "scopes": g["scopes"],
            "grant_type": g["grant_type"],
            "status": g["status"],
            "use_count": g["use_count"],
            "max_uses": g["max_uses"],
            "created_at": g["created_at"],
            "expires_at": g["expires_at"],
        })
        if len(results) >= limit:
            break
    return results


def get_grant_usage(
    grant_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get grant usage audit trail."""
    results: list[dict[str, Any]] = []
    for entry in reversed(_grant_usage):
        if grant_id and entry["grant_id"] != grant_id:
            continue
        if agent_id and entry["agent_id"] != agent_id:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def reset_for_tests() -> None:
    """Clear all grant data for testing."""
    _grants.clear()
    _grant_usage.clear()
