"""Token Scope Narrowing (S157).

Runtime scope reduction for delegation tokens — agents request narrower
scopes from their current grants without re-authentication.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.scope_narrowing")

_MAX_RECORDS = 10_000
_narrowed_tokens: dict[str, dict[str, Any]] = {}  # token_id -> narrowed token
_narrowing_log: list[dict[str, Any]] = []


def narrow_scope(
    *,
    parent_token_id: str,
    parent_scopes: list[str],
    requested_scopes: list[str],
    agent_id: str,
    ttl_seconds: int = 3600,
    reason: str = "",
) -> dict[str, Any]:
    """Create a narrowed token with a subset of parent scopes."""
    parent_set = set(parent_scopes)
    requested_set = set(requested_scopes)

    if not requested_set:
        raise ValueError("requested_scopes must not be empty")

    # Check that requested scopes are a subset of parent
    if not _is_subset(requested_set, parent_set):
        extra = requested_set - parent_set
        raise ValueError(f"scope escalation denied: {sorted(extra)} not in parent scopes")

    token_id = f"nt-{uuid.uuid4().hex[:12]}"
    now = time.time()

    token: dict[str, Any] = {
        "token_id": token_id,
        "parent_token_id": parent_token_id,
        "agent_id": agent_id,
        "original_scopes": sorted(parent_scopes),
        "narrowed_scopes": sorted(requested_scopes),
        "scopes_removed": sorted(parent_set - requested_set),
        "reason": reason,
        "ttl_seconds": ttl_seconds,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "active": True,
    }

    _narrowed_tokens[token_id] = token

    _narrowing_log.append({
        "token_id": token_id,
        "parent_token_id": parent_token_id,
        "agent_id": agent_id,
        "action": "narrow",
        "from_scopes": sorted(parent_scopes),
        "to_scopes": sorted(requested_scopes),
        "timestamp": now,
    })

    if len(_narrowed_tokens) > _MAX_RECORDS:
        oldest = sorted(_narrowed_tokens, key=lambda k: _narrowed_tokens[k]["issued_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _narrowed_tokens[k]

    if len(_narrowing_log) > _MAX_RECORDS:
        _narrowing_log[:] = _narrowing_log[-_MAX_RECORDS:]

    return token


def get_narrowed_token(token_id: str) -> dict[str, Any]:
    """Get a narrowed token by ID."""
    token = _narrowed_tokens.get(token_id)
    if not token:
        raise KeyError(f"narrowed token not found: {token_id}")
    return token


def list_narrowed_tokens(
    *,
    agent_id: str | None = None,
    parent_token_id: str | None = None,
    active_only: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List narrowed tokens with optional filters."""
    now = time.time()
    results: list[dict[str, Any]] = []
    for t in sorted(_narrowed_tokens.values(), key=lambda x: x["issued_at"], reverse=True):
        if agent_id and t["agent_id"] != agent_id:
            continue
        if parent_token_id and t["parent_token_id"] != parent_token_id:
            continue
        if active_only and (not t["active"] or t["expires_at"] < now):
            continue
        results.append(t)
        if len(results) >= limit:
            break
    return results


def validate_narrowed_token(token_id: str) -> dict[str, Any]:
    """Validate a narrowed token is still active and not expired."""
    token = _narrowed_tokens.get(token_id)
    if not token:
        return {"valid": False, "reason": "not_found"}

    now = time.time()
    if not token["active"]:
        return {"valid": False, "reason": "revoked", "token_id": token_id}

    if token["expires_at"] < now:
        return {"valid": False, "reason": "expired", "token_id": token_id, "expired_at": token["expires_at"]}

    return {
        "valid": True,
        "token_id": token_id,
        "agent_id": token["agent_id"],
        "scopes": token["narrowed_scopes"],
        "expires_in": token["expires_at"] - now,
    }


def revoke_narrowed_token(token_id: str) -> dict[str, Any]:
    """Revoke a narrowed token."""
    token = _narrowed_tokens.get(token_id)
    if not token:
        raise KeyError(f"narrowed token not found: {token_id}")

    token["active"] = False
    token["revoked_at"] = time.time()

    _narrowing_log.append({
        "token_id": token_id,
        "parent_token_id": token["parent_token_id"],
        "agent_id": token["agent_id"],
        "action": "revoke",
        "timestamp": time.time(),
    })

    return token


def get_narrowing_log(
    *,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get scope narrowing history."""
    results: list[dict[str, Any]] = []
    for entry in reversed(_narrowing_log):
        if agent_id and entry["agent_id"] != agent_id:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def get_narrowing_stats() -> dict[str, Any]:
    """Get scope narrowing statistics."""
    now = time.time()
    total = len(_narrowed_tokens)
    active = sum(1 for t in _narrowed_tokens.values() if t["active"] and t["expires_at"] > now)
    expired = sum(1 for t in _narrowed_tokens.values() if t["expires_at"] < now)
    revoked = sum(1 for t in _narrowed_tokens.values() if not t["active"])

    return {
        "total_narrowed_tokens": total,
        "active_tokens": active,
        "expired_tokens": expired,
        "revoked_tokens": revoked,
        "total_narrowing_events": len(_narrowing_log),
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _is_subset(requested: set[str], parent: set[str]) -> bool:
    """Check if requested scopes are a subset, supporting wildcard."""
    if "*" in parent:
        return True
    return requested.issubset(parent)


def reset_for_tests() -> None:
    """Clear all scope narrowing data for testing."""
    _narrowed_tokens.clear()
    _narrowing_log.clear()
