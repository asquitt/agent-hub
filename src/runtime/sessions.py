"""Agent Session Management — concurrent session limits and forced logout.

Provides:
- Create/destroy agent sessions with TTL
- Concurrent session limits per agent
- Forced logout (terminate all sessions)
- Session activity tracking
- Session policy enforcement
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.sessions")

# Session status
STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_TERMINATED = "terminated"

# In-memory stores
_MAX_RECORDS = 10_000
_sessions: dict[str, dict[str, Any]] = {}  # session_id -> session
_policies: dict[str, dict[str, Any]] = {}  # agent_id -> policy

# Default limits
DEFAULT_MAX_CONCURRENT = 5
DEFAULT_SESSION_TTL = 3600  # 1 hour


def create_session(
    *,
    agent_id: str,
    ttl_seconds: int = DEFAULT_SESSION_TTL,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> dict[str, Any]:
    """Create a new session for an agent."""
    if ttl_seconds < 60 or ttl_seconds > 86400:
        raise ValueError("ttl must be between 60 seconds and 24 hours")

    # Check concurrent session limit
    policy = _policies.get(agent_id, {})
    max_concurrent = policy.get("max_concurrent", DEFAULT_MAX_CONCURRENT)

    active = _get_active_sessions(agent_id)
    if len(active) >= max_concurrent:
        raise ValueError(
            f"concurrent session limit ({max_concurrent}) reached for {agent_id}"
        )

    now = time.time()
    session_id = f"sess-{uuid.uuid4().hex[:12]}"

    session: dict[str, Any] = {
        "session_id": session_id,
        "agent_id": agent_id,
        "status": STATUS_ACTIVE,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "last_activity": now,
        "ip_address": ip_address,
        "metadata": metadata or {},
        "activity_count": 0,
    }

    _sessions[session_id] = session
    if len(_sessions) > _MAX_RECORDS:
        oldest = sorted(_sessions, key=lambda k: _sessions[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _sessions[k]

    _log.info("session created: agent=%s session=%s", agent_id, session_id)
    return session


def get_session(session_id: str) -> dict[str, Any]:
    """Get session details."""
    session = _sessions.get(session_id)
    if not session:
        raise KeyError(f"session not found: {session_id}")

    # Auto-expire
    if session["status"] == STATUS_ACTIVE and time.time() > session["expires_at"]:
        session["status"] = STATUS_EXPIRED

    return session


def list_sessions(
    *,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List sessions with filters."""
    results: list[dict[str, Any]] = []
    for s in _sessions.values():
        # Auto-expire
        if s["status"] == STATUS_ACTIVE and time.time() > s["expires_at"]:
            s["status"] = STATUS_EXPIRED

        if agent_id and s["agent_id"] != agent_id:
            continue
        if status and s["status"] != status:
            continue
        results.append(s)
        if len(results) >= limit:
            break
    return results


def touch_session(session_id: str) -> dict[str, Any]:
    """Record activity on a session (heartbeat)."""
    session = _sessions.get(session_id)
    if not session:
        raise KeyError(f"session not found: {session_id}")

    if session["status"] != STATUS_ACTIVE:
        raise ValueError(f"session is {session['status']}")

    if time.time() > session["expires_at"]:
        session["status"] = STATUS_EXPIRED
        raise ValueError("session expired")

    session["last_activity"] = time.time()
    session["activity_count"] += 1
    return session


def terminate_session(session_id: str, *, reason: str = "") -> dict[str, Any]:
    """Terminate a specific session."""
    session = _sessions.get(session_id)
    if not session:
        raise KeyError(f"session not found: {session_id}")

    session["status"] = STATUS_TERMINATED
    session["terminated_at"] = time.time()
    session["termination_reason"] = reason

    _log.info("session terminated: %s reason=%s", session_id, reason)
    return session


def force_logout(agent_id: str, *, reason: str = "forced_logout") -> dict[str, Any]:
    """Terminate all active sessions for an agent."""
    terminated = 0
    for session in _sessions.values():
        if session["agent_id"] == agent_id and session["status"] == STATUS_ACTIVE:
            session["status"] = STATUS_TERMINATED
            session["terminated_at"] = time.time()
            session["termination_reason"] = reason
            terminated += 1

    _log.warning("force logout: agent=%s terminated=%d", agent_id, terminated)
    return {"agent_id": agent_id, "terminated": terminated, "reason": reason}


def set_session_policy(
    *,
    agent_id: str,
    max_concurrent: int | None = None,
    default_ttl: int | None = None,
    allowed_ips: list[str] | None = None,
) -> dict[str, Any]:
    """Set session policy for an agent."""
    policy = _policies.get(agent_id, {
        "agent_id": agent_id,
        "max_concurrent": DEFAULT_MAX_CONCURRENT,
        "default_ttl": DEFAULT_SESSION_TTL,
        "allowed_ips": None,
        "created_at": time.time(),
    })

    if max_concurrent is not None:
        if max_concurrent < 1 or max_concurrent > 100:
            raise ValueError("max_concurrent must be 1-100")
        policy["max_concurrent"] = max_concurrent
    if default_ttl is not None:
        if default_ttl < 60 or default_ttl > 86400:
            raise ValueError("default_ttl must be 60-86400")
        policy["default_ttl"] = default_ttl
    if allowed_ips is not None:
        policy["allowed_ips"] = allowed_ips

    policy["updated_at"] = time.time()
    _policies[agent_id] = policy

    if len(_policies) > _MAX_RECORDS:
        oldest = sorted(_policies, key=lambda k: _policies[k].get("created_at", 0))
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _policies[k]

    return policy


def get_session_policy(agent_id: str) -> dict[str, Any]:
    """Get session policy for an agent."""
    return _policies.get(agent_id, {
        "agent_id": agent_id,
        "max_concurrent": DEFAULT_MAX_CONCURRENT,
        "default_ttl": DEFAULT_SESSION_TTL,
        "allowed_ips": None,
    })


def get_session_stats(agent_id: str | None = None) -> dict[str, Any]:
    """Get session statistics."""
    sessions = list(_sessions.values())

    # Auto-expire
    for s in sessions:
        if s["status"] == STATUS_ACTIVE and time.time() > s["expires_at"]:
            s["status"] = STATUS_EXPIRED

    if agent_id:
        sessions = [s for s in sessions if s["agent_id"] == agent_id]

    active = sum(1 for s in sessions if s["status"] == STATUS_ACTIVE)
    expired = sum(1 for s in sessions if s["status"] == STATUS_EXPIRED)
    terminated = sum(1 for s in sessions if s["status"] == STATUS_TERMINATED)

    return {
        "total_sessions": len(sessions),
        "active": active,
        "expired": expired,
        "terminated": terminated,
        "agent_id": agent_id,
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _get_active_sessions(agent_id: str) -> list[dict[str, Any]]:
    """Get active (non-expired) sessions for an agent."""
    now = time.time()
    active: list[dict[str, Any]] = []
    for s in _sessions.values():
        if s["agent_id"] != agent_id:
            continue
        if s["status"] == STATUS_ACTIVE and now <= s["expires_at"]:
            active.append(s)
        elif s["status"] == STATUS_ACTIVE and now > s["expires_at"]:
            s["status"] = STATUS_EXPIRED
    return active


def reset_for_tests() -> None:
    """Clear all session data for testing."""
    _sessions.clear()
    _policies.clear()
