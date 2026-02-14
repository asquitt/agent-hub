"""Rate Limit Policies — per-agent configurable rate limiting.

Provides:
- Define rate limit policies per agent (requests/minute, tokens/hour, etc.)
- Sliding window counter tracking
- Rate limit check (allow/deny with remaining quota)
- Override policies for burst scenarios
- Usage analytics
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.rate_policies")

_MAX_RECORDS = 10_000
_policies: dict[str, dict[str, Any]] = {}  # policy_id -> policy
_counters: dict[str, list[float]] = {}  # "agent_id:resource" -> list of timestamps
_violations: list[dict[str, Any]] = []


def create_policy(
    *,
    agent_id: str,
    resource: str = "api",
    max_requests: int,
    window_seconds: int = 60,
    burst_allowance: int = 0,
    action: str = "deny",
) -> dict[str, Any]:
    """Create a rate limit policy for an agent."""
    if max_requests < 1:
        raise ValueError("max_requests must be at least 1")
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")
    if action not in {"deny", "throttle", "log"}:
        raise ValueError(f"invalid action: {action}")

    policy_id = f"rlp-{uuid.uuid4().hex[:12]}"
    now = time.time()

    policy: dict[str, Any] = {
        "policy_id": policy_id,
        "agent_id": agent_id,
        "resource": resource,
        "max_requests": max_requests,
        "window_seconds": window_seconds,
        "burst_allowance": burst_allowance,
        "action": action,
        "enabled": True,
        "created_at": now,
    }

    _policies[policy_id] = policy
    if len(_policies) > _MAX_RECORDS:
        oldest = sorted(_policies, key=lambda k: _policies[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _policies[k]

    return policy


def get_policy(policy_id: str) -> dict[str, Any]:
    """Get rate limit policy details."""
    policy = _policies.get(policy_id)
    if not policy:
        raise KeyError(f"policy not found: {policy_id}")
    return policy


def list_policies(
    *,
    agent_id: str | None = None,
    resource: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List rate limit policies."""
    results: list[dict[str, Any]] = []
    for p in _policies.values():
        if agent_id and p["agent_id"] != agent_id:
            continue
        if resource and p["resource"] != resource:
            continue
        results.append(p)
        if len(results) >= limit:
            break
    return results


def update_policy(
    policy_id: str,
    *,
    max_requests: int | None = None,
    window_seconds: int | None = None,
    burst_allowance: int | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Update a rate limit policy."""
    policy = _policies.get(policy_id)
    if not policy:
        raise KeyError(f"policy not found: {policy_id}")

    if max_requests is not None:
        policy["max_requests"] = max_requests
    if window_seconds is not None:
        policy["window_seconds"] = window_seconds
    if burst_allowance is not None:
        policy["burst_allowance"] = burst_allowance
    if enabled is not None:
        policy["enabled"] = enabled

    return policy


def check_rate_limit(
    agent_id: str,
    resource: str = "api",
) -> dict[str, Any]:
    """Check if an agent is within rate limits. Records the request."""
    now = time.time()

    # Find applicable policies
    applicable: list[dict[str, Any]] = []
    for p in _policies.values():
        if p["agent_id"] == agent_id and p["resource"] == resource and p["enabled"]:
            applicable.append(p)

    if not applicable:
        return {
            "allowed": True,
            "agent_id": agent_id,
            "resource": resource,
            "reason": "no_policy",
        }

    counter_key = f"{agent_id}:{resource}"
    timestamps = _counters.get(counter_key, [])

    # Check each policy
    for policy in applicable:
        window_start = now - policy["window_seconds"]
        recent = [t for t in timestamps if t > window_start]
        effective_limit = policy["max_requests"] + policy["burst_allowance"]

        if len(recent) >= effective_limit:
            violation: dict[str, Any] = {
                "agent_id": agent_id,
                "resource": resource,
                "policy_id": policy["policy_id"],
                "action": policy["action"],
                "count": len(recent),
                "limit": effective_limit,
                "timestamp": now,
            }
            _violations.append(violation)
            if len(_violations) > _MAX_RECORDS:
                _violations[:] = _violations[-_MAX_RECORDS:]

            return {
                "allowed": policy["action"] == "log",
                "agent_id": agent_id,
                "resource": resource,
                "policy_id": policy["policy_id"],
                "action": policy["action"],
                "current_count": len(recent),
                "limit": effective_limit,
                "remaining": 0,
                "retry_after_seconds": policy["window_seconds"],
            }

    # All policies passed — record the request
    timestamps.append(now)
    # Trim old timestamps
    min_window = min(p["window_seconds"] for p in applicable)
    cutoff = now - min_window * 2
    timestamps = [t for t in timestamps if t > cutoff]
    _counters[counter_key] = timestamps

    # Report remaining from most restrictive policy
    most_restrictive = min(applicable, key=lambda p: p["max_requests"] + p["burst_allowance"])
    window_start = now - most_restrictive["window_seconds"]
    recent_count = sum(1 for t in timestamps if t > window_start)
    effective_limit = most_restrictive["max_requests"] + most_restrictive["burst_allowance"]

    return {
        "allowed": True,
        "agent_id": agent_id,
        "resource": resource,
        "current_count": recent_count,
        "limit": effective_limit,
        "remaining": max(0, effective_limit - recent_count),
    }


def get_violations(
    *,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get rate limit violations."""
    results: list[dict[str, Any]] = []
    for v in reversed(_violations):
        if agent_id and v["agent_id"] != agent_id:
            continue
        results.append(v)
        if len(results) >= limit:
            break
    return results


def get_rate_stats() -> dict[str, Any]:
    """Get rate limiting statistics."""
    return {
        "total_policies": len(_policies),
        "enabled_policies": sum(1 for p in _policies.values() if p["enabled"]),
        "active_counters": len(_counters),
        "total_violations": len(_violations),
    }


def reset_for_tests() -> None:
    """Clear all rate policy data for testing."""
    _policies.clear()
    _counters.clear()
    _violations.clear()
