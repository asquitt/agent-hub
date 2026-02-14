"""Agent Capability Quotas (S159).

Enforce per-agent limits on API calls, resources, delegation depth,
and other capabilities with quota tracking and enforcement.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.capability_quotas")

_MAX_RECORDS = 10_000
_quotas: dict[str, dict[str, Any]] = {}  # quota_id -> quota
_usage: dict[str, dict[str, Any]] = {}  # "{agent_id}:{resource}:{quota_id}" -> {"used": n, "window_start": t}
_violations: list[dict[str, Any]] = []

VALID_RESOURCES = (
    "api_calls", "delegations", "sandboxes", "credentials",
    "keys", "sessions", "storage_mb", "custom",
)


def create_quota(
    *,
    agent_id: str,
    resource: str,
    max_value: int,
    period_seconds: int = 0,
    description: str = "",
) -> dict[str, Any]:
    """Create a capability quota for an agent."""
    if resource not in VALID_RESOURCES:
        raise ValueError(f"resource must be one of {VALID_RESOURCES}")
    if max_value <= 0:
        raise ValueError("max_value must be positive")

    qid = f"quota-{uuid.uuid4().hex[:12]}"
    now = time.time()

    quota: dict[str, Any] = {
        "quota_id": qid,
        "agent_id": agent_id,
        "resource": resource,
        "max_value": max_value,
        "period_seconds": period_seconds,
        "description": description,
        "enabled": True,
        "created_at": now,
    }
    _quotas[qid] = quota

    if len(_quotas) > _MAX_RECORDS:
        oldest = sorted(_quotas, key=lambda k: _quotas[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _quotas[k]

    return quota


def get_quota(quota_id: str) -> dict[str, Any]:
    """Get a quota by ID."""
    q = _quotas.get(quota_id)
    if not q:
        raise KeyError(f"quota not found: {quota_id}")
    return q


def list_quotas(
    *,
    agent_id: str | None = None,
    resource: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List quotas with optional filters."""
    results: list[dict[str, Any]] = []
    for q in sorted(_quotas.values(), key=lambda x: x["created_at"], reverse=True):
        if agent_id and q["agent_id"] != agent_id:
            continue
        if resource and q["resource"] != resource:
            continue
        results.append(q)
        if len(results) >= limit:
            break
    return results


def check_quota(
    *,
    agent_id: str,
    resource: str,
    amount: int = 1,
) -> dict[str, Any]:
    """Check if an agent has quota remaining and consume it."""
    agent_quotas = [
        q for q in _quotas.values()
        if q["agent_id"] == agent_id and q["resource"] == resource and q["enabled"]
    ]

    if not agent_quotas:
        return {
            "allowed": True,
            "reason": "no_quota",
            "agent_id": agent_id,
            "resource": resource,
        }

    # Use the most restrictive quota
    for quota in agent_quotas:
        key = f"{agent_id}:{resource}:{quota['quota_id']}"
        current = _usage.get(key, {"used": 0, "window_start": time.time()})

        # Reset window if period-based quota expired
        if quota["period_seconds"] > 0:
            elapsed = time.time() - current.get("window_start", time.time())
            if elapsed > quota["period_seconds"]:
                current = {"used": 0, "window_start": time.time()}

        if current["used"] + amount > quota["max_value"]:
            violation: dict[str, Any] = {
                "agent_id": agent_id,
                "resource": resource,
                "quota_id": quota["quota_id"],
                "used": current["used"],
                "max_value": quota["max_value"],
                "requested": amount,
                "timestamp": time.time(),
            }
            _violations.append(violation)
            if len(_violations) > _MAX_RECORDS:
                _violations[:] = _violations[-_MAX_RECORDS:]

            return {
                "allowed": False,
                "reason": "quota_exceeded",
                "agent_id": agent_id,
                "resource": resource,
                "quota_id": quota["quota_id"],
                "used": current["used"],
                "max_value": quota["max_value"],
                "remaining": quota["max_value"] - current["used"],
            }

        # Consume quota
        current["used"] += amount
        _usage[key] = current

    # Get final usage for response
    remaining = 0
    max_val = 0
    used = 0
    for quota in agent_quotas:
        key = f"{agent_id}:{resource}:{quota['quota_id']}"
        u = _usage.get(key, {"used": 0})
        used = u["used"]
        max_val = quota["max_value"]
        remaining = max_val - used

    return {
        "allowed": True,
        "agent_id": agent_id,
        "resource": resource,
        "used": used,
        "max_value": max_val,
        "remaining": remaining,
    }


def get_usage(
    *,
    agent_id: str,
    resource: str | None = None,
) -> dict[str, Any]:
    """Get current usage for an agent."""
    usage_data: list[dict[str, Any]] = []
    for key, val in _usage.items():
        parts = key.split(":", 2)
        if len(parts) < 3:
            continue
        a_id, res, q_id = parts[0], parts[1], parts[2]
        if a_id != agent_id:
            continue
        if resource and res != resource:
            continue
        quota = _quotas.get(q_id)
        usage_data.append({
            "resource": res,
            "quota_id": q_id,
            "used": val["used"],
            "max_value": quota["max_value"] if quota else 0,
            "remaining": (quota["max_value"] - val["used"]) if quota else 0,
        })

    return {"agent_id": agent_id, "usage": usage_data, "total": len(usage_data)}


def get_violations(
    *,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get quota violation log."""
    results: list[dict[str, Any]] = []
    for v in reversed(_violations):
        if agent_id and v["agent_id"] != agent_id:
            continue
        results.append(v)
        if len(results) >= limit:
            break
    return results


def update_quota(quota_id: str, *, max_value: int | None = None, enabled: bool | None = None) -> dict[str, Any]:
    """Update a quota's max value or enabled status."""
    q = _quotas.get(quota_id)
    if not q:
        raise KeyError(f"quota not found: {quota_id}")
    if max_value is not None:
        if max_value <= 0:
            raise ValueError("max_value must be positive")
        q["max_value"] = max_value
    if enabled is not None:
        q["enabled"] = enabled
    return q


def get_quota_stats() -> dict[str, Any]:
    """Get quota statistics."""
    total = len(_quotas)
    enabled = sum(1 for q in _quotas.values() if q["enabled"])
    by_resource: dict[str, int] = {}
    for q in _quotas.values():
        by_resource[q["resource"]] = by_resource.get(q["resource"], 0) + 1

    return {
        "total_quotas": total,
        "enabled_quotas": enabled,
        "by_resource": by_resource,
        "total_violations": len(_violations),
    }


def reset_for_tests() -> None:
    """Clear all quota data for testing."""
    _quotas.clear()
    _usage.clear()
    _violations.clear()
