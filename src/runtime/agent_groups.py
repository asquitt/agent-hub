"""Agent Group Policies — organizational grouping with inherited policies.

Provides:
- Create groups with policy settings (rate limits, allowed scopes, etc.)
- Add/remove agents from groups
- Policy inheritance: agent inherits most restrictive group policy
- Group hierarchy support
- Effective policy resolution
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.agent_groups")

_MAX_RECORDS = 10_000
_groups: dict[str, dict[str, Any]] = {}  # group_id -> group


def create_group(
    *,
    name: str,
    description: str = "",
    parent_group_id: str | None = None,
    policies: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create an agent group with optional policies."""
    if parent_group_id and parent_group_id not in _groups:
        raise KeyError(f"parent group not found: {parent_group_id}")

    group_id = f"grp-{uuid.uuid4().hex[:12]}"
    now = time.time()

    group: dict[str, Any] = {
        "group_id": group_id,
        "name": name,
        "description": description,
        "parent_group_id": parent_group_id,
        "policies": policies or {},
        "members": [],
        "children": [],
        "created_at": now,
    }

    _groups[group_id] = group

    if parent_group_id:
        _groups[parent_group_id]["children"].append(group_id)

    if len(_groups) > _MAX_RECORDS:
        oldest = sorted(_groups, key=lambda k: _groups[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _groups[k]

    return group


def get_group(group_id: str) -> dict[str, Any]:
    """Get group details."""
    group = _groups.get(group_id)
    if not group:
        raise KeyError(f"group not found: {group_id}")
    return group


def list_groups(*, limit: int = 100) -> list[dict[str, Any]]:
    """List all groups."""
    return list(_groups.values())[:limit]


def update_group_policies(
    group_id: str,
    policies: dict[str, Any],
) -> dict[str, Any]:
    """Update policies for a group."""
    group = _groups.get(group_id)
    if not group:
        raise KeyError(f"group not found: {group_id}")
    group["policies"].update(policies)
    return group


def add_member(group_id: str, agent_id: str) -> dict[str, Any]:
    """Add an agent to a group."""
    group = _groups.get(group_id)
    if not group:
        raise KeyError(f"group not found: {group_id}")
    if agent_id not in group["members"]:
        group["members"].append(agent_id)
    return group


def remove_member(group_id: str, agent_id: str) -> dict[str, Any]:
    """Remove an agent from a group."""
    group = _groups.get(group_id)
    if not group:
        raise KeyError(f"group not found: {group_id}")
    if agent_id in group["members"]:
        group["members"].remove(agent_id)
    return group


def get_agent_groups(agent_id: str) -> list[dict[str, Any]]:
    """Get all groups an agent belongs to."""
    results: list[dict[str, Any]] = []
    for group in _groups.values():
        if agent_id in group["members"]:
            results.append({
                "group_id": group["group_id"],
                "name": group["name"],
                "policies": group["policies"],
            })
    return results


def get_effective_policy(agent_id: str) -> dict[str, Any]:
    """Resolve effective policy for an agent (most restrictive wins)."""
    merged: dict[str, Any] = {}

    for group in _groups.values():
        if agent_id not in group["members"]:
            continue
        # Merge this group's policies + inherited from parent chain
        chain_policies = _get_policy_chain(group["group_id"])
        for policy in chain_policies:
            for key, value in policy.items():
                if key not in merged:
                    merged[key] = value
                else:
                    merged[key] = _most_restrictive(key, merged[key], value)

    return {
        "agent_id": agent_id,
        "effective_policies": merged,
        "resolved_at": time.time(),
    }


def get_group_stats() -> dict[str, Any]:
    """Get group statistics."""
    total_groups = len(_groups)
    total_members = sum(len(g["members"]) for g in _groups.values())
    groups_with_policies = sum(1 for g in _groups.values() if g["policies"])

    return {
        "total_groups": total_groups,
        "total_memberships": total_members,
        "groups_with_policies": groups_with_policies,
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _get_policy_chain(group_id: str) -> list[dict[str, Any]]:
    """Get policies from group up through parent chain."""
    chain: list[dict[str, Any]] = []
    current = _groups.get(group_id)
    visited: set[str] = set()
    while current and current["group_id"] not in visited:
        visited.add(current["group_id"])
        if current["policies"]:
            chain.append(current["policies"])
        parent_id = current.get("parent_group_id")
        current = _groups.get(parent_id) if parent_id else None
    return chain


def _most_restrictive(key: str, a: Any, b: Any) -> Any:
    """Pick the most restrictive value for a policy key."""
    # For numeric limits, take the lower value
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return min(a, b)
    # For lists (allowed scopes), take the intersection
    if isinstance(a, list) and isinstance(b, list):
        intersection = [x for x in a if x in b]
        return intersection if intersection else a
    # For booleans, False is more restrictive
    if isinstance(a, bool) and isinstance(b, bool):
        return a and b
    # Default: keep existing
    return a


def reset_for_tests() -> None:
    """Clear all group data for testing."""
    _groups.clear()
