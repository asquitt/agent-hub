"""RBAC — Role-Based Access Control with hierarchical roles.

Extends the entitlement catalog (S148) with:
- Role hierarchy (parent-child inheritance)
- Permission checking (does agent X have permission Y?)
- RBAC policy evaluation (allow/deny based on role membership)
- Separation of duties (mutually exclusive roles)
- Role constraint enforcement
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.rbac")

# In-memory stores
_MAX_RECORDS = 10_000
_role_hierarchy: dict[str, dict[str, Any]] = {}  # role_id -> {parent_id, children}
_role_permissions: dict[str, set[str]] = {}  # role_id -> set of permissions
_role_members: dict[str, set[str]] = {}  # role_id -> set of agent_ids
_sod_constraints: dict[str, dict[str, Any]] = {}  # constraint_id -> constraint
_check_log: list[dict[str, Any]] = []


def define_role(
    *,
    name: str,
    permissions: list[str] | None = None,
    parent_role_id: str | None = None,
    description: str = "",
) -> dict[str, Any]:
    """Define an RBAC role with optional parent for inheritance."""
    role_id = f"rbac-{uuid.uuid4().hex[:12]}"
    now = time.time()

    if parent_role_id and parent_role_id not in _role_hierarchy:
        raise KeyError(f"parent role not found: {parent_role_id}")

    perms = set(permissions or [])
    _role_permissions[role_id] = perms
    _role_members[role_id] = set()

    node: dict[str, Any] = {
        "role_id": role_id,
        "name": name,
        "description": description,
        "parent_role_id": parent_role_id,
        "children": [],
        "created_at": now,
    }

    _role_hierarchy[role_id] = node

    # Register as child of parent
    if parent_role_id:
        _role_hierarchy[parent_role_id]["children"].append(role_id)

    if len(_role_hierarchy) > _MAX_RECORDS:
        oldest = sorted(_role_hierarchy, key=lambda k: _role_hierarchy[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _role_hierarchy[k]

    return {
        "role_id": role_id,
        "name": name,
        "description": description,
        "parent_role_id": parent_role_id,
        "permissions": sorted(perms),
        "created_at": now,
    }


def get_role(role_id: str) -> dict[str, Any]:
    """Get RBAC role details including inherited permissions."""
    node = _role_hierarchy.get(role_id)
    if not node:
        raise KeyError(f"role not found: {role_id}")

    effective = _get_effective_permissions(role_id)
    own = _role_permissions.get(role_id, set())

    return {
        "role_id": role_id,
        "name": node["name"],
        "description": node["description"],
        "parent_role_id": node["parent_role_id"],
        "children": node["children"],
        "own_permissions": sorted(own),
        "effective_permissions": sorted(effective),
        "members": sorted(_role_members.get(role_id, set())),
    }


def list_roles(*, limit: int = 100) -> list[dict[str, Any]]:
    """List all RBAC roles."""
    results: list[dict[str, Any]] = []
    for role_id, node in _role_hierarchy.items():
        results.append({
            "role_id": role_id,
            "name": node["name"],
            "parent_role_id": node["parent_role_id"],
            "member_count": len(_role_members.get(role_id, set())),
            "permission_count": len(_role_permissions.get(role_id, set())),
        })
        if len(results) >= limit:
            break
    return results


def assign_role(role_id: str, agent_id: str) -> dict[str, Any]:
    """Assign an agent to an RBAC role."""
    if role_id not in _role_hierarchy:
        raise KeyError(f"role not found: {role_id}")

    # Check SoD constraints
    _check_sod(agent_id, role_id)

    if role_id not in _role_members:
        _role_members[role_id] = set()
    _role_members[role_id].add(agent_id)

    return {
        "role_id": role_id,
        "agent_id": agent_id,
        "assigned": True,
        "effective_permissions": sorted(_get_effective_permissions(role_id)),
    }


def remove_role(role_id: str, agent_id: str) -> dict[str, Any]:
    """Remove an agent from an RBAC role."""
    if role_id not in _role_hierarchy:
        raise KeyError(f"role not found: {role_id}")
    members = _role_members.get(role_id, set())
    members.discard(agent_id)
    return {"role_id": role_id, "agent_id": agent_id, "removed": True}


def check_permission(
    agent_id: str,
    permission: str,
    *,
    resource: str | None = None,
) -> dict[str, Any]:
    """Check if an agent has a specific permission via any role."""
    granted = False
    granting_roles: list[str] = []

    for role_id, members in _role_members.items():
        if agent_id not in members:
            continue
        effective = _get_effective_permissions(role_id)
        if permission in effective or "*" in effective:
            granted = True
            granting_roles.append(role_id)

    result: dict[str, Any] = {
        "agent_id": agent_id,
        "permission": permission,
        "resource": resource,
        "granted": granted,
        "granting_roles": granting_roles,
        "checked_at": time.time(),
    }

    _check_log.append(result)
    if len(_check_log) > _MAX_RECORDS:
        _check_log[:] = _check_log[-_MAX_RECORDS:]

    return result


def get_agent_roles(agent_id: str) -> list[dict[str, Any]]:
    """Get all roles assigned to an agent."""
    roles: list[dict[str, Any]] = []
    for role_id, members in _role_members.items():
        if agent_id in members:
            node = _role_hierarchy[role_id]
            roles.append({
                "role_id": role_id,
                "name": node["name"],
                "effective_permissions": sorted(_get_effective_permissions(role_id)),
            })
    return roles


def add_sod_constraint(
    *,
    name: str,
    role_ids: list[str],
    description: str = "",
) -> dict[str, Any]:
    """Add a separation-of-duties constraint (mutually exclusive roles)."""
    if len(role_ids) < 2:
        raise ValueError("SoD constraint requires at least 2 roles")

    for rid in role_ids:
        if rid not in _role_hierarchy:
            raise KeyError(f"role not found: {rid}")

    cid = f"sod-{uuid.uuid4().hex[:12]}"
    constraint: dict[str, Any] = {
        "constraint_id": cid,
        "name": name,
        "role_ids": role_ids,
        "description": description,
        "created_at": time.time(),
    }
    _sod_constraints[cid] = constraint
    return constraint


def list_sod_constraints() -> list[dict[str, Any]]:
    """List all SoD constraints."""
    return list(_sod_constraints.values())


def get_check_log(
    *,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get permission check log."""
    results: list[dict[str, Any]] = []
    for entry in reversed(_check_log):
        if agent_id and entry["agent_id"] != agent_id:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def get_rbac_stats() -> dict[str, Any]:
    """Get RBAC statistics."""
    total_roles = len(_role_hierarchy)
    total_members = sum(len(m) for m in _role_members.values())
    total_permissions = sum(len(p) for p in _role_permissions.values())
    total_checks = len(_check_log)
    granted = sum(1 for c in _check_log if c["granted"])

    return {
        "total_roles": total_roles,
        "total_assignments": total_members,
        "total_permissions": total_permissions,
        "total_checks": total_checks,
        "granted_checks": granted,
        "denied_checks": total_checks - granted,
        "sod_constraints": len(_sod_constraints),
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _get_effective_permissions(role_id: str) -> set[str]:
    """Get effective permissions including inherited from parent chain."""
    perms = set(_role_permissions.get(role_id, set()))
    node = _role_hierarchy.get(role_id)
    if node and node["parent_role_id"]:
        perms |= _get_effective_permissions(node["parent_role_id"])
    return perms


def _check_sod(agent_id: str, new_role_id: str) -> None:
    """Check separation-of-duties constraints."""
    current_roles = {
        rid for rid, members in _role_members.items() if agent_id in members
    }
    candidate = current_roles | {new_role_id}

    for constraint in _sod_constraints.values():
        conflict_roles = set(constraint["role_ids"])
        overlap = candidate & conflict_roles
        if len(overlap) >= 2:
            raise ValueError(
                f"SoD violation: constraint '{constraint['name']}' "
                f"prevents holding roles {sorted(overlap)} simultaneously"
            )


def reset_for_tests() -> None:
    """Clear all RBAC data for testing."""
    _role_hierarchy.clear()
    _role_permissions.clear()
    _role_members.clear()
    _sod_constraints.clear()
    _check_log.clear()
