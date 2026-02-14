"""Entitlement Catalog — centralized permission and role management.

Provides:
- Define entitlements (permissions/capabilities) with metadata
- Assign entitlements to agents
- Bundle entitlements into roles
- Query effective permissions for an agent
- Entitlement usage analytics
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.entitlements")

# Entitlement types
TYPE_PERMISSION = "permission"
TYPE_CAPABILITY = "capability"
TYPE_RESOURCE_ACCESS = "resource_access"
TYPE_API_SCOPE = "api_scope"

VALID_TYPES = {TYPE_PERMISSION, TYPE_CAPABILITY, TYPE_RESOURCE_ACCESS, TYPE_API_SCOPE}

# In-memory stores
_MAX_RECORDS = 10_000
_entitlements: dict[str, dict[str, Any]] = {}  # entitlement_id -> definition
_assignments: dict[str, dict[str, Any]] = {}  # assignment_id -> assignment
_roles: dict[str, dict[str, Any]] = {}  # role_id -> role


def create_entitlement(
    *,
    name: str,
    entitlement_type: str = TYPE_PERMISSION,
    description: str = "",
    resource: str | None = None,
    actions: list[str] | None = None,
    risk_level: str = "low",
) -> dict[str, Any]:
    """Define a new entitlement in the catalog."""
    if entitlement_type not in VALID_TYPES:
        raise ValueError(f"invalid entitlement type: {entitlement_type}")

    ent_id = f"ent-{uuid.uuid4().hex[:12]}"
    now = time.time()

    entitlement: dict[str, Any] = {
        "entitlement_id": ent_id,
        "name": name,
        "entitlement_type": entitlement_type,
        "description": description,
        "resource": resource,
        "actions": actions or [],
        "risk_level": risk_level,
        "created_at": now,
        "assignment_count": 0,
    }

    _entitlements[ent_id] = entitlement
    if len(_entitlements) > _MAX_RECORDS:
        oldest = sorted(_entitlements, key=lambda k: _entitlements[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _entitlements[k]

    return entitlement


def get_entitlement(entitlement_id: str) -> dict[str, Any]:
    """Get entitlement details."""
    ent = _entitlements.get(entitlement_id)
    if not ent:
        raise KeyError(f"entitlement not found: {entitlement_id}")
    return ent


def list_entitlements(
    *,
    entitlement_type: str | None = None,
    risk_level: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List entitlements."""
    results: list[dict[str, Any]] = []
    for e in _entitlements.values():
        if entitlement_type and e["entitlement_type"] != entitlement_type:
            continue
        if risk_level and e["risk_level"] != risk_level:
            continue
        results.append(e)
        if len(results) >= limit:
            break
    return results


def assign_entitlement(
    *,
    agent_id: str,
    entitlement_id: str,
    granted_by: str,
    reason: str = "",
    expires_at: float | None = None,
) -> dict[str, Any]:
    """Assign an entitlement to an agent."""
    ent = _entitlements.get(entitlement_id)
    if not ent:
        raise KeyError(f"entitlement not found: {entitlement_id}")

    # Check for duplicate
    for a in _assignments.values():
        if (a["agent_id"] == agent_id
                and a["entitlement_id"] == entitlement_id
                and a["status"] == "active"):
            raise ValueError(f"agent {agent_id} already has entitlement {entitlement_id}")

    assign_id = f"assign-{uuid.uuid4().hex[:12]}"
    now = time.time()

    assignment: dict[str, Any] = {
        "assignment_id": assign_id,
        "agent_id": agent_id,
        "entitlement_id": entitlement_id,
        "entitlement_name": ent["name"],
        "granted_by": granted_by,
        "reason": reason,
        "status": "active",
        "created_at": now,
        "expires_at": expires_at,
    }

    _assignments[assign_id] = assignment
    ent["assignment_count"] += 1

    if len(_assignments) > _MAX_RECORDS:
        oldest = sorted(_assignments, key=lambda k: _assignments[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _assignments[k]

    return assignment


def revoke_assignment(assignment_id: str) -> dict[str, Any]:
    """Revoke an entitlement assignment."""
    assignment = _assignments.get(assignment_id)
    if not assignment:
        raise KeyError(f"assignment not found: {assignment_id}")

    assignment["status"] = "revoked"
    assignment["revoked_at"] = time.time()

    ent = _entitlements.get(assignment["entitlement_id"])
    if ent:
        ent["assignment_count"] = max(0, ent["assignment_count"] - 1)

    return assignment


def get_agent_entitlements(agent_id: str) -> list[dict[str, Any]]:
    """Get all active entitlements for an agent (including from roles)."""
    now = time.time()
    direct: list[dict[str, Any]] = []

    for a in _assignments.values():
        if a["agent_id"] != agent_id:
            continue
        if a["status"] != "active":
            continue
        if a.get("expires_at") and a["expires_at"] < now:
            a["status"] = "expired"
            continue
        direct.append(a)

    # Also gather entitlements from roles
    role_entitlements: list[dict[str, Any]] = []
    for role in _roles.values():
        if agent_id in role.get("members", []):
            for ent_id in role.get("entitlement_ids", []):
                ent = _entitlements.get(ent_id)
                if ent:
                    role_entitlements.append({
                        "entitlement_id": ent_id,
                        "entitlement_name": ent["name"],
                        "source": "role",
                        "role_id": role["role_id"],
                        "role_name": role["name"],
                    })

    return direct + role_entitlements


def create_role(
    *,
    name: str,
    description: str = "",
    entitlement_ids: list[str] | None = None,
    members: list[str] | None = None,
) -> dict[str, Any]:
    """Create a role that bundles entitlements."""
    role_id = f"role-{uuid.uuid4().hex[:12]}"
    now = time.time()

    # Validate entitlement IDs
    ent_ids = entitlement_ids or []
    for eid in ent_ids:
        if eid not in _entitlements:
            raise KeyError(f"entitlement not found: {eid}")

    role: dict[str, Any] = {
        "role_id": role_id,
        "name": name,
        "description": description,
        "entitlement_ids": ent_ids,
        "members": members or [],
        "created_at": now,
    }

    _roles[role_id] = role
    if len(_roles) > _MAX_RECORDS:
        oldest = sorted(_roles, key=lambda k: _roles[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _roles[k]

    return role


def get_role(role_id: str) -> dict[str, Any]:
    """Get role details."""
    role = _roles.get(role_id)
    if not role:
        raise KeyError(f"role not found: {role_id}")
    return role


def list_roles(*, limit: int = 100) -> list[dict[str, Any]]:
    """List all roles."""
    return list(_roles.values())[:limit]


def add_role_member(role_id: str, agent_id: str) -> dict[str, Any]:
    """Add an agent to a role."""
    role = _roles.get(role_id)
    if not role:
        raise KeyError(f"role not found: {role_id}")
    if agent_id not in role["members"]:
        role["members"].append(agent_id)
    return role


def remove_role_member(role_id: str, agent_id: str) -> dict[str, Any]:
    """Remove an agent from a role."""
    role = _roles.get(role_id)
    if not role:
        raise KeyError(f"role not found: {role_id}")
    if agent_id in role["members"]:
        role["members"].remove(agent_id)
    return role


def get_catalog_stats() -> dict[str, Any]:
    """Get catalog statistics."""
    total_ents = len(_entitlements)
    total_assignments = sum(1 for a in _assignments.values() if a["status"] == "active")
    total_roles = len(_roles)
    high_risk = sum(1 for e in _entitlements.values() if e["risk_level"] == "high")

    return {
        "total_entitlements": total_ents,
        "active_assignments": total_assignments,
        "total_roles": total_roles,
        "high_risk_entitlements": high_risk,
    }


def reset_for_tests() -> None:
    """Clear all entitlement data for testing."""
    _entitlements.clear()
    _assignments.clear()
    _roles.clear()
