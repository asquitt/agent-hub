"""RBAC routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.rbac import (
    add_sod_constraint,
    assign_role,
    check_permission,
    define_role,
    get_agent_roles,
    get_check_log,
    get_rbac_stats,
    get_role,
    list_roles,
    list_sod_constraints,
    remove_role,
)

router = APIRouter(tags=["rbac"])


class DefineRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    permissions: list[str] | None = None
    parent_role_id: str | None = None
    description: str = ""


class RoleAssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)


class CheckPermissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    permission: str = Field(min_length=1)
    resource: str | None = None


class SodConstraintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    role_ids: list[str] = Field(min_length=2)
    description: str = ""


@router.post("/v1/rbac/roles")
def post_define_role(
    body: DefineRoleRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Define an RBAC role."""
    try:
        return define_role(
            name=body.name,
            permissions=body.permissions,
            parent_role_id=body.parent_role_id,
            description=body.description,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/rbac/roles")
def get_list_roles(
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List RBAC roles."""
    items = list_roles(limit=limit)
    return {"total": len(items), "roles": items}


# Static routes before parameterized
@router.get("/v1/rbac/stats")
def get_stats(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get RBAC statistics."""
    return get_rbac_stats()


@router.get("/v1/rbac/roles/{role_id}")
def get_role_detail(
    role_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get RBAC role details."""
    try:
        return get_role(role_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/rbac/assignments")
def post_assign(
    body: RoleAssignRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Assign an agent to a role."""
    try:
        return assign_role(body.role_id, body.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/rbac/assignments/remove")
def post_remove(
    body: RoleAssignRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Remove an agent from a role."""
    try:
        return remove_role(body.role_id, body.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/rbac/check")
def post_check(
    body: CheckPermissionRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check if agent has a permission."""
    return check_permission(
        body.agent_id,
        body.permission,
        resource=body.resource,
    )


@router.get("/v1/rbac/agents/{agent_id}/roles")
def get_agent_roles_detail(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get all roles for an agent."""
    items = get_agent_roles(agent_id)
    return {"agent_id": agent_id, "total": len(items), "roles": items}


@router.get("/v1/rbac/check-log")
def get_checks(
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get permission check log."""
    items = get_check_log(agent_id=agent_id, limit=limit)
    return {"total": len(items), "checks": items}


# ── SoD ─────────────────────────────────────────────────────────────

@router.post("/v1/rbac/sod-constraints")
def post_sod(
    body: SodConstraintRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Add a separation-of-duties constraint."""
    try:
        return add_sod_constraint(
            name=body.name,
            role_ids=body.role_ids,
            description=body.description,
        )
    except (KeyError, ValueError) as exc:
        status = 404 if isinstance(exc, KeyError) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.get("/v1/rbac/sod-constraints")
def get_sod_list(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List SoD constraints."""
    items = list_sod_constraints()
    return {"total": len(items), "constraints": items}
