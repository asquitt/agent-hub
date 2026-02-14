"""Entitlement catalog routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.entitlements import (
    add_role_member,
    assign_entitlement,
    create_entitlement,
    create_role,
    get_agent_entitlements,
    get_catalog_stats,
    get_entitlement,
    get_role,
    list_entitlements,
    list_roles,
    remove_role_member,
    revoke_assignment,
)

router = APIRouter(tags=["entitlements"])


class CreateEntitlementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    entitlement_type: str = Field(default="permission")
    description: str = ""
    resource: str | None = None
    actions: list[str] | None = None
    risk_level: str = Field(default="low")


class AssignEntitlementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    entitlement_id: str = Field(min_length=1)
    reason: str = ""
    expires_at: float | None = None


class CreateRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    description: str = ""
    entitlement_ids: list[str] | None = None
    members: list[str] | None = None


class RoleMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)


@router.post("/v1/entitlements")
def post_create_entitlement(
    body: CreateEntitlementRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a new entitlement."""
    try:
        return create_entitlement(
            name=body.name,
            entitlement_type=body.entitlement_type,
            description=body.description,
            resource=body.resource,
            actions=body.actions,
            risk_level=body.risk_level,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/entitlements")
def get_list_entitlements(
    entitlement_type: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List entitlements."""
    items = list_entitlements(
        entitlement_type=entitlement_type,
        risk_level=risk_level,
        limit=limit,
    )
    return {"total": len(items), "entitlements": items}


# ── Static routes MUST come before /{entitlement_id} ────────────────

@router.get("/v1/entitlements/stats")
def get_stats(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get catalog statistics."""
    return get_catalog_stats()


# ── Assignments (static prefix) ─────────────────────────────────────

@router.post("/v1/entitlements/assignments")
def post_assign(
    body: AssignEntitlementRequest,
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Assign an entitlement to an agent."""
    try:
        return assign_entitlement(
            agent_id=body.agent_id,
            entitlement_id=body.entitlement_id,
            granted_by=caller,
            reason=body.reason,
            expires_at=body.expires_at,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/entitlements/assignments/{assignment_id}/revoke")
def post_revoke(
    assignment_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Revoke an assignment."""
    try:
        return revoke_assignment(assignment_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/entitlements/agents/{agent_id}")
def get_agent_permissions(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get all entitlements for an agent."""
    items = get_agent_entitlements(agent_id)
    return {"agent_id": agent_id, "total": len(items), "entitlements": items}


# ── Roles (static prefix) ───────────────────────────────────────────

@router.post("/v1/entitlements/roles")
def post_create_role(
    body: CreateRoleRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a role."""
    try:
        return create_role(
            name=body.name,
            description=body.description,
            entitlement_ids=body.entitlement_ids,
            members=body.members,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/entitlements/roles")
def get_list_roles(
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List roles."""
    items = list_roles(limit=limit)
    return {"total": len(items), "roles": items}


@router.get("/v1/entitlements/roles/{role_id}")
def get_role_detail(
    role_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get role details."""
    try:
        return get_role(role_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/entitlements/roles/{role_id}/members")
def post_add_member(
    role_id: str,
    body: RoleMemberRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Add agent to a role."""
    try:
        return add_role_member(role_id, body.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/entitlements/roles/{role_id}/members/remove")
def post_remove_member(
    role_id: str,
    body: RoleMemberRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Remove agent from a role."""
    try:
        return remove_role_member(role_id, body.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ── Parameterized (MUST be last) ────────────────────────────────────

@router.get("/v1/entitlements/{entitlement_id}")
def get_entitlement_detail(
    entitlement_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get entitlement details."""
    try:
        return get_entitlement(entitlement_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
