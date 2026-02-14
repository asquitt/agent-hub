"""Agent group policy routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.agent_groups import (
    add_member,
    create_group,
    get_agent_groups,
    get_effective_policy,
    get_group,
    get_group_stats,
    list_groups,
    remove_member,
    update_group_policies,
)

router = APIRouter(tags=["agent-groups"])


class CreateGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    description: str = ""
    parent_group_id: str | None = None
    policies: dict[str, Any] | None = None


class UpdatePoliciesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policies: dict[str, Any]


class MemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)


@router.post("/v1/groups")
def post_create(
    body: CreateGroupRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create an agent group."""
    try:
        return create_group(
            name=body.name,
            description=body.description,
            parent_group_id=body.parent_group_id,
            policies=body.policies,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/groups")
def get_list(
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List groups."""
    items = list_groups(limit=limit)
    return {"total": len(items), "groups": items}


# Static routes before parameterized
@router.get("/v1/groups/stats")
def get_stats(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get group statistics."""
    return get_group_stats()


@router.get("/v1/groups/agents/{agent_id}")
def get_agent_group_list(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get groups for an agent."""
    items = get_agent_groups(agent_id)
    return {"agent_id": agent_id, "total": len(items), "groups": items}


@router.get("/v1/groups/agents/{agent_id}/effective-policy")
def get_effective(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get effective policy for an agent."""
    return get_effective_policy(agent_id)


@router.get("/v1/groups/{group_id}")
def get_detail(
    group_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get group details."""
    try:
        return get_group(group_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/v1/groups/{group_id}/policies")
def put_policies(
    group_id: str,
    body: UpdatePoliciesRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Update group policies."""
    try:
        return update_group_policies(group_id, body.policies)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/groups/{group_id}/members")
def post_add_member(
    group_id: str,
    body: MemberRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Add agent to group."""
    try:
        return add_member(group_id, body.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/groups/{group_id}/members/remove")
def post_remove_member(
    group_id: str,
    body: MemberRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Remove agent from group."""
    try:
        return remove_member(group_id, body.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
