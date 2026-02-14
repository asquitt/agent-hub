"""Session-based ephemeral access grant routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.session_grants import (
    check_grant,
    consume_grant,
    create_grant,
    get_grant,
    get_grant_usage,
    list_grants,
    revoke_grant,
)

router = APIRouter(tags=["grants"])


class CreateGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    scopes: list[str] = Field(min_length=1)
    grant_type: str = Field(default="time_bound")
    ttl_seconds: int = Field(default=300, ge=10, le=86400)
    max_uses: int | None = None
    resource: str | None = None
    context: str = ""


class ConsumeGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = ""
    resource: str | None = None


class CheckGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    resource: str | None = None


@router.post("/v1/grants")
def post_create_grant(
    body: CreateGrantRequest,
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create an ephemeral access grant."""
    try:
        return create_grant(
            agent_id=body.agent_id,
            scopes=body.scopes,
            grant_type=body.grant_type,
            ttl_seconds=body.ttl_seconds,
            max_uses=body.max_uses,
            resource=body.resource,
            context=body.context,
            granted_by=caller,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/grants")
def get_list_grants(
    agent_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List grants with filters."""
    items = list_grants(agent_id=agent_id, status=status, limit=limit)
    return {"total": len(items), "grants": items}


# Static routes BEFORE parameterized {grant_id} to avoid conflicts


@router.post("/v1/grants/check")
def post_check_grant(
    body: CheckGrantRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check if an agent has an active grant for a scope."""
    return check_grant(
        agent_id=body.agent_id,
        scope=body.scope,
        resource=body.resource,
    )


@router.get("/v1/grants/usage")
def get_usage(
    grant_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get grant usage audit trail."""
    entries = get_grant_usage(grant_id=grant_id, agent_id=agent_id, limit=limit)
    return {"total": len(entries), "entries": entries}


# Parameterized routes after static ones


@router.get("/v1/grants/{grant_id}")
def get_grant_detail(
    grant_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get details of a specific grant."""
    try:
        return get_grant(grant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/grants/{grant_id}/consume")
def post_consume_grant(
    grant_id: str,
    body: ConsumeGrantRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Consume a grant (use it)."""
    try:
        return consume_grant(
            grant_id=grant_id,
            action=body.action,
            resource=body.resource,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/grants/{grant_id}/revoke")
def post_revoke_grant(
    grant_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Revoke an active grant."""
    try:
        return revoke_grant(grant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
