"""Rate limit policy routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.rate_policies import (
    check_rate_limit,
    create_policy,
    get_policy,
    get_rate_stats,
    get_violations,
    list_policies,
    update_policy,
)

router = APIRouter(tags=["rate-policies"])


class CreatePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    resource: str = "api"
    max_requests: int = Field(ge=1)
    window_seconds: int = Field(default=60, ge=1)
    burst_allowance: int = Field(default=0, ge=0)
    action: str = Field(default="deny")


class UpdatePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_requests: int | None = Field(default=None, ge=1)
    window_seconds: int | None = Field(default=None, ge=1)
    burst_allowance: int | None = Field(default=None, ge=0)
    enabled: bool | None = None


class CheckRateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    resource: str = "api"


@router.post("/v1/rate-policies")
def post_create(
    body: CreatePolicyRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a rate limit policy."""
    try:
        return create_policy(
            agent_id=body.agent_id,
            resource=body.resource,
            max_requests=body.max_requests,
            window_seconds=body.window_seconds,
            burst_allowance=body.burst_allowance,
            action=body.action,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/rate-policies")
def get_list(
    agent_id: str | None = Query(default=None),
    resource: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List rate limit policies."""
    items = list_policies(agent_id=agent_id, resource=resource, limit=limit)
    return {"total": len(items), "policies": items}


# Static routes before parameterized
@router.get("/v1/rate-policies/stats")
def get_stats(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get rate limiting statistics."""
    return get_rate_stats()


@router.post("/v1/rate-policies/check")
def post_check(
    body: CheckRateRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check rate limit for an agent."""
    return check_rate_limit(body.agent_id, body.resource)


@router.get("/v1/rate-policies/violations")
def get_violation_list(
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get rate limit violations."""
    items = get_violations(agent_id=agent_id, limit=limit)
    return {"total": len(items), "violations": items}


@router.get("/v1/rate-policies/{policy_id}")
def get_detail(
    policy_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get rate limit policy details."""
    try:
        return get_policy(policy_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/v1/rate-policies/{policy_id}")
def put_update(
    policy_id: str,
    body: UpdatePolicyRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Update a rate limit policy."""
    try:
        return update_policy(
            policy_id,
            max_requests=body.max_requests,
            window_seconds=body.window_seconds,
            burst_allowance=body.burst_allowance,
            enabled=body.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
