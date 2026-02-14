"""Human-in-the-loop approval workflow routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.approval import (
    check_approval,
    create_approval_request,
    decide_approval,
    get_approval_request,
    get_pending_count,
    list_approval_policies,
    list_approval_requests,
    set_approval_policy,
)

router = APIRouter(tags=["approval"])


class CreateApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str | None = None
    justification: str = ""
    metadata: dict[str, Any] | None = None
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class DecideApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern=r"^(approve|reject)$")
    reason: str = ""


class CheckApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str | None = None


class SetPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str | None = None
    action_pattern: str | None = None
    risk_level: str | None = None
    decision: str = Field(pattern=r"^(auto_approve|require_approval|deny)$")


@router.post("/v1/approval/requests")
def post_create_approval(
    body: CreateApprovalRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a new approval request."""
    return create_approval_request(
        agent_id=body.agent_id,
        action=body.action,
        resource=body.resource,
        justification=body.justification,
        metadata=body.metadata,
        ttl_seconds=body.ttl_seconds,
    )


@router.get("/v1/approval/requests")
def get_list_approvals(
    agent_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List approval requests with filters."""
    items = list_approval_requests(
        agent_id=agent_id,
        status=status,
        risk_level=risk_level,
        limit=limit,
    )
    return {"total": len(items), "requests": items}


@router.get("/v1/approval/requests/{request_id}")
def get_approval_detail(
    request_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get details of a specific approval request."""
    try:
        return get_approval_request(request_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/approval/requests/{request_id}/decide")
def post_decide_approval(
    request_id: str,
    body: DecideApprovalRequest,
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Approve or reject a pending request."""
    try:
        return decide_approval(
            request_id=request_id,
            decision=body.decision,
            decided_by=caller,
            reason=body.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/approval/check")
def post_check_approval(
    body: CheckApprovalRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check if an action needs approval."""
    return check_approval(
        agent_id=body.agent_id,
        action=body.action,
        resource=body.resource,
    )


@router.get("/v1/approval/pending")
def get_pending(
    agent_id: str | None = Query(default=None),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get count of pending approvals."""
    return get_pending_count(agent_id=agent_id)


@router.post("/v1/approval/policies")
def post_set_policy(
    body: SetPolicyRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Set an approval policy rule."""
    try:
        return set_approval_policy(
            agent_id=body.agent_id,
            action_pattern=body.action_pattern,
            risk_level=body.risk_level,
            decision=body.decision,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/approval/policies")
def get_policies(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List all approval policies."""
    policies = list_approval_policies()
    return {"total": len(policies), "policies": policies}
