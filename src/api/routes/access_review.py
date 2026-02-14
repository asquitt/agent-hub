"""Agent access review / certification campaign routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.access_review import (
    add_review_item,
    create_campaign,
    decide_review_item,
    get_campaign,
    get_campaign_progress,
    get_compliance_summary,
    list_campaigns,
    list_review_items,
)

router = APIRouter(tags=["access-review"])


class CreateCampaignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    campaign_type: str = Field(default="ad_hoc")
    scope: str | None = None
    reviewer: str | None = None
    deadline_seconds: int = Field(default=604800, ge=3600, le=7776000)
    description: str = ""
    agent_ids: list[str] | None = None


class AddReviewItemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    entitlement_type: str = Field(min_length=1)
    entitlement_detail: str = ""
    resource: str | None = None


class DecideReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern=r"^(certified|revoked)$")
    reason: str = ""


@router.post("/v1/access-review/campaigns")
def post_create_campaign(
    body: CreateCampaignRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create an access review campaign."""
    try:
        return create_campaign(
            name=body.name,
            campaign_type=body.campaign_type,
            scope=body.scope,
            reviewer=body.reviewer,
            deadline_seconds=body.deadline_seconds,
            description=body.description,
            agent_ids=body.agent_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/access-review/campaigns")
def get_list_campaigns(
    status: str | None = Query(default=None),
    campaign_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List campaigns."""
    items = list_campaigns(status=status, campaign_type=campaign_type, limit=limit)
    return {"total": len(items), "campaigns": items}


@router.get("/v1/access-review/campaigns/{campaign_id}")
def get_campaign_detail(
    campaign_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get campaign details."""
    try:
        return get_campaign(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/access-review/campaigns/{campaign_id}/progress")
def get_progress(
    campaign_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get campaign progress metrics."""
    try:
        return get_campaign_progress(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/access-review/campaigns/{campaign_id}/items")
def post_add_item(
    campaign_id: str,
    body: AddReviewItemRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Add a review item to a campaign."""
    try:
        return add_review_item(
            campaign_id=campaign_id,
            agent_id=body.agent_id,
            entitlement_type=body.entitlement_type,
            entitlement_detail=body.entitlement_detail,
            resource=body.resource,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/access-review/campaigns/{campaign_id}/items")
def get_items(
    campaign_id: str,
    decision: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List review items for a campaign."""
    items = list_review_items(
        campaign_id=campaign_id,
        decision=decision,
        agent_id=agent_id,
        limit=limit,
    )
    return {"total": len(items), "items": items}


@router.post("/v1/access-review/items/{item_id}/decide")
def post_decide_item(
    item_id: str,
    body: DecideReviewRequest,
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Certify or revoke access for a review item."""
    try:
        return decide_review_item(
            item_id=item_id,
            decision=body.decision,
            decided_by=caller,
            reason=body.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/access-review/compliance")
def get_compliance(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get overall access review compliance summary."""
    return get_compliance_summary()
