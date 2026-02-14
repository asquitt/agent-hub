"""Routes — Agent Capability Quotas (S159)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.runtime import capability_quotas

router = APIRouter(prefix="/v1/quotas", tags=["capability-quotas"])


@router.post("")
async def create_quota(request: Request) -> dict:
    body = await request.json()
    try:
        return capability_quotas.create_quota(
            agent_id=body["agent_id"],
            resource=body["resource"],
            max_value=body["max_value"],
            period_seconds=body.get("period_seconds", 0),
            description=body.get("description", ""),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats")
async def get_stats() -> dict:
    return capability_quotas.get_quota_stats()


@router.get("/violations")
async def get_violations(agent_id: str | None = None, limit: int = 100) -> dict:
    items = capability_quotas.get_violations(agent_id=agent_id, limit=limit)
    return {"violations": items, "total": len(items)}


@router.post("/check")
async def check_quota(request: Request) -> dict:
    body = await request.json()
    try:
        return capability_quotas.check_quota(
            agent_id=body["agent_id"],
            resource=body["resource"],
            amount=body.get("amount", 1),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/usage/{agent_id}")
async def get_usage(agent_id: str, resource: str | None = None) -> dict:
    return capability_quotas.get_usage(agent_id=agent_id, resource=resource)


@router.put("/{quota_id}")
async def update_quota(quota_id: str, request: Request) -> dict:
    body = await request.json()
    try:
        return capability_quotas.update_quota(
            quota_id,
            max_value=body.get("max_value"),
            enabled=body.get("enabled"),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400 if isinstance(exc, ValueError) else 404, detail=str(exc)) from exc


@router.get("")
async def list_quotas(
    agent_id: str | None = None,
    resource: str | None = None,
    limit: int = 100,
) -> dict:
    items = capability_quotas.list_quotas(agent_id=agent_id, resource=resource, limit=limit)
    return {"quotas": items, "total": len(items)}


@router.get("/{quota_id}")
async def get_quota(quota_id: str) -> dict:
    try:
        return capability_quotas.get_quota(quota_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
