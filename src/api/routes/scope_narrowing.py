"""Routes — Token Scope Narrowing (S157)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.runtime import scope_narrowing

router = APIRouter(prefix="/v1/scope-narrowing", tags=["scope-narrowing"])


@router.post("")
async def narrow_scope(request: Request) -> dict:
    body = await request.json()
    try:
        return scope_narrowing.narrow_scope(
            parent_token_id=body["parent_token_id"],
            parent_scopes=body["parent_scopes"],
            requested_scopes=body["requested_scopes"],
            agent_id=body["agent_id"],
            ttl_seconds=body.get("ttl_seconds", 3600),
            reason=body.get("reason", ""),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats")
async def get_stats() -> dict:
    return scope_narrowing.get_narrowing_stats()


@router.get("/log")
async def get_log(agent_id: str | None = None, limit: int = 100) -> dict:
    items = scope_narrowing.get_narrowing_log(agent_id=agent_id, limit=limit)
    return {"events": items, "total": len(items)}


@router.post("/validate")
async def validate_token(request: Request) -> dict:
    body = await request.json()
    return scope_narrowing.validate_narrowed_token(body["token_id"])


@router.get("")
async def list_tokens(
    agent_id: str | None = None,
    parent_token_id: str | None = None,
    active_only: bool = False,
    limit: int = 100,
) -> dict:
    items = scope_narrowing.list_narrowed_tokens(
        agent_id=agent_id, parent_token_id=parent_token_id,
        active_only=active_only, limit=limit,
    )
    return {"tokens": items, "total": len(items)}


@router.get("/{token_id}")
async def get_token(token_id: str) -> dict:
    try:
        return scope_narrowing.get_narrowed_token(token_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{token_id}/revoke")
async def revoke_token(token_id: str) -> dict:
    try:
        return scope_narrowing.revoke_narrowed_token(token_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
