"""Routes — Environment-Based Access Controls (S156)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.runtime import env_access

router = APIRouter(prefix="/v1/environments", tags=["env-access"])


@router.post("")
async def create_environment(request: Request) -> dict:
    body = await request.json()
    try:
        return env_access.create_environment(
            name=body["name"],
            tier=body["tier"],
            description=body.get("description", ""),
            allowed_actions=body.get("allowed_actions"),
            max_agents=body.get("max_agents", 0),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats")
async def get_stats() -> dict:
    return env_access.get_env_stats()


@router.get("/promotions")
async def get_promotions(agent_id: str | None = None, limit: int = 100) -> dict:
    items = env_access.get_promotion_log(agent_id=agent_id, limit=limit)
    return {"promotions": items, "total": len(items)}


@router.get("/policies")
async def list_policies(env_id: str | None = None, limit: int = 100) -> dict:
    items = env_access.list_policies(env_id=env_id, limit=limit)
    return {"policies": items, "total": len(items)}


@router.post("/policies")
async def create_policy(request: Request) -> dict:
    body = await request.json()
    try:
        return env_access.create_policy(
            env_id=body["env_id"],
            name=body["name"],
            rules=body["rules"],
            description=body.get("description", ""),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/check")
async def check_access(request: Request) -> dict:
    body = await request.json()
    try:
        return env_access.check_access(
            agent_id=body["agent_id"],
            env_id=body["env_id"],
            action=body["action"],
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/promote")
async def promote_agent(request: Request) -> dict:
    body = await request.json()
    try:
        return env_access.promote_agent(
            agent_id=body["agent_id"],
            from_env_id=body["from_env_id"],
            to_env_id=body["to_env_id"],
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{env_id}/register")
async def register_agent(env_id: str, request: Request) -> dict:
    body = await request.json()
    try:
        return env_access.register_agent(env_id, body["agent_id"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{env_id}/unregister")
async def unregister_agent(env_id: str, request: Request) -> dict:
    body = await request.json()
    try:
        return env_access.unregister_agent(env_id, body["agent_id"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("")
async def list_environments(tier: str | None = None, limit: int = 100) -> dict:
    items = env_access.list_environments(tier=tier, limit=limit)
    return {"environments": items, "total": len(items)}


@router.get("/{env_id}")
async def get_environment(env_id: str) -> dict:
    try:
        return env_access.get_environment(env_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
