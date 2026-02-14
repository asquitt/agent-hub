"""Routes — IP Allowlisting (S158)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.runtime import ip_allowlist

router = APIRouter(prefix="/v1/ip-rules", tags=["ip-allowlist"])


@router.post("")
async def create_rule(request: Request) -> dict:
    body = await request.json()
    try:
        return ip_allowlist.create_rule(
            agent_id=body["agent_id"],
            name=body["name"],
            rule_type=body["rule_type"],
            cidrs=body["cidrs"],
            description=body.get("description", ""),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats")
async def get_stats() -> dict:
    return ip_allowlist.get_ip_stats()


@router.get("/access-log")
async def get_access_log(agent_id: str | None = None, limit: int = 100) -> dict:
    items = ip_allowlist.get_access_log(agent_id=agent_id, limit=limit)
    return {"entries": items, "total": len(items)}


@router.post("/check")
async def check_ip(request: Request) -> dict:
    body = await request.json()
    try:
        return ip_allowlist.check_ip(agent_id=body["agent_id"], ip_address=body["ip_address"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("")
async def list_rules(
    agent_id: str | None = None,
    rule_type: str | None = None,
    limit: int = 100,
) -> dict:
    items = ip_allowlist.list_rules(agent_id=agent_id, rule_type=rule_type, limit=limit)
    return {"rules": items, "total": len(items)}


@router.get("/{rule_id}")
async def get_rule(rule_id: str) -> dict:
    try:
        return ip_allowlist.get_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{rule_id}/disable")
async def disable_rule(rule_id: str) -> dict:
    try:
        return ip_allowlist.disable_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
