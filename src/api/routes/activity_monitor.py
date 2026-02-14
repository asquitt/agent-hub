"""Routes — Agent Activity Monitoring (S155)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.runtime import activity_monitor

router = APIRouter(prefix="/v1/activity", tags=["activity-monitor"])


@router.post("")
async def record_activity(request: Request) -> dict:
    body = await request.json()
    try:
        return activity_monitor.record_activity(
            agent_id=body["agent_id"],
            action=body["action"],
            resource=body.get("resource"),
            details=body.get("details"),
            source_ip=body.get("source_ip"),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats")
async def get_stats() -> dict:
    return activity_monitor.get_activity_stats()


@router.get("/summary/{agent_id}")
async def get_agent_summary(agent_id: str) -> dict:
    return activity_monitor.get_agent_summary(agent_id)


@router.get("/alerts")
async def list_alerts(
    agent_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> dict:
    items = activity_monitor.list_alerts(
        agent_id=agent_id, status=status, severity=severity, limit=limit,
    )
    return {"alerts": items, "total": len(items)}


@router.post("/alerts")
async def create_alert(request: Request) -> dict:
    body = await request.json()
    try:
        return activity_monitor.create_alert(
            agent_id=body["agent_id"],
            alert_type=body["alert_type"],
            severity=body["severity"],
            message=body["message"],
            activity_id=body.get("activity_id"),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str) -> dict:
    try:
        return activity_monitor.get_alert(alert_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str) -> dict:
    try:
        return activity_monitor.acknowledge_alert(alert_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("")
async def list_activities(
    agent_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
) -> dict:
    items = activity_monitor.list_activities(
        agent_id=agent_id, action=action, limit=limit,
    )
    return {"activities": items, "total": len(items)}


@router.get("/{activity_id}")
async def get_activity(activity_id: str) -> dict:
    try:
        return activity_monitor.get_activity(activity_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
