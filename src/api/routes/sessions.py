"""Agent session management routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.sessions import (
    create_session,
    force_logout,
    get_session,
    get_session_policy,
    get_session_stats,
    list_sessions,
    set_session_policy,
    terminate_session,
    touch_session,
)

router = APIRouter(tags=["sessions"])


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    metadata: dict[str, Any] | None = None
    ip_address: str | None = None


class ForceLogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    reason: str = "forced_logout"


class SetPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    max_concurrent: int | None = Field(default=None, ge=1, le=100)
    default_ttl: int | None = Field(default=None, ge=60, le=86400)
    allowed_ips: list[str] | None = None


@router.post("/v1/sessions")
def post_create_session(
    body: CreateSessionRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a new agent session."""
    try:
        return create_session(
            agent_id=body.agent_id,
            ttl_seconds=body.ttl_seconds,
            metadata=body.metadata,
            ip_address=body.ip_address,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/sessions")
def get_list_sessions(
    agent_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List sessions."""
    items = list_sessions(agent_id=agent_id, status=status, limit=limit)
    return {"total": len(items), "sessions": items}


@router.get("/v1/sessions/stats")
def get_stats(
    agent_id: str | None = Query(default=None),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get session statistics."""
    return get_session_stats(agent_id=agent_id)


@router.get("/v1/sessions/{session_id}")
def get_session_detail(
    session_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get session details."""
    try:
        return get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/sessions/{session_id}/touch")
def post_touch_session(
    session_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Record activity on a session (heartbeat)."""
    try:
        return touch_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/sessions/{session_id}/terminate")
def post_terminate_session(
    session_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Terminate a session."""
    try:
        return terminate_session(session_id, reason="api_terminated")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/sessions/force-logout")
def post_force_logout(
    body: ForceLogoutRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Terminate all active sessions for an agent."""
    return force_logout(body.agent_id, reason=body.reason)


@router.post("/v1/sessions/policies")
def post_set_policy(
    body: SetPolicyRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Set session policy for an agent."""
    try:
        return set_session_policy(
            agent_id=body.agent_id,
            max_concurrent=body.max_concurrent,
            default_ttl=body.default_ttl,
            allowed_ips=body.allowed_ips,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/sessions/policies/{agent_id}")
def get_policy(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get session policy for an agent."""
    return get_session_policy(agent_id)
