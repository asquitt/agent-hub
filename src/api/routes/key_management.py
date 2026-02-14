"""Agent key management routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.key_management import (
    create_key,
    get_key,
    get_key_stats,
    get_usage_log,
    list_keys,
    record_usage,
    revoke_key,
    rotate_key,
)

router = APIRouter(tags=["key-management"])


class CreateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    name: str = ""
    scopes: list[str] | None = None
    ttl_seconds: int | None = Field(default=None, ge=60)


class RevokeKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = "manual"


class RecordUsageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=1)


@router.post("/v1/keys")
def post_create_key(
    body: CreateKeyRequest,
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a new API key."""
    return create_key(
        agent_id=body.agent_id,
        name=body.name,
        scopes=body.scopes,
        ttl_seconds=body.ttl_seconds,
        created_by=caller,
    )


@router.get("/v1/keys")
def get_list_keys(
    agent_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List API keys."""
    items = list_keys(agent_id=agent_id, status=status, limit=limit)
    return {"total": len(items), "keys": items}


# Static routes before parameterized
@router.get("/v1/keys/stats")
def get_stats(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get key statistics."""
    return get_key_stats()


@router.get("/v1/keys/usage")
def get_usage(
    key_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get key usage log."""
    items = get_usage_log(key_id=key_id, agent_id=agent_id, limit=limit)
    return {"total": len(items), "usage": items}


@router.post("/v1/keys/record-usage")
def post_record_usage(
    body: RecordUsageRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Record key usage."""
    try:
        return record_usage(body.key_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/keys/{key_id}")
def get_key_detail(
    key_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get key details."""
    try:
        return get_key(key_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/keys/{key_id}/rotate")
def post_rotate(
    key_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Rotate a key."""
    try:
        return rotate_key(key_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/keys/{key_id}/revoke")
def post_revoke(
    key_id: str,
    body: RevokeKeyRequest | None = None,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Revoke a key."""
    reason = body.reason if body else "manual"
    try:
        return revoke_key(key_id, reason=reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
