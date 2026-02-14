"""Secret rotation vault routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.secret_vault import (
    access_secret,
    get_expiring_secrets,
    get_rotation_due,
    get_rotation_history,
    get_secret,
    list_secrets,
    revoke_secret,
    rotate_secret,
    store_secret,
)

router = APIRouter(tags=["vault"])


class StoreSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    value: str = Field(min_length=1)
    secret_type: str = Field(default="api_key")
    agent_id: str | None = None
    ttl_seconds: int = Field(default=2592000, ge=300, le=31536000)
    rotation_interval: int | None = None
    metadata: dict[str, Any] | None = None


class RotateSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_value: str = Field(min_length=1)
    ttl_seconds: int | None = Field(default=None, ge=300, le=31536000)


class AccessSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)


@router.post("/v1/vault/secrets")
def post_store_secret(
    body: StoreSecretRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Store a new secret."""
    try:
        return store_secret(
            name=body.name,
            value=body.value,
            secret_type=body.secret_type,
            agent_id=body.agent_id,
            ttl_seconds=body.ttl_seconds,
            rotation_interval=body.rotation_interval,
            metadata=body.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/vault/secrets")
def get_list_secrets(
    agent_id: str | None = Query(default=None),
    secret_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List secrets (metadata only)."""
    items = list_secrets(
        agent_id=agent_id,
        secret_type=secret_type,
        status=status,
        limit=limit,
    )
    return {"total": len(items), "secrets": items}


# Static routes before parameterized ones
@router.get("/v1/vault/secrets/expiring")
def get_expiring(
    within_seconds: int = Query(default=86400, ge=60, le=2592000),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get secrets expiring within a time window."""
    items = get_expiring_secrets(within_seconds=within_seconds)
    return {"total": len(items), "secrets": items}


@router.get("/v1/vault/secrets/rotation-due")
def get_due_for_rotation(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get secrets overdue for rotation."""
    items = get_rotation_due()
    return {"total": len(items), "secrets": items}


@router.get("/v1/vault/rotation-history")
def get_history(
    secret_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get rotation history."""
    items = get_rotation_history(secret_id=secret_id, limit=limit)
    return {"total": len(items), "history": items}


# Parameterized routes after static ones
@router.get("/v1/vault/secrets/{secret_id}")
def get_secret_detail(
    secret_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get secret metadata."""
    try:
        return get_secret(secret_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/vault/secrets/{secret_id}/access")
def post_access_secret(
    secret_id: str,
    body: AccessSecretRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Record access to a secret."""
    try:
        return access_secret(secret_id, agent_id=body.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/vault/secrets/{secret_id}/rotate")
def post_rotate_secret(
    secret_id: str,
    body: RotateSecretRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Rotate a secret."""
    try:
        return rotate_secret(
            secret_id,
            new_value=body.new_value,
            ttl_seconds=body.ttl_seconds,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/vault/secrets/{secret_id}/revoke")
def post_revoke_secret(
    secret_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Revoke a secret."""
    try:
        return revoke_secret(secret_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
