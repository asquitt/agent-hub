"""Credential binding rules routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.credential_binding import (
    create_binding,
    deactivate_binding,
    get_binding,
    get_binding_stats,
    get_validation_log,
    list_bindings,
    validate_binding,
)

router = APIRouter(tags=["credential-binding"])


class CreateBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    binding_type: str = Field(min_length=1)
    constraints: dict[str, Any]
    enforce: bool = True
    description: str = ""


class ValidateBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    context: dict[str, Any]


@router.post("/v1/credential-bindings")
def post_create(
    body: CreateBindingRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a credential binding rule."""
    try:
        return create_binding(
            credential_id=body.credential_id,
            agent_id=body.agent_id,
            binding_type=body.binding_type,
            constraints=body.constraints,
            enforce=body.enforce,
            description=body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/credential-bindings")
def get_list(
    credential_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    binding_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List bindings."""
    items = list_bindings(
        credential_id=credential_id,
        agent_id=agent_id,
        binding_type=binding_type,
        limit=limit,
    )
    return {"total": len(items), "bindings": items}


# Static routes before parameterized
@router.get("/v1/credential-bindings/stats")
def get_stats(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get binding statistics."""
    return get_binding_stats()


@router.post("/v1/credential-bindings/validate")
def post_validate(
    body: ValidateBindingRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Validate credential usage against bindings."""
    return validate_binding(
        credential_id=body.credential_id,
        agent_id=body.agent_id,
        context=body.context,
    )


@router.get("/v1/credential-bindings/validations")
def get_validations(
    credential_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get validation log."""
    items = get_validation_log(
        credential_id=credential_id,
        agent_id=agent_id,
        limit=limit,
    )
    return {"total": len(items), "validations": items}


@router.get("/v1/credential-bindings/{binding_id}")
def get_detail(
    binding_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get binding details."""
    try:
        return get_binding(binding_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/credential-bindings/{binding_id}/deactivate")
def post_deactivate(
    binding_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Deactivate a binding rule."""
    try:
        return deactivate_binding(binding_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
