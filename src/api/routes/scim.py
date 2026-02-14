"""SCIM 2.0 provisioning routes for agent identities."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.identity.scim import (
    scim_bulk_operations,
    scim_create_user,
    scim_delete_user,
    scim_get_user,
    scim_list_users,
    scim_patch_user,
    scim_replace_user,
    scim_resource_types,
    scim_schemas,
    scim_service_provider_config,
)

router = APIRouter(tags=["scim"])


class ScimPatchOp(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: str = Field(pattern=r"^(add|remove|replace)$")
    path: str = ""
    value: Any = None


class ScimPatchRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"])
    Operations: list[ScimPatchOp]


class ScimBulkOp(BaseModel):
    model_config = ConfigDict(extra="allow")
    method: str
    path: str
    bulkId: str = ""
    data: dict[str, Any] | None = None


class ScimBulkRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"])
    Operations: list[ScimBulkOp]


# Service discovery endpoints (no auth required per SCIM spec)


@router.get("/scim/v2/ServiceProviderConfig")
def get_service_provider_config() -> dict[str, Any]:
    return scim_service_provider_config()


@router.get("/scim/v2/Schemas")
def get_schemas() -> dict[str, Any]:
    return scim_schemas()


@router.get("/scim/v2/ResourceTypes")
def get_resource_types() -> dict[str, Any]:
    return scim_resource_types()


# User (Agent) CRUD


@router.get("/scim/v2/Users")
def get_users(
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=1, le=200),
    filter: str | None = Query(default=None),
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    return scim_list_users(
        owner=caller,
        start_index=startIndex,
        count=count,
        filter_expr=filter,
    )


@router.get("/scim/v2/Users/{agent_id}")
def get_user(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return scim_get_user(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/scim/v2/Users", status_code=201)
def post_user(
    body: dict[str, Any],
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return scim_create_user(scim_resource=body, owner=caller)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/scim/v2/Users/{agent_id}")
def put_user(
    agent_id: str,
    body: dict[str, Any],
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return scim_replace_user(agent_id=agent_id, scim_resource=body)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/scim/v2/Users/{agent_id}")
def patch_user(
    agent_id: str,
    body: ScimPatchRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        ops = [{"op": o.op, "path": o.path, "value": o.value} for o in body.Operations]
        return scim_patch_user(agent_id=agent_id, operations=ops)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/scim/v2/Users/{agent_id}", status_code=204)
def delete_user(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> Response:
    try:
        scim_delete_user(agent_id)
        return Response(status_code=204)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# Bulk operations


@router.post("/scim/v2/Bulk")
def post_bulk(
    body: ScimBulkRequest,
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    ops = [{"method": o.method, "path": o.path, "bulkId": o.bulkId, "data": o.data or {}} for o in body.Operations]
    return scim_bulk_operations(operations=ops, owner=caller)
