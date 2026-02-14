"""Consent and authorization registry routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.consent_registry import (
    check_consent,
    get_audit_trail,
    get_consent,
    get_consent_stats,
    grant_consent,
    list_consents,
    revoke_consent,
)

router = APIRouter(tags=["consent"])


class GrantConsentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    scopes: list[str] = Field(min_length=1)
    purpose: str = ""
    ttl_seconds: int | None = Field(default=None, ge=60)
    conditions: dict[str, Any] | None = None


class CheckConsentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    scope: str = Field(min_length=1)


@router.post("/v1/consents")
def post_grant(
    body: GrantConsentRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Grant consent from a principal to an agent."""
    try:
        return grant_consent(
            principal_id=body.principal_id,
            agent_id=body.agent_id,
            scopes=body.scopes,
            purpose=body.purpose,
            ttl_seconds=body.ttl_seconds,
            conditions=body.conditions,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/consents")
def get_list(
    principal_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List consents."""
    items = list_consents(
        principal_id=principal_id,
        agent_id=agent_id,
        status=status,
        limit=limit,
    )
    return {"total": len(items), "consents": items}


# Static routes before parameterized
@router.get("/v1/consents/stats")
def get_stats(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get consent statistics."""
    return get_consent_stats()


@router.post("/v1/consents/check")
def post_check(
    body: CheckConsentRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check if consent exists for a scope."""
    return check_consent(
        principal_id=body.principal_id,
        agent_id=body.agent_id,
        scope=body.scope,
    )


@router.get("/v1/consents/audit-trail")
def get_audit(
    principal_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get consent audit trail."""
    items = get_audit_trail(
        principal_id=principal_id,
        agent_id=agent_id,
        limit=limit,
    )
    return {"total": len(items), "trail": items}


@router.get("/v1/consents/{consent_id}")
def get_consent_detail(
    consent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get consent details."""
    try:
        return get_consent(consent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/consents/{consent_id}/revoke")
def post_revoke(
    consent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Revoke a consent grant."""
    try:
        return revoke_consent(consent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
