"""AAP-compliant JWT token endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.common.time import iso_from_epoch
from src.identity.jwt_constants import (
    DEFAULT_JWT_TTL_SECONDS,
    DEFAULT_ISSUER,
    MAX_JWT_TTL_SECONDS,
    MIN_JWT_TTL_SECONDS,
    VALID_OVERSIGHT_LEVELS,
)
from src.identity.jwt_tokens import get_jwks, issue_jwt, verify_jwt

router = APIRouter(prefix="/v1/identity/tokens", tags=["identity-tokens"])


# --- Request Models ---


class IssueJWTRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=256)
    scopes: list[str] = Field(default_factory=list, max_length=50)
    ttl_seconds: int = Field(default=DEFAULT_JWT_TTL_SECONDS, ge=MIN_JWT_TTL_SECONDS, le=MAX_JWT_TTL_SECONDS)
    audience: str | None = Field(default=None, max_length=512)
    agent_capabilities: list[str] | None = Field(default=None, max_length=50)
    task_binding: str | None = Field(default=None, max_length=256)
    oversight_level: str | None = Field(default=None, max_length=32)
    delegation_chain_id: str | None = Field(default=None, max_length=256)


class VerifyJWTRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=8192)
    audience: str | None = Field(default=None, max_length=512)
    require_agent_id: bool = Field(default=True)


# --- Endpoints ---


@router.post("/jwt")
def post_issue_jwt(
    request: IssueJWTRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if request.oversight_level and request.oversight_level not in VALID_OVERSIGHT_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"invalid oversight_level, must be one of: {sorted(VALID_OVERSIGHT_LEVELS)}",
        )
    try:
        result = issue_jwt(
            subject=owner,
            agent_id=request.agent_id,
            scopes=request.scopes,
            ttl_seconds=request.ttl_seconds,
            audience=request.audience,
            agent_capabilities=request.agent_capabilities,
            task_binding=request.task_binding,
            oversight_level=request.oversight_level,
            delegation_chain_id=request.delegation_chain_id,
        )
        return {
            "token": result["token"],
            "token_type": result["token_type"],
            "jti": result["jti"],
            "subject": result["subject"],
            "agent_id": result["agent_id"],
            "issuer": result["issuer"],
            "issued_at": iso_from_epoch(result["issued_at"]),
            "expires_at": iso_from_epoch(result["expires_at"]),
            "scopes": result["scopes"],
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/jwt/verify")
def post_verify_jwt(
    request: VerifyJWTRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        claims = verify_jwt(
            request.token,
            audience=request.audience,
            require_agent_id=request.require_agent_id,
        )
        return {
            "valid": True,
            "claims": claims,
        }
    except ValueError as exc:
        return {
            "valid": False,
            "error": str(exc),
        }


@router.get("/jwt/jwks")
def get_jwks_endpoint() -> dict[str, Any]:
    """Public JWKS endpoint — no authentication required."""
    return get_jwks()
