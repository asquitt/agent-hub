"""AAP-compliant JWT token endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import AuthContext, require_api_key
from src.common.time import iso_from_epoch
from src.identity.constants import STATUS_ACTIVE
from src.identity.jwt_constants import (
    DEFAULT_JWT_TTL_SECONDS,
    DEFAULT_ISSUER,
    MAX_JWT_TTL_SECONDS,
    MIN_JWT_TTL_SECONDS,
    VALID_OVERSIGHT_LEVELS,
)
from src.identity.jwt_tokens import get_jwks, issue_jwt, verify_jwt
from src.identity.storage import get_agent_identity

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
    delegation_chain: list[dict[str, Any]] | None = None
    behavioral_attestation: dict[str, Any] | None = None
    runtime_constraints: dict[str, Any] | None = None
    peer_attestations: list[dict[str, Any]] | None = None


class VerifyJWTRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=8192)
    audience: str | None = Field(default=None, max_length=512)
    require_agent_id: bool = Field(default=True)


# --- Endpoints ---


def _authorize_jwt_issuance(request: IssueJWTRequest, context: AuthContext) -> list[str]:
    if not isinstance(context, AuthContext):
        raise HTTPException(status_code=403, detail="JWT issuance requires an authorization context")

    try:
        identity = get_agent_identity(request.agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent identity not found") from exc

    if identity["status"] != STATUS_ACTIVE:
        raise HTTPException(status_code=403, detail="agent identity is not active")
    if identity["owner"] != context.owner:
        raise HTTPException(status_code=403, detail="agent identity belongs to another owner")
    if context.agent_id is not None and context.agent_id != request.agent_id:
        raise HTTPException(status_code=403, detail="agent principal cannot issue a token for another agent")

    requested_scopes = sorted({scope.strip() for scope in request.scopes if scope.strip()})
    is_platform_admin = "admin" in context.roles
    if not is_platform_admin and any(not context.allows_scope(scope) for scope in requested_scopes):
        raise HTTPException(status_code=403, detail="requested scopes exceed issuer authority")
    return requested_scopes


@router.post("/jwt")
def post_issue_jwt(
    request: IssueJWTRequest,
    context: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    requested_scopes = _authorize_jwt_issuance(request, context)
    if request.oversight_level and request.oversight_level not in VALID_OVERSIGHT_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"invalid oversight_level, must be one of: {sorted(VALID_OVERSIGHT_LEVELS)}",
        )
    try:
        result = issue_jwt(
            subject=context.owner,
            agent_id=request.agent_id,
            scopes=requested_scopes,
            ttl_seconds=request.ttl_seconds,
            audience=request.audience,
            agent_capabilities=request.agent_capabilities,
            task_binding=request.task_binding,
            oversight_level=request.oversight_level,
            delegation_chain_id=request.delegation_chain_id,
            delegation_chain=request.delegation_chain,
            behavioral_attestation=request.behavioral_attestation,
            runtime_constraints=request.runtime_constraints,
            peer_attestations=request.peer_attestations,
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
