"""MCP Authorization Server — OAuth 2.1 endpoints.

Implements:
- Protected Resource Metadata (PRM) at /.well-known/oauth-protected-resource
- Authorization Server Metadata at /.well-known/oauth-authorization-server
- Token endpoint (client_credentials grant) at /v1/oauth/token
- Dynamic client registration at /v1/oauth/register
"""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.identity.jwt_tokens import issue_jwt
from src.identity.oauth_clients import OAUTH_CLIENT_STORE

router = APIRouter(tags=["oauth"])

_DEFAULT_ISSUER = "urn:agenthub:registry"


def _base_url() -> str:
    return os.getenv("AGENTHUB_BASE_URL", "https://localhost:8000").rstrip("/")


# --- Well-Known Metadata ---


@router.get("/.well-known/oauth-protected-resource")
def get_protected_resource_metadata() -> dict[str, Any]:
    """MCP Protected Resource Metadata (RFC 9728)."""
    base = _base_url()
    return {
        "resource": base,
        "authorization_servers": [base],
        "scopes_supported": [
            "read",
            "write",
            "delegation.create",
            "discovery.search",
            "runtime.execute",
        ],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base}/docs",
    }


@router.get("/.well-known/oauth-authorization-server")
def get_authorization_server_metadata() -> dict[str, Any]:
    """OAuth 2.1 Authorization Server Metadata (RFC 8414)."""
    base = _base_url()
    return {
        "issuer": _DEFAULT_ISSUER,
        "token_endpoint": f"{base}/v1/oauth/token",
        "registration_endpoint": f"{base}/v1/oauth/register",
        "jwks_uri": f"{base}/v1/identity/tokens/jwt/jwks",
        "scopes_supported": [
            "read",
            "write",
            "delegation.create",
            "discovery.search",
            "runtime.execute",
        ],
        "response_types_supported": [],
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "service_documentation": f"{base}/docs",
        "code_challenge_methods_supported": [],
    }


# --- Dynamic Client Registration ---


class RegisterClientRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_name: str = Field(min_length=1, max_length=256)
    grant_types: list[str] = Field(default_factory=lambda: ["client_credentials"], max_length=5)
    scope: str | None = Field(default=None, max_length=512)
    redirect_uris: list[str] = Field(default_factory=list, max_length=10)


@router.post("/v1/oauth/register")
def post_register_client(
    request: RegisterClientRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Dynamic client registration (RFC 7591)."""
    for gt in request.grant_types:
        if gt not in {"client_credentials", "authorization_code", "refresh_token"}:
            raise HTTPException(status_code=400, detail=f"unsupported grant_type: {gt}")
    result = OAUTH_CLIENT_STORE.register_client(
        client_name=request.client_name,
        grant_types=request.grant_types,
        scope=request.scope,
        redirect_uris=request.redirect_uris,
    )
    return result


# --- Token Endpoint ---


@router.post("/v1/oauth/token")
def post_token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
    scope: str = Form(default=""),
) -> dict[str, Any]:
    """OAuth 2.1 Token Endpoint — client_credentials grant."""
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_grant_type", "error_description": f"grant_type '{grant_type}' is not supported"},
        )

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "client_id and client_secret are required"},
        )

    client = OAUTH_CLIENT_STORE.authenticate_client(client_id, client_secret)
    if client is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "invalid client credentials"},
        )

    if "client_credentials" not in client.get("grant_types", []):
        raise HTTPException(
            status_code=400,
            detail={"error": "unauthorized_client", "error_description": "client not authorized for client_credentials grant"},
        )

    requested_scopes = [s.strip() for s in scope.split() if s.strip()] if scope else []

    jwt_result = issue_jwt(
        subject=client_id,
        agent_id=client_id,
        scopes=requested_scopes or None,
        issuer=_DEFAULT_ISSUER,
        ttl_seconds=3600,
    )

    response: dict[str, Any] = {
        "access_token": jwt_result["token"],
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    if requested_scopes:
        response["scope"] = " ".join(sorted(requested_scopes))
    return response
