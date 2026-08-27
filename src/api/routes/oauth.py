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

from src.api.auth import AuthContext, require_api_key
from src.identity.jwt_tokens import TOKEN_USE_OAUTH_CLIENT, issue_jwt
from src.identity.oauth_clients import OAUTH_CLIENT_STORE
from src.runtime.audit_streaming import EVENT_OAUTH_CLIENT_AUTHORITY_BOUND, emit_event
from src.protocol.mcp_server import is_allowed_mcp_resource, mcp_resource_url

router = APIRouter(tags=["oauth"])

_DEFAULT_ISSUER = "urn:agenthub:registry"
_SUPPORTED_GRANT_TYPES = frozenset({"client_credentials"})


def _base_url() -> str:
    return os.getenv("AGENTHUB_BASE_URL", "https://localhost:8000").rstrip("/")


# --- Well-Known Metadata ---


@router.get("/.well-known/oauth-protected-resource")
def get_protected_resource_metadata() -> dict[str, Any]:
    """MCP Protected Resource Metadata (RFC 9728)."""
    base = _base_url()
    return {
        "resource": mcp_resource_url(),
        "authorization_servers": [base],
        "scopes_supported": [
            "read",
            "write",
            "delegation.create",
            "discovery.search",
            "discovery.read",
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
            "discovery.read",
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
    grant_types: list[str] = Field(default_factory=lambda: ["client_credentials"], min_length=1, max_length=5)
    scope: str | None = Field(default=None, max_length=512)
    redirect_uris: list[str] = Field(default_factory=list, max_length=10)


class BindClientAuthorityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_secret: str = Field(min_length=1, max_length=512)


@router.post("/v1/oauth/register")
def post_register_client(
    request: RegisterClientRequest,
    context: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Dynamic client registration (RFC 7591)."""
    unsupported = sorted(set(request.grant_types) - _SUPPORTED_GRANT_TYPES)
    if unsupported:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client_metadata",
                "error_description": f"unsupported grant_type: {unsupported[0]}",
            },
        )
    requested_scopes = sorted(set((request.scope or "").split()))
    if any(not context.allows_scope(scope) for scope in requested_scopes):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "invalid_scope",
                "error_description": "requested scope exceeds registrar authority",
            },
        )
    try:
        result = OAUTH_CLIENT_STORE.register_client(
            client_name=request.client_name,
            grant_types=request.grant_types,
            scope=request.scope,
            redirect_uris=request.redirect_uris,
            owner=context.owner,
            tenant_id=context.tenant_id,
            authorized_scopes=context.scopes,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_client_metadata", "error_description": str(exc)},
        ) from exc
    return result


@router.post("/v1/oauth/clients/{client_id}/authority/register")
def post_bind_client_authority(
    client_id: str,
    request: BindClientAuthorityRequest,
    context: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Bind a pre-authority OAuth record after proving its client secret."""
    if not context.allows_scope("oauth.register"):
        raise HTTPException(status_code=403, detail="oauth.register scope is required")
    result = OAUTH_CLIENT_STORE.bind_legacy_client_authority(
        client_id=client_id,
        client_secret=request.client_secret,
        owner=context.owner,
        tenant_id=context.tenant_id,
        authorized_scopes=context.scopes,
    )
    if result is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "client authority binding failed"},
        )
    emit_event(
        event_type=EVENT_OAUTH_CLIENT_AUTHORITY_BOUND,
        actor=context.owner,
        resource=client_id,
        detail={
            "tenant_id": context.tenant_id,
            "authority_binding_id": result["authority_binding_id"],
        },
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
    resource: str = Form(default=""),
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

    registered_scopes = set(str(client.get("scope", "")).split())
    requested_scopes = set(scope.split()) if scope else set()
    unauthorized_scopes = requested_scopes - registered_scopes
    if unauthorized_scopes:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_scope",
                "error_description": "requested scope is not authorized for this client",
            },
        )
    granted_scopes = sorted(requested_scopes or registered_scopes)

    audience: str | None = None
    if resource:
        if not is_allowed_mcp_resource(resource):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_target",
                    "error_description": "requested resource is not served by this authorization server",
                },
            )
        audience = resource

    jwt_result = issue_jwt(
        subject=str(client["owner"]),
        agent_id=client_id,
        tenant_id=str(client["tenant_id"]),
        token_use=TOKEN_USE_OAUTH_CLIENT,
        scopes=granted_scopes or None,
        audience=audience,
        issuer=_DEFAULT_ISSUER,
        ttl_seconds=3600,
        extra_claims={"principal_type": "oauth_client"},
    )

    response: dict[str, Any] = {
        "access_token": jwt_result["token"],
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    if granted_scopes:
        response["scope"] = " ".join(granted_scopes)
    return response
