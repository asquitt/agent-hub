"""Authenticated MCP Streamable HTTP endpoint for capability discovery."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from src.api.auth import AuthContext
from src.protocol.mcp_server import (
    MCP_FALLBACK_PROTOCOL_VERSION,
    MCP_PROTOCOL_VERSION,
    dispatch_mcp_message,
    is_allowed_mcp_origin,
    is_supported_protocol_version,
    mcp_www_authenticate,
)


router = APIRouter(tags=["mcp"])


def _accepted_media_types(value: str) -> set[str]:
    accepted: set[str] = set()
    for item in value.split(","):
        parts = [part.strip().lower() for part in item.split(";")]
        if not parts[0]:
            continue
        quality = next((part for part in parts[1:] if part.startswith("q=")), None)
        if quality in {"q=0", "q=0.0"}:
            continue
        accepted.add(parts[0])
    return accepted


def _protocol_error(status_code: int, code: int, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}},
        headers={"MCP-Protocol-Version": MCP_PROTOCOL_VERSION},
    )


def _auth_context(request: Request) -> AuthContext | None:
    context = getattr(request.state, "agenthub_auth_context", None)
    return context if isinstance(context, AuthContext) else None


@router.post("/mcp")
async def post_mcp(request: Request) -> Response:
    if not is_allowed_mcp_origin(request.headers.get("Origin")):
        return _protocol_error(403, -32000, "Origin not allowed")

    accept = request.headers.get("Accept", "")
    accepted_media = _accepted_media_types(accept)
    if not {"application/json", "text/event-stream"}.issubset(accepted_media):
        return _protocol_error(406, -32000, "Accept must include application/json and text/event-stream")

    content_type = request.headers.get("Content-Type", "")
    if content_type.partition(";")[0].strip().lower() != "application/json":
        return _protocol_error(415, -32700, "Content-Type must be application/json")

    context = _auth_context(request)
    if context is None:
        response = _protocol_error(401, -32001, "Authentication required")
        response.headers["WWW-Authenticate"] = mcp_www_authenticate()
        return response

    try:
        message: Any = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _protocol_error(400, -32700, "Parse error")

    method = message.get("method") if isinstance(message, dict) else None
    if method != "initialize":
        version = request.headers.get("MCP-Protocol-Version", MCP_FALLBACK_PROTOCOL_VERSION)
        if not is_supported_protocol_version(version):
            return _protocol_error(400, -32602, "Unsupported MCP protocol version")

    result = dispatch_mcp_message(
        message,
        tenant_id=context.tenant_id,
        allows_scope=context.allows_scope,
    )
    headers = {"MCP-Protocol-Version": result.protocol_version}
    if result.payload is None:
        return Response(status_code=result.status_code, headers=headers)
    return JSONResponse(status_code=result.status_code, content=result.payload, headers=headers)


@router.get("/mcp")
def get_mcp(request: Request) -> Response:
    if not is_allowed_mcp_origin(request.headers.get("Origin")):
        return _protocol_error(403, -32000, "Origin not allowed")
    return Response(status_code=405, headers={"Allow": "POST", "MCP-Protocol-Version": MCP_PROTOCOL_VERSION})


@router.delete("/mcp")
def delete_mcp(request: Request) -> Response:
    if not is_allowed_mcp_origin(request.headers.get("Origin")):
        return _protocol_error(403, -32000, "Origin not allowed")
    return Response(status_code=405, headers={"Allow": "POST", "MCP-Protocol-Version": MCP_PROTOCOL_VERSION})
