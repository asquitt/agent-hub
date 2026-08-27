"""Stateless MCP Streamable HTTP dispatch over AgentHub discovery services."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import os
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.discovery.service import DISCOVERY_SERVICE, mcp_tool_declarations
from src.protocol.mcp_contracts import (
    CompatibilityArguments,
    ManifestArguments,
    SearchArguments,
)
from src.registry.store import STORE


MCP_PROTOCOL_VERSION = "2025-11-25"
MCP_FALLBACK_PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_MCP_PROTOCOL_VERSIONS = frozenset({MCP_PROTOCOL_VERSION, MCP_FALLBACK_PROTOCOL_VERSION})

_TOOL_SCOPES = {
    "search_capabilities": "discovery.search",
    "get_agent_manifest": "discovery.read",
    "check_compatibility": "discovery.search",
}


class _Implementation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    title: str | None = None
    version: str = Field(min_length=1)
    description: str | None = None
    websiteUrl: str | None = None
    icons: list[dict[str, Any]] | None = None


class _InitializeParams(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    protocolVersion: str = Field(min_length=1)
    capabilities: dict[str, Any]
    clientInfo: _Implementation
    meta: dict[str, Any] = Field(default_factory=dict, alias="_meta")


class _ToolCallParams(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict, alias="_meta")


@dataclass(frozen=True)
class MCPDispatchResult:
    payload: dict[str, Any] | None
    status_code: int
    protocol_version: str


def agenthub_base_url() -> str:
    return os.getenv("AGENTHUB_BASE_URL", "https://localhost:8000").rstrip("/")


def mcp_resource_url() -> str:
    return f"{agenthub_base_url()}/mcp"


def mcp_resource_metadata_url() -> str:
    return f"{agenthub_base_url()}/.well-known/oauth-protected-resource"


def mcp_www_authenticate() -> str:
    return (
        f'Bearer resource_metadata="{mcp_resource_metadata_url()}", '
        'scope="discovery.read discovery.search"'
    )


def is_allowed_mcp_resource(resource: str) -> bool:
    return bool(resource) and resource == mcp_resource_url()


def _origin(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def allowed_mcp_origins() -> frozenset[str]:
    allowed = {_origin(agenthub_base_url())}
    raw = os.getenv("AGENTHUB_MCP_ALLOWED_ORIGINS_JSON", "[]")
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError:
        configured = []
    if isinstance(configured, list):
        allowed.update(_origin(str(item).strip()) for item in configured)
    return frozenset(item for item in allowed if item is not None)


def is_allowed_mcp_origin(origin: str | None) -> bool:
    if origin is None:
        return True
    normalized = _origin(origin.strip())
    return normalized is not None and normalized in allowed_mcp_origins()


def is_supported_protocol_version(version: str) -> bool:
    return version in SUPPORTED_MCP_PROTOCOL_VERSIONS


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _jsonrpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _tool_result(output: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(output, sort_keys=True, separators=(",", ":")),
            }
        ],
        "structuredContent": output,
        "isError": False,
    }


def _tool_error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _visible_tools(allows_scope: Callable[[str], bool]) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    for declaration in mcp_tool_declarations():
        name = str(declaration.get("name", ""))
        required_scope = _TOOL_SCOPES.get(name)
        if required_scope is None or not allows_scope(required_scope):
            continue
        tools.append(
            {
                **declaration,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
                "execution": {"taskSupport": "forbidden"},
            }
        )
    return tools


def _execute_tool(
    *,
    name: str,
    arguments: dict[str, Any],
    tenant_id: str,
    allows_scope: Callable[[str], bool],
) -> dict[str, Any]:
    required_scope = _TOOL_SCOPES.get(name)
    if required_scope is None:
        raise KeyError(name)
    if not allows_scope(required_scope):
        return _tool_error("insufficient scope")

    try:
        if name == "search_capabilities":
            parsed = SearchArguments.model_validate(arguments)
            return _tool_result(
                DISCOVERY_SERVICE.semantic_discovery(
                    query=parsed.query,
                    constraints=parsed.constraints.model_dump(exclude_none=True),
                    tenant_id=tenant_id,
                )
            )

        if name == "get_agent_manifest":
            parsed = ManifestArguments.model_validate(arguments)
            agent = STORE.get_agent(parsed.agent_id, tenant_id=tenant_id)
            if parsed.version is not None:
                record = STORE.get_version(parsed.agent_id, parsed.version, tenant_id=tenant_id)
            else:
                if not agent.versions:
                    return _tool_error("agent has no published version")
                record = agent.versions[-1]
            return _tool_result(
                {
                    "agent_id": parsed.agent_id,
                    "version": record.version,
                    "manifest": record.manifest,
                }
            )

        parsed = CompatibilityArguments.model_validate(arguments)
        return _tool_result(
            DISCOVERY_SERVICE.compatibility_report(
                my_schema=parsed.my_schema,
                agent_id=parsed.agent_id,
                tenant_id=tenant_id,
            )
        )
    except ValidationError:
        return _tool_error("invalid tool arguments")
    except KeyError:
        return _tool_error("agent not found")
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return _tool_error("tool execution failed")


def dispatch_mcp_message(
    message: Any,
    *,
    tenant_id: str,
    allows_scope: Callable[[str], bool],
) -> MCPDispatchResult:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return MCPDispatchResult(_jsonrpc_error(None, -32600, "Invalid Request"), 400, MCP_PROTOCOL_VERSION)

    method = message.get("method")
    if not isinstance(method, str) or not method:
        return MCPDispatchResult(_jsonrpc_error(None, -32600, "Invalid Request"), 400, MCP_PROTOCOL_VERSION)

    request_id = message.get("id")
    is_notification = "id" not in message
    if not is_notification and (
        isinstance(request_id, bool) or not isinstance(request_id, (int, str))
    ):
        return MCPDispatchResult(_jsonrpc_error(None, -32600, "Invalid Request"), 400, MCP_PROTOCOL_VERSION)
    params = message.get("params", {})
    if not isinstance(params, dict):
        if is_notification:
            return MCPDispatchResult(None, 202, MCP_PROTOCOL_VERSION)
        return MCPDispatchResult(_jsonrpc_error(request_id, -32602, "Invalid params"), 200, MCP_PROTOCOL_VERSION)

    if is_notification:
        return MCPDispatchResult(None, 202, MCP_PROTOCOL_VERSION)

    if method == "initialize":
        try:
            parsed = _InitializeParams.model_validate(params)
        except ValidationError:
            return MCPDispatchResult(_jsonrpc_error(request_id, -32602, "Invalid params"), 200, MCP_PROTOCOL_VERSION)
        negotiated = (
            parsed.protocolVersion
            if is_supported_protocol_version(parsed.protocolVersion)
            else MCP_PROTOCOL_VERSION
        )
        return MCPDispatchResult(
            _jsonrpc_result(
                request_id,
                {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "agenthub-discovery",
                        "version": "0.1.0",
                        "description": "Policy-governed AgentHub capability discovery.",
                    },
                    "instructions": "Use tools to discover and inspect policy-compliant agent capabilities.",
                },
            ),
            200,
            negotiated,
        )

    if method == "ping":
        return MCPDispatchResult(_jsonrpc_result(request_id, {}), 200, MCP_PROTOCOL_VERSION)

    if method == "tools/list":
        return MCPDispatchResult(
            _jsonrpc_result(request_id, {"tools": _visible_tools(allows_scope)}),
            200,
            MCP_PROTOCOL_VERSION,
        )

    if method == "tools/call":
        try:
            call = _ToolCallParams.model_validate(params)
        except ValidationError:
            return MCPDispatchResult(_jsonrpc_error(request_id, -32602, "Invalid params"), 200, MCP_PROTOCOL_VERSION)
        if call.name not in _TOOL_SCOPES:
            return MCPDispatchResult(
                _jsonrpc_error(request_id, -32602, f"Unknown tool: {call.name}"),
                200,
                MCP_PROTOCOL_VERSION,
            )
        return MCPDispatchResult(
            _jsonrpc_result(
                request_id,
                _execute_tool(
                    name=call.name,
                    arguments=call.arguments,
                    tenant_id=tenant_id,
                    allows_scope=allows_scope,
                ),
            ),
            200,
            MCP_PROTOCOL_VERSION,
        )

    return MCPDispatchResult(
        _jsonrpc_error(request_id, -32601, "Method not found"),
        200,
        MCP_PROTOCOL_VERSION,
    )
