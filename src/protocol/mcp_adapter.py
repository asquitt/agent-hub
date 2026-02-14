"""MCP Protocol Adapter — canonical contract ↔ MCP tool-use translation.

Translates between AgentHub's canonical internal contract format
and the Model Context Protocol (MCP) tool-use format.
"""
from __future__ import annotations

import json
from typing import Any

from src.protocol.types import CanonicalCapability, CanonicalToolCall, CanonicalToolResult


def capability_to_mcp_tool(capability: CanonicalCapability) -> dict[str, Any]:
    """Convert a canonical capability to an MCP tool definition.

    MCP Tool schema: { name, description, inputSchema }
    """
    tool: dict[str, Any] = {
        "name": capability.get("id", "unknown"),
        "description": capability.get("description", ""),
    }

    input_schema = capability.get("input_schema")
    if input_schema:
        tool["inputSchema"] = input_schema
    else:
        tool["inputSchema"] = {"type": "object", "properties": {}}

    return tool


def capabilities_to_mcp_tools(capabilities: list[CanonicalCapability]) -> list[dict[str, Any]]:
    """Convert a list of canonical capabilities to MCP tool definitions."""
    return [capability_to_mcp_tool(cap) for cap in capabilities]


def mcp_tool_to_capability(tool: dict[str, Any]) -> CanonicalCapability:
    """Convert an MCP tool definition to a canonical capability."""
    cap: CanonicalCapability = {
        "id": str(tool.get("name", "unknown")),
        "name": str(tool.get("name", "unknown")),
        "description": str(tool.get("description", "")),
        "category": "tool",
        "protocols": ["MCP"],
        "idempotency_key_required": False,
        "side_effect_level": "unknown",
    }

    input_schema = tool.get("inputSchema")
    if isinstance(input_schema, dict):
        cap["input_schema"] = input_schema

    return cap


def to_mcp_tool_call(canonical: CanonicalToolCall) -> dict[str, Any]:
    """Convert a canonical tool call to MCP tool_use format.

    MCP tool_use: { type: "tool_use", id, name, input }
    """
    return {
        "type": "tool_use",
        "id": canonical.get("idempotency_key", ""),
        "name": canonical.get("tool_name", ""),
        "input": canonical.get("tool_input", {}),
    }


def from_mcp_tool_call(mcp_call: dict[str, Any]) -> CanonicalToolCall:
    """Convert an MCP tool_use to a canonical tool call."""
    call: CanonicalToolCall = {
        "tool_name": str(mcp_call.get("name", "")),
        "tool_input": mcp_call.get("input", {}),
    }

    call_id = mcp_call.get("id")
    if call_id:
        call["idempotency_key"] = str(call_id)

    return call


def to_mcp_tool_result(canonical: CanonicalToolResult) -> dict[str, Any]:
    """Convert a canonical tool result to MCP tool_result format.

    MCP tool_result: { type: "tool_result", tool_use_id, content, is_error }
    """
    content: list[dict[str, Any]] = []

    output = canonical.get("output")
    if output is not None:
        if isinstance(output, str):
            content.append({"type": "text", "text": output})
        elif isinstance(output, dict):
            content.append({"type": "text", "text": json.dumps(output)})
        elif isinstance(output, list):
            content.append({"type": "text", "text": json.dumps(output)})
        else:
            content.append({"type": "text", "text": str(output)})

    error = canonical.get("error")
    if error:
        content.append({"type": "text", "text": f"Error: {error}"})

    return {
        "type": "tool_result",
        "tool_use_id": canonical.get("metadata", {}).get("call_id", ""),
        "content": content,
        "is_error": canonical.get("is_error", False),
    }


def from_mcp_tool_result(mcp_result: dict[str, Any]) -> CanonicalToolResult:
    """Convert an MCP tool_result to a canonical tool result."""
    content = mcp_result.get("content", [])
    text_parts: list[str] = []

    for item in content if isinstance(content, list) else []:
        if isinstance(item, dict) and item.get("type") == "text":
            text_parts.append(str(item.get("text", "")))

    output_text = "\n".join(text_parts)

    # Try to parse as JSON
    output: Any = output_text
    try:
        output = json.loads(output_text)
    except (json.JSONDecodeError, TypeError):
        pass

    is_error = bool(mcp_result.get("is_error", False))
    result: CanonicalToolResult = {
        "tool_name": "",
        "output": output,
        "is_error": is_error,
        "error": output_text if is_error else None,
        "metadata": {"call_id": mcp_result.get("tool_use_id", "")},
    }

    return result


def build_mcp_list_tools_response(capabilities: list[CanonicalCapability]) -> dict[str, Any]:
    """Build an MCP tools/list response from canonical capabilities."""
    return {
        "tools": capabilities_to_mcp_tools(capabilities),
    }
