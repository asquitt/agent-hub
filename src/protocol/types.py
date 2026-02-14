"""Canonical contract types — protocol-agnostic tool/capability representations."""
from __future__ import annotations

from typing import Any, TypedDict


class CanonicalCapability(TypedDict, total=False):
    """AgentHub canonical capability representation."""
    id: str
    name: str
    description: str
    category: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    protocols: list[str]
    idempotency_key_required: bool
    side_effect_level: str


class CanonicalToolCall(TypedDict, total=False):
    """AgentHub canonical tool call representation."""
    tool_name: str
    tool_input: dict[str, Any]
    agent_id: str
    sandbox_id: str
    idempotency_key: str


class CanonicalToolResult(TypedDict, total=False):
    """AgentHub canonical tool result representation."""
    tool_name: str
    output: Any
    error: str | None
    is_error: bool
    metadata: dict[str, Any]
