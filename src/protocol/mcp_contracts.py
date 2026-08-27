"""Canonical MCP tool argument contracts shared by declarations and execution."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DiscoveryConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    max_cost_usd: float | None = Field(default=None, ge=0)
    max_latency_ms: int | None = Field(default=None, gt=0)
    min_trust_score: float | None = Field(default=None, ge=0, le=1)
    required_permissions: list[str] = Field(default_factory=list)
    allowed_protocols: list[str] = Field(default_factory=list)


class SearchArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=2)
    constraints: DiscoveryConstraints = Field(default_factory=DiscoveryConstraints)


class ManifestArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1)
    version: str | None = Field(default=None, min_length=1)


class CompatibilityArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    my_schema: dict[str, Any]
    agent_id: str = Field(min_length=1)


MCP_TOOL_ARGUMENT_MODELS: dict[str, type[BaseModel]] = {
    "search_capabilities": SearchArguments,
    "get_agent_manifest": ManifestArguments,
    "check_compatibility": CompatibilityArguments,
}


def mcp_tool_input_schema(name: str) -> dict[str, Any]:
    """Return the runtime model's JSON Schema for an advertised MCP tool."""
    return MCP_TOOL_ARGUMENT_MODELS[name].model_json_schema()
