from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ConfigDict, field_validator


class PaginationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["cursor", "offset"] = "offset"
    cursor: str | None = None
    offset: int | None = 0
    limit: int = Field(default=20, ge=1, le=100)

    @field_validator("cursor")
    @classmethod
    def validate_cursor(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith("idx:"):
            raise ValueError("cursor must follow idx:<n> format")
        return value


class SearchFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_latency_ms: int | None = Field(default=None, gt=0)
    max_cost_usd: float | None = Field(default=None, ge=0)
    min_trust_score: float | None = Field(default=None, ge=0, le=1)
    required_permissions: list[str] = []
    allowed_protocols: list[Literal["MCP", "A2A", "HTTP", "INTERNAL"]] = []
    compatibility_mode: Literal["exact", "backward_compatible"] = "backward_compatible"


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=2)
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    filters: SearchFilters | None = None
    ranking_weights: dict[str, float] | None = None
    pagination: PaginationRequest | None = None


class MatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    filters: SearchFilters | None = None
    pagination: PaginationRequest | None = None


class RecommendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_description: str = Field(min_length=4)
    current_capability_ids: list[str] = Field(min_length=1)
    filters: SearchFilters | None = None
    ranking_weights: dict[str, float] | None = None
    pagination: PaginationRequest | None = None


class AgentRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    namespace: str = Field(pattern=r"^@[a-z0-9][a-z0-9_-]{1,62}$")
    manifest: dict[str, Any]


class AgentUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]


class AgentVersionResponse(BaseModel):
    version: str
    manifest: dict[str, Any]
    eval_summary: dict[str, Any]
