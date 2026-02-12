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


class AgentForkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    namespace: str = Field(pattern=r"^@[a-z0-9][a-z0-9_-]{1,62}$")
    new_slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class AgentVersionResponse(BaseModel):
    version: str
    manifest: dict[str, Any]
    eval_summary: dict[str, Any]


class TrustUsageEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    cost_usd: float = Field(ge=0)
    latency_ms: float = Field(ge=0)


class DiscoverySearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=2)
    constraints: dict[str, Any] | None = None


class ContractMatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    constraints: dict[str, Any] | None = None


class CompatibilityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    my_schema: dict[str, Any]
    agent_id: str


class DelegationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requester_agent_id: str
    delegate_agent_id: str
    task_spec: str = Field(min_length=3)
    estimated_cost_usd: float = Field(gt=0)
    max_budget_usd: float = Field(gt=0)
    simulated_actual_cost_usd: float | None = Field(default=None, ge=0)
    auto_reauthorize: bool = True
    min_delegate_trust_score: float | None = Field(default=None, ge=0, le=1)
    required_permissions: list[str] = []
    metering_events: list[dict[str, Any]] | None = None


class LeaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requester_agent_id: str
    capability_ref: str = Field(min_length=3)
    ttl_seconds: int = Field(default=3600, gt=0, le=86400)


class LeasePromoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signature: str = Field(min_length=8)
    attestation_hash: str = Field(min_length=12)
    policy_approved: bool = False
    approval_ticket: str = Field(min_length=6)
    compatibility_verified: bool = False


class LeaseRollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3)


class KnowledgeContributeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=4)
    content: str = Field(min_length=20)
    tags: list[str] = Field(default_factory=list, max_length=12)
    source_uri: str = Field(min_length=8)
    contributor: str = Field(min_length=2)
    base_confidence: float = Field(default=0.65, ge=0, le=1)


class KnowledgeValidationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: bool
    rationale: str = Field(min_length=4)


class BillingSubscriptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(min_length=3)
    plan_id: str = Field(min_length=2)
    monthly_fee_usd: float = Field(ge=0)
    included_units: int = Field(default=0, ge=0)


class BillingUsageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(min_length=3)
    meter: str = Field(min_length=2)
    quantity: float = Field(gt=0)
    unit_price_usd: float = Field(ge=0)


class BillingInvoiceGenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(min_length=3)


class BillingRefundRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount_usd: float = Field(gt=0)
    reason: str = Field(min_length=3)


class FederatedExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain_id: str = Field(min_length=3)
    domain_token: str = Field(min_length=8)
    task_spec: str = Field(min_length=3)
    payload: dict[str, Any]
    policy_context: dict[str, Any]
    estimated_cost_usd: float = Field(gt=0)
    max_budget_usd: float = Field(gt=0)


class MarketplaceListingCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_ref: str = Field(min_length=3)
    unit_price_usd: float = Field(ge=0)
    max_units_per_purchase: int = Field(gt=0)
    policy_purchase_limit_usd: float = Field(gt=0)


class MarketplacePurchaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    listing_id: str = Field(min_length=8)
    units: int = Field(gt=0)
    max_total_usd: float = Field(gt=0)
    policy_approved: bool = False


class MarketplaceSettlementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    units_used: int = Field(gt=0)
