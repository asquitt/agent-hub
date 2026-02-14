"""Intent-aware access logging routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.intent_logging import (
    evaluate_intent,
    get_intent_summary,
    list_intent_policies,
    log_access,
    query_access_log,
    set_intent_policy,
)

router = APIRouter(tags=["intent-logging"])


class LogAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str | None = None
    intent: str = "unknown"
    justification: str = ""
    outcome: str = "allowed"
    metadata: dict[str, Any] | None = None


class EvaluateIntentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    intent: str = Field(min_length=1)
    justification: str = ""


class SetIntentPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str | None = None
    allowed_intents: list[str] | None = None
    required_justification: bool = False
    max_risk_score: int = Field(default=100, ge=0, le=100)


@router.post("/v1/intent/log")
def post_log_access(
    body: LogAccessRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Log an access event with intent metadata."""
    return log_access(
        agent_id=body.agent_id,
        action=body.action,
        resource=body.resource,
        intent=body.intent,
        justification=body.justification,
        outcome=body.outcome,
        metadata=body.metadata,
    )


@router.get("/v1/intent/log")
def get_access_log(
    agent_id: str | None = Query(default=None),
    intent: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Query the intent-aware access log."""
    entries = query_access_log(
        agent_id=agent_id,
        intent=intent,
        action=action,
        outcome=outcome,
        limit=limit,
    )
    return {"total": len(entries), "entries": entries}


@router.get("/v1/intent/summary/{agent_id}")
def get_agent_intent_summary(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get intent summary for an agent."""
    return get_intent_summary(agent_id)


@router.post("/v1/intent/evaluate")
def post_evaluate_intent(
    body: EvaluateIntentRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Evaluate if an intent is allowed by policy."""
    return evaluate_intent(
        agent_id=body.agent_id,
        intent=body.intent,
        justification=body.justification,
    )


@router.post("/v1/intent/policies")
def post_set_intent_policy(
    body: SetIntentPolicyRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Set an intent policy."""
    return set_intent_policy(
        agent_id=body.agent_id,
        allowed_intents=body.allowed_intents,
        required_justification=body.required_justification,
        max_risk_score=body.max_risk_score,
    )


@router.get("/v1/intent/policies")
def get_intent_policies(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List all intent policies."""
    policies = list_intent_policies()
    return {"total": len(policies), "policies": policies}
