"""Policy-as-Code declarative rule engine routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.policy.policy_as_code import (
    create_rule,
    delete_rule,
    evaluate,
    get_evaluation_log,
    get_rule,
    get_rule_versions,
    list_rules,
    update_rule,
)

router = APIRouter(tags=["policy-as-code"])


class CreateRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    description: str = ""
    effect: str = Field(pattern=r"^(allow|deny|require_approval)$")
    priority: int = Field(default=100, ge=0, le=1000)
    conditions: list[dict[str, Any]] | None = None
    target_agents: list[str] | None = None
    target_actions: list[str] | None = None
    target_resources: list[str] | None = None
    enabled: bool = True


class UpdateRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    description: str | None = None
    effect: str | None = Field(default=None, pattern=r"^(allow|deny|require_approval)$")
    priority: int | None = Field(default=None, ge=0, le=1000)
    conditions: list[dict[str, Any]] | None = None
    target_agents: list[str] | None = None
    target_actions: list[str] | None = None
    target_resources: list[str] | None = None
    enabled: bool | None = None


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str | None = None
    context: dict[str, Any] | None = None
    dry_run: bool = False


@router.post("/v1/policy/rules")
def post_create_rule(
    body: CreateRuleRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a policy rule."""
    try:
        return create_rule(
            name=body.name,
            description=body.description,
            effect=body.effect,
            priority=body.priority,
            conditions=body.conditions,
            target_agents=body.target_agents,
            target_actions=body.target_actions,
            target_resources=body.target_resources,
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/policy/rules")
def get_list_rules(
    enabled_only: bool = Query(default=False),
    effect: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List policy rules."""
    items = list_rules(enabled_only=enabled_only, effect=effect, limit=limit)
    return {"total": len(items), "rules": items}


@router.get("/v1/policy/rules/{rule_id}")
def get_rule_detail(
    rule_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get rule details."""
    try:
        return get_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/v1/policy/rules/{rule_id}")
def put_update_rule(
    rule_id: str,
    body: UpdateRuleRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Update a policy rule."""
    try:
        return update_rule(
            rule_id,
            name=body.name,
            description=body.description,
            effect=body.effect,
            priority=body.priority,
            conditions=body.conditions,
            target_agents=body.target_agents,
            target_actions=body.target_actions,
            target_resources=body.target_resources,
            enabled=body.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/v1/policy/rules/{rule_id}")
def delete_rule_endpoint(
    rule_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Delete a policy rule."""
    try:
        return delete_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/policy/rules/{rule_id}/versions")
def get_versions(
    rule_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get version history for a rule."""
    versions = get_rule_versions(rule_id)
    return {"total": len(versions), "versions": versions}


@router.post("/v1/policy/evaluate")
def post_evaluate(
    body: EvaluateRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Evaluate policy rules against a request."""
    return evaluate(
        agent_id=body.agent_id,
        action=body.action,
        resource=body.resource,
        context=body.context,
        dry_run=body.dry_run,
    )


@router.get("/v1/policy/evaluations")
def get_evaluations(
    agent_id: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get policy evaluation history."""
    items = get_evaluation_log(agent_id=agent_id, decision=decision, limit=limit)
    return {"total": len(items), "evaluations": items}
