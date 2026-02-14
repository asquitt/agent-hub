"""Audit event streaming and webhook dispatch routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.audit_streaming import (
    activate_webhook,
    compute_webhook_signature,
    deactivate_webhook,
    emit_event,
    get_dead_letters,
    get_delivery_log,
    get_event_stats,
    get_webhook,
    list_webhooks,
    query_events,
    register_webhook,
    retry_dead_letter,
    simulate_failure,
    test_webhook,
)

router = APIRouter(tags=["audit"])


class EmitEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str = Field(min_length=1)
    agent_id: str | None = None
    resource: str | None = None
    detail: dict[str, Any] | None = None
    severity: str | None = None


class RegisterWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1)
    secret: str | None = None
    event_types: list[str] | None = None
    severity_filter: str | None = None
    agent_filter: str | None = None
    description: str = ""


class RetryDeadLetterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dead_letter_id: str = Field(min_length=1)


class SimulateFailureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    webhook_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)


# ── Event endpoints ──────────────────────────────────────────────────

@router.post("/v1/audit/events")
def post_emit_event(
    body: EmitEventRequest,
    caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Emit an audit event."""
    try:
        return emit_event(
            event_type=body.event_type,
            agent_id=body.agent_id,
            actor=caller,
            resource=body.resource,
            detail=body.detail,
            severity=body.severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/audit/events")
def get_events(
    event_type: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    since: float | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Query audit events."""
    items = query_events(
        event_type=event_type,
        agent_id=agent_id,
        severity=severity,
        since=since,
        limit=limit,
    )
    return {"total": len(items), "events": items}


@router.get("/v1/audit/stats")
def get_stats(
    since: float | None = Query(default=None),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get audit event statistics."""
    return get_event_stats(since=since)


# ── Webhook endpoints ────────────────────────────────────────────────

@router.post("/v1/audit/webhooks")
def post_register_webhook(
    body: RegisterWebhookRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Register a webhook subscription."""
    try:
        return register_webhook(
            url=body.url,
            secret=body.secret,
            event_types=body.event_types,
            severity_filter=body.severity_filter,
            agent_filter=body.agent_filter,
            description=body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/audit/webhooks")
def get_list_webhooks(
    active_only: bool = Query(default=False),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List webhook subscriptions."""
    items = list_webhooks(active_only=active_only)
    return {"total": len(items), "webhooks": items}


@router.get("/v1/audit/webhooks/{webhook_id}")
def get_webhook_detail(
    webhook_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get webhook details."""
    try:
        return get_webhook(webhook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/audit/webhooks/{webhook_id}/deactivate")
def post_deactivate(
    webhook_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Deactivate a webhook."""
    try:
        return deactivate_webhook(webhook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/audit/webhooks/{webhook_id}/activate")
def post_activate(
    webhook_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Re-activate a webhook."""
    try:
        return activate_webhook(webhook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/audit/webhooks/{webhook_id}/test")
def post_test_webhook(
    webhook_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Send a test event to a webhook."""
    try:
        return test_webhook(webhook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ── Delivery log & dead letters ──────────────────────────────────────

@router.get("/v1/audit/deliveries")
def get_deliveries(
    webhook_id: str | None = Query(default=None),
    event_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get delivery attempt log."""
    items = get_delivery_log(
        webhook_id=webhook_id,
        event_id=event_id,
        status=status,
        limit=limit,
    )
    return {"total": len(items), "deliveries": items}


@router.get("/v1/audit/dead-letters")
def get_dead_letter_queue(
    webhook_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get dead letter queue."""
    items = get_dead_letters(webhook_id=webhook_id, limit=limit)
    return {"total": len(items), "dead_letters": items}


@router.post("/v1/audit/dead-letters/retry")
def post_retry_dead_letter(
    body: RetryDeadLetterRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Retry a dead letter delivery."""
    try:
        return retry_dead_letter(body.dead_letter_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/audit/simulate-failure")
def post_simulate_failure(
    body: SimulateFailureRequest,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Simulate a webhook delivery failure (testing endpoint)."""
    try:
        return simulate_failure(body.webhook_id, body.event_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
