"""Delegation create, status, contract, multi-party ceremony routes."""
from __future__ import annotations

import copy
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key, require_api_key_owner
from src.delegation.multiparty import (
    cast_vote,
    create_ceremony,
    get_ceremony,
    list_ceremonies,
    verify_ceremony_signatures,
)
from src.api.models import DelegationRequest
from src.api.route_helpers import (
    delegate_policy_signals,
    delegation_idempotency_owner,
    request_hash,
    require_idempotency_key,
    resolve_tenant_id,
)
from src.cost_governance.service import record_metering_event
from src.delegation import storage as delegation_storage
from src.delegation.service import create_delegation, delegation_contract, get_delegation_status
from src.policy import evaluate_delegation_policy
from src.reliability.service import DEFAULT_WINDOW_SIZE, build_slo_dashboard

router = APIRouter(tags=["delegation"])


@router.post("/v1/delegations")
def post_delegation(
    request: DelegationRequest,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    key = require_idempotency_key(idempotency_key)
    request_payload = request.model_dump(mode="json")
    request_digest = request_hash(request_payload)
    tenant_id = resolve_tenant_id(x_tenant_id)
    idempotency_owner = delegation_idempotency_owner(owner=owner, tenant_id=tenant_id)
    reservation = delegation_storage.reserve_idempotency(
        owner=idempotency_owner,
        idempotency_key=key,
        request_hash=request_digest,
    )
    reservation_state = str(reservation.get("state"))
    if reservation_state == "mismatch":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "idempotency.key_reused_with_different_payload",
                "message": "idempotency key replay with different request payload",
            },
        )
    if reservation_state == "response":
        return copy.deepcopy(reservation["response"])
    if reservation_state == "pending":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "idempotency.in_progress",
                "message": "idempotency key request already in progress",
            },
        )

    owns_reservation = reservation_state == "reserved"
    if not owns_reservation:
        raise HTTPException(status_code=500, detail="unable to reserve idempotency slot")

    sre_dashboard = build_slo_dashboard(window_size=DEFAULT_WINDOW_SIZE)
    circuit_breaker = sre_dashboard["circuit_breaker"]
    if circuit_breaker["state"] == "open":
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise HTTPException(
            status_code=503,
            detail={
                "message": "delegation circuit breaker is open",
                "circuit_breaker": circuit_breaker,
                "alerts": sre_dashboard["alerts"],
            },
        )

    delegate_trust_score, delegate_permissions = delegate_policy_signals(request.delegate_agent_id)
    try:
        policy_decision = evaluate_delegation_policy(
            actor="runtime.delegation",
            requester_agent_id=request.requester_agent_id,
            delegate_agent_id=request.delegate_agent_id,
            estimated_cost_usd=request.estimated_cost_usd,
            max_budget_usd=request.max_budget_usd,
            auto_reauthorize=request.auto_reauthorize,
            min_delegate_trust_score=request.min_delegate_trust_score,
            delegate_trust_score=delegate_trust_score,
            required_permissions=request.required_permissions,
            delegate_permissions=delegate_permissions,
            abac_context={
                "principal": {
                    "owner": owner,
                    "tenant_id": tenant_id,
                    "allowed_actions": ["create_delegation"],
                    "mfa_present": True,
                },
                "resource": {"tenant_id": tenant_id},
                "environment": {"requires_mfa": False},
            },
        )
        if not policy_decision["allowed"]:
            status = 400 if all(code.startswith("budget.") for code in policy_decision["violated_constraints"]) else 403
            raise HTTPException(
                status_code=status,
                detail={
                    "message": "policy denied delegation",
                    "policy_decision": policy_decision,
                },
            )

        row = create_delegation(
            requester_agent_id=request.requester_agent_id,
            delegate_agent_id=request.delegate_agent_id,
            task_spec=request.task_spec,
            estimated_cost_usd=request.estimated_cost_usd,
            max_budget_usd=request.max_budget_usd,
            simulated_actual_cost_usd=request.simulated_actual_cost_usd,
            auto_reauthorize=request.auto_reauthorize,
            policy_decision=policy_decision,
            metering_events=request.metering_events,
            delegation_token=request.delegation_token,
        )
        response = {
            "contract": delegation_contract(),
            "delegation_id": row["delegation_id"],
            "status": row["status"],
            "budget_controls": row["budget_controls"],
            "policy_decision": policy_decision,
            "lifecycle": row["lifecycle"],
            "queue_state": row.get("queue_state"),
            "identity_context": row.get("identity_context"),
            "sre_governance": {
                "circuit_breaker": circuit_breaker,
                "alerts": sre_dashboard["alerts"],
            },
        }
    except ValueError as exc:
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise
    except Exception:
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise

    delegation_storage.finalize_idempotency(owner=idempotency_owner, idempotency_key=key, response=response)
    return response


@router.get("/v1/delegations/contract")
def get_delegation_contract_endpoint(_owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return delegation_contract()


@router.get("/v1/delegations/{delegation_id}/status")
def get_delegation_status_endpoint(delegation_id: str) -> dict[str, Any]:
    row = get_delegation_status(delegation_id)
    if not row:
        raise HTTPException(status_code=404, detail="delegation not found")
    return row


# ── Multi-Party Delegation Ceremonies ─────────────────────────────


class CreateCeremonyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    initiator_agent_id: str = Field(min_length=1, max_length=256)
    subject_agent_id: str = Field(min_length=1, max_length=256)
    scopes: list[str] = Field(min_length=1, max_length=50)
    approvers: list[str] = Field(min_length=1, max_length=20)
    required_approvals: int = Field(ge=1, le=20)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    metadata: dict[str, str] | None = None


class CastVoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    voter_id: str = Field(min_length=1, max_length=256)
    decision: str = Field(pattern="^(approve|reject)$")


@router.post("/v1/delegations/ceremonies")
def post_create_ceremony(
    request: CreateCeremonyRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a multi-party delegation ceremony."""
    try:
        return create_ceremony(
            initiator_agent_id=request.initiator_agent_id,
            subject_agent_id=request.subject_agent_id,
            scopes=request.scopes,
            approvers=request.approvers,
            required_approvals=request.required_approvals,
            ttl_seconds=request.ttl_seconds,
            metadata=request.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/delegations/ceremonies/{ceremony_id}")
def get_ceremony_endpoint(
    ceremony_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get a ceremony by ID."""
    try:
        return get_ceremony(ceremony_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/delegations/ceremonies/{ceremony_id}/vote")
def post_cast_vote(
    ceremony_id: str,
    request: CastVoteRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Cast a vote on a ceremony."""
    try:
        return cast_vote(
            ceremony_id=ceremony_id,
            voter_id=request.voter_id,
            decision=request.decision,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/delegations/ceremonies")
def get_list_ceremonies(
    initiator: str | None = None,
    status: str | None = None,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List delegation ceremonies."""
    ceremonies = list_ceremonies(initiator=initiator, status=status)
    return {"count": len(ceremonies), "ceremonies": ceremonies}


@router.get("/v1/delegations/ceremonies/{ceremony_id}/verify")
def get_verify_ceremony(
    ceremony_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify all vote signatures in a ceremony."""
    try:
        return verify_ceremony_signatures(ceremony_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
