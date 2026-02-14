"""Capability search, match, recommend, lease routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import (
    LeaseCreateRequest,
    LeasePromoteRequest,
    LeaseRollbackRequest,
    MatchRequest,
    RecommendRequest,
    SearchRequest,
)
from src.api.route_helpers import (
    capability_match,
    capability_recommend,
    capability_search,
    extract_required_fields,
    resolve_tenant_id,
)
from src.cost_governance.service import record_metering_event
from src.lease import create_lease, get_lease, promote_lease, rollback_install
from src.policy import evaluate_install_promotion_policy

router = APIRouter(tags=["capabilities"])


@router.post("/v1/capabilities/search")
def search_capabilities(
    request: SearchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        result = capability_search(
            query=request.query,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            tenant_id=tenant_id,
        )
        record_metering_event(
            actor="runtime.search",
            operation="capabilities.search",
            cost_usd=max(0.0002, 0.00005 * len(result.get("data", []))),
            metadata={"query": request.query, "result_count": len(result.get("data", []))},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/v1/capabilities/match")
def match_capabilities(
    request: MatchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        result = capability_match(
            input_required=extract_required_fields(request.input_schema),
            output_required=extract_required_fields(request.output_schema),
            compatibility_mode=request.filters.compatibility_mode if request.filters else "backward_compatible",
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            tenant_id=tenant_id,
        )
        record_metering_event(
            actor="runtime.search",
            operation="capabilities.match",
            cost_usd=max(0.00015, 0.00005 * len(result.get("data", []))),
            metadata={"result_count": len(result.get("data", []))},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/v1/capabilities/recommend")
def recommend_capabilities(
    request: RecommendRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        result = capability_recommend(
            task_description=request.task_description,
            current_capability_ids=request.current_capability_ids,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            tenant_id=tenant_id,
        )
        record_metering_event(
            actor="runtime.search",
            operation="capabilities.recommend",
            cost_usd=max(0.0002, 0.00005 * len(result.get("data", []))),
            metadata={"result_count": len(result.get("data", []))},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/v1/capabilities/lease")
def post_capability_lease(request: LeaseCreateRequest, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        lease = create_lease(
            requester_agent_id=request.requester_agent_id,
            capability_ref=request.capability_ref,
            owner=owner,
            ttl_seconds=request.ttl_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return lease


@router.get("/v1/capabilities/leases/{lease_id}")
def get_capability_lease(lease_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        return get_lease(lease_id=lease_id, owner=owner)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="lease not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/v1/capabilities/leases/{lease_id}/promote")
def post_capability_promote(
    lease_id: str,
    request: LeasePromoteRequest,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    policy_decision = evaluate_install_promotion_policy(
        actor="runtime.install",
        owner=owner,
        lease_id=lease_id,
        policy_approved=request.policy_approved,
        attestation_hash=request.attestation_hash,
        signature=request.signature,
        abac_context={
            "principal": {
                "owner": owner,
                "tenant_id": tenant_id,
                "allowed_actions": ["promote_lease"],
                "mfa_present": True,
            },
            "resource": {"tenant_id": tenant_id},
            "environment": {"requires_mfa": False},
        },
    )
    if not policy_decision["allowed"]:
        record_metering_event(
            actor=owner,
            operation="capabilities.lease_promote_denied",
            cost_usd=0.0,
            metadata={"lease_id": lease_id, "violations": policy_decision["violated_constraints"]},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "message": "policy denied install promotion",
                "policy_decision": policy_decision,
            },
        )

    try:
        promoted = promote_lease(
            lease_id=lease_id,
            owner=owner,
            signature=request.signature,
            attestation_hash=request.attestation_hash,
            policy_approved=request.policy_approved,
            approval_ticket=request.approval_ticket,
            compatibility_verified=request.compatibility_verified,
        )
        record_metering_event(
            actor=owner,
            operation="capabilities.lease_promote",
            cost_usd=0.0003,
            metadata={"lease_id": lease_id, "status": promoted.get("status")},
        )
        promoted["policy_decision"] = policy_decision
        return promoted
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="lease not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/capabilities/installs/{install_id}/rollback")
def post_install_rollback(
    install_id: str,
    request: LeaseRollbackRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        rolled_back = rollback_install(install_id=install_id, owner=owner, reason=request.reason)
        record_metering_event(
            actor=owner,
            operation="capabilities.install_rollback",
            cost_usd=0.0001,
            metadata={"install_id": install_id},
        )
        return rolled_back
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="install not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
