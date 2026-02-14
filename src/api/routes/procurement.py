"""Procurement policy packs, approvals, exceptions, audit routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import (
    ProcurementApprovalCreateRequest,
    ProcurementApprovalDecisionRequest,
    ProcurementExceptionCreateRequest,
    ProcurementPolicyPackUpsertRequest,
)
from src.cost_governance.service import record_metering_event
from src.procurement import (
    create_approval_request,
    create_exception,
    decide_approval,
    list_approvals,
    list_audit_events as list_procurement_audit_events,
    list_exceptions,
    list_policy_packs,
    upsert_policy_pack,
)

router = APIRouter(tags=["procurement"])


@router.post("/v1/procurement/policy-packs")
def post_procurement_policy_pack(
    request: ProcurementPolicyPackUpsertRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = upsert_policy_pack(
            actor=owner,
            buyer=request.buyer,
            auto_approve_limit_usd=request.auto_approve_limit_usd,
            hard_stop_limit_usd=request.hard_stop_limit_usd,
            allowed_sellers=request.allowed_sellers,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.policy_pack.upsert",
            cost_usd=0.0,
            metadata={"buyer": request.buyer, "pack_id": row["pack_id"]},
        )
        return row
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/procurement/policy-packs")
def get_procurement_policy_packs(
    buyer: str | None = Query(default=None, min_length=3),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer policy packs")
    return {"data": list_policy_packs(buyer=buyer)}


@router.post("/v1/procurement/approvals")
def post_procurement_approval_request(
    request: ProcurementApprovalCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = create_approval_request(
            actor=owner,
            buyer=request.buyer,
            listing_id=request.listing_id,
            units=request.units,
            estimated_total_usd=request.estimated_total_usd,
            note=request.note,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.approval.request",
            cost_usd=0.0,
            metadata={"buyer": request.buyer, "approval_id": row["approval_id"]},
        )
        return row
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/procurement/approvals")
def get_procurement_approvals(
    buyer: str | None = Query(default=None, min_length=3),
    status: str | None = Query(default=None, min_length=3),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer approvals")
    return {"data": list_approvals(buyer=buyer, status=status)}


@router.post("/v1/procurement/approvals/{approval_id}/decision")
def post_procurement_approval_decision(
    approval_id: str,
    request: ProcurementApprovalDecisionRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = decide_approval(
            actor=owner,
            approval_id=approval_id,
            decision=request.decision,
            approved_max_total_usd=request.approved_max_total_usd,
            note=request.note,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.approval.decision",
            cost_usd=0.0,
            metadata={"approval_id": approval_id, "decision": request.decision},
        )
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="approval not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/procurement/exceptions")
def post_procurement_exception(
    request: ProcurementExceptionCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = create_exception(
            actor=owner,
            buyer=request.buyer,
            reason=request.reason,
            override_hard_stop_limit_usd=request.override_hard_stop_limit_usd,
            allow_seller_id=request.allow_seller_id,
            expires_at=request.expires_at,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.exception.create",
            cost_usd=0.0,
            metadata={"exception_id": row["exception_id"], "buyer": request.buyer},
        )
        return row
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/procurement/exceptions")
def get_procurement_exceptions(
    buyer: str | None = Query(default=None, min_length=3),
    active_only: bool = Query(default=False),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer exceptions")
    return {"data": list_exceptions(buyer=buyer, active_only=active_only)}


@router.get("/v1/procurement/audit")
def get_procurement_audit(
    buyer: str | None = Query(default=None, min_length=3),
    limit: int = Query(default=100, ge=1, le=500),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer audit trail")
    return {"data": list_procurement_audit_events(buyer=buyer, limit=limit)}
