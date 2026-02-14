"""Marketplace listings, purchase, contracts, settlements, disputes, payouts routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import require_api_key
from src.api.models import (
    MarketplaceDisputeCreateRequest,
    MarketplaceDisputeResolveRequest,
    MarketplaceListingCreateRequest,
    MarketplacePurchaseRequest,
    MarketplaceSettlementRequest,
)
from src.api.route_helpers import require_contract_read_access
from src.cost_governance.service import record_metering_event
from src.marketplace import (
    create_dispute,
    create_listing,
    create_payout,
    get_contract,
    list_disputes,
    list_listings,
    list_payouts,
    purchase_listing,
    resolve_dispute,
    settle_contract,
)

router = APIRouter(tags=["marketplace"])


@router.post("/v1/marketplace/listings")
def post_marketplace_listing(
    request: MarketplaceListingCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        listing = create_listing(
            owner=owner,
            capability_ref=request.capability_ref,
            unit_price_usd=request.unit_price_usd,
            max_units_per_purchase=request.max_units_per_purchase,
            policy_purchase_limit_usd=request.policy_purchase_limit_usd,
        )
        record_metering_event(actor=owner, operation="marketplace.listing_create", cost_usd=0.0, metadata={"listing_id": listing["listing_id"]})
        return listing
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/marketplace/listings")
def get_marketplace_listings(_owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_listings()}


@router.post("/v1/marketplace/purchase")
def post_marketplace_purchase(
    request: MarketplacePurchaseRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        contract = purchase_listing(
            buyer=owner,
            listing_id=request.listing_id,
            units=request.units,
            max_total_usd=request.max_total_usd,
            policy_approved=request.policy_approved,
            procurement_approval_id=request.procurement_approval_id,
            procurement_exception_id=request.procurement_exception_id,
        )
        record_metering_event(actor=owner, operation="marketplace.purchase", cost_usd=contract["estimated_total_usd"], metadata={"contract_id": contract["contract_id"]})
        return contract
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="listing not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/marketplace/contracts/{contract_id}")
def get_marketplace_contract(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        contract = get_contract(contract_id)
        require_contract_read_access(owner, contract)
        return contract
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc


@router.post("/v1/marketplace/contracts/{contract_id}/settle")
def post_marketplace_settlement(
    contract_id: str,
    request: MarketplaceSettlementRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        settled = settle_contract(contract_id=contract_id, actor=owner, units_used=request.units_used)
        record_metering_event(actor=owner, operation="marketplace.settle", cost_usd=0.0, metadata={"contract_id": contract_id})
        return settled
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/marketplace/contracts/{contract_id}/disputes")
def post_marketplace_dispute(
    contract_id: str,
    request: MarketplaceDisputeCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = create_dispute(
            contract_id=contract_id,
            actor=owner,
            reason=request.reason,
            requested_amount_usd=request.requested_amount_usd,
        )
        record_metering_event(actor=owner, operation="marketplace.dispute.create", cost_usd=0.0, metadata={"contract_id": contract_id})
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/marketplace/contracts/{contract_id}/disputes")
def get_marketplace_disputes(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        contract = get_contract(contract_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    require_contract_read_access(owner, contract)
    return {"data": list_disputes(contract_id=contract_id)}


@router.post("/v1/marketplace/disputes/{dispute_id}/resolve")
def post_marketplace_dispute_resolve(
    dispute_id: str,
    request: MarketplaceDisputeResolveRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = resolve_dispute(
            dispute_id=dispute_id,
            actor=owner,
            resolution=request.resolution,
            approved_amount_usd=request.approved_amount_usd,
        )
        record_metering_event(actor=owner, operation="marketplace.dispute.resolve", cost_usd=0.0, metadata={"dispute_id": dispute_id})
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="dispute not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/marketplace/contracts/{contract_id}/payout")
def post_marketplace_payout(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        row = create_payout(contract_id=contract_id, actor=owner)
        record_metering_event(actor=owner, operation="marketplace.payout", cost_usd=0.0, metadata={"contract_id": contract_id})
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/marketplace/contracts/{contract_id}/payouts")
def get_marketplace_payouts(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        contract = get_contract(contract_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    require_contract_read_access(owner, contract)
    return {"data": list_payouts(contract_id=contract_id)}
