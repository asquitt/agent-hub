"""Billing subscription, usage, invoices, refund routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import require_api_key, require_scope
from src.api.models import (
    BillingInvoiceGenerateRequest,
    BillingRefundRequest,
    BillingSubscriptionRequest,
    BillingUsageRequest,
)
from src.api.route_helpers import require_invoice_read_access
from src.billing import (
    create_subscription,
    generate_invoice,
    get_invoice,
    reconcile_invoice,
    record_usage_event as billing_record_usage_event,
    refund_invoice,
)

router = APIRouter(tags=["billing"])


@router.post("/v1/billing/subscriptions")
def post_billing_subscription(
    request: BillingSubscriptionRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return create_subscription(
        account_id=request.account_id,
        plan_id=request.plan_id,
        owner=owner,
        monthly_fee_usd=request.monthly_fee_usd,
        included_units=request.included_units,
    )


@router.post("/v1/billing/usage")
def post_billing_usage(
    request: BillingUsageRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return billing_record_usage_event(
        account_id=request.account_id,
        meter=request.meter,
        quantity=request.quantity,
        unit_price_usd=request.unit_price_usd,
        owner=owner,
    )


@router.post("/v1/billing/invoices/generate")
def post_billing_generate_invoice(
    request: BillingInvoiceGenerateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return generate_invoice(account_id=request.account_id, owner=owner)


@router.get("/v1/billing/invoices/{invoice_id}")
def get_billing_invoice(invoice_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        invoice = get_invoice(invoice_id)
        require_invoice_read_access(owner, invoice)
        return invoice
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="invoice not found") from exc


@router.post("/v1/billing/invoices/{invoice_id}/reconcile")
def post_billing_reconcile(invoice_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        invoice = get_invoice(invoice_id)
        require_invoice_read_access(owner, invoice)
        return reconcile_invoice(invoice_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="invoice not found") from exc


@router.post("/v1/billing/invoices/{invoice_id}/refund")
def post_billing_refund(
    invoice_id: str,
    request: BillingRefundRequest,
    owner: str = Depends(require_scope("billing.refund")),
) -> dict[str, Any]:
    if owner != "owner-platform":
        raise HTTPException(status_code=403, detail="billing admin role required")
    try:
        return refund_invoice(
            invoice_id=invoice_id,
            amount_usd=request.amount_usd,
            reason=request.reason,
            actor=owner,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="invoice not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
