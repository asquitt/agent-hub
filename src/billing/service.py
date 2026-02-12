from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

SUBSCRIPTIONS: dict[str, dict[str, Any]] = {}
USAGE_EVENTS: list[dict[str, Any]] = []
INVOICES: dict[str, dict[str, Any]] = {}


def _now_epoch() -> int:
    return int(datetime.now(UTC).timestamp())


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


def create_subscription(
    account_id: str,
    plan_id: str,
    owner: str,
    monthly_fee_usd: float,
    included_units: int = 0,
) -> dict[str, Any]:
    now = _now_epoch()
    row = {
        "account_id": account_id,
        "plan_id": plan_id,
        "owner": owner,
        "monthly_fee_usd": round(float(monthly_fee_usd), 6),
        "included_units": int(included_units),
        "created_at": _iso(now),
    }
    SUBSCRIPTIONS[account_id] = row
    return row.copy()


def record_usage_event(
    account_id: str,
    meter: str,
    quantity: float,
    unit_price_usd: float,
    owner: str,
) -> dict[str, Any]:
    now = _now_epoch()
    row = {
        "event_id": str(uuid.uuid4()),
        "account_id": account_id,
        "owner": owner,
        "meter": meter,
        "quantity": float(quantity),
        "unit_price_usd": float(unit_price_usd),
        "cost_usd": round(float(quantity) * float(unit_price_usd), 6),
        "timestamp": _iso(now),
        "timestamp_epoch": now,
        "invoice_id": None,
    }
    USAGE_EVENTS.append(row)
    return row.copy()


def generate_invoice(account_id: str, owner: str) -> dict[str, Any]:
    usage_events = [row for row in USAGE_EVENTS if row["account_id"] == account_id and row["invoice_id"] is None]
    usage_total = round(sum(row["cost_usd"] for row in usage_events), 6)

    subscription = SUBSCRIPTIONS.get(account_id)
    subscription_fee = float(subscription["monthly_fee_usd"]) if subscription else 0.0

    invoice_id = str(uuid.uuid4())
    now = _now_epoch()
    invoice = {
        "invoice_id": invoice_id,
        "account_id": account_id,
        "owner": owner,
        "line_items": [
            {
                "type": "subscription",
                "amount_usd": round(subscription_fee, 6),
            },
            {
                "type": "usage",
                "amount_usd": usage_total,
                "event_count": len(usage_events),
            },
        ],
        "subtotal_usd": round(subscription_fee + usage_total, 6),
        "refunded_usd": 0.0,
        "due_usd": round(subscription_fee + usage_total, 6),
        "usage_event_ids": [row["event_id"] for row in usage_events],
        "created_at": _iso(now),
    }
    INVOICES[invoice_id] = invoice

    for row in usage_events:
        row["invoice_id"] = invoice_id

    return invoice.copy()


def get_invoice(invoice_id: str) -> dict[str, Any]:
    if invoice_id not in INVOICES:
        raise KeyError("invoice not found")
    return INVOICES[invoice_id].copy()


def reconcile_invoice(invoice_id: str) -> dict[str, Any]:
    if invoice_id not in INVOICES:
        raise KeyError("invoice not found")

    row = INVOICES[invoice_id]
    subscription_amount = next((item["amount_usd"] for item in row["line_items"] if item["type"] == "subscription"), 0.0)
    usage_amount = next((item["amount_usd"] for item in row["line_items"] if item["type"] == "usage"), 0.0)
    computed_subtotal = round(float(subscription_amount) + float(usage_amount), 6)
    stored_subtotal = round(float(row["subtotal_usd"]), 6)
    delta = round(computed_subtotal - stored_subtotal, 6)

    return {
        "invoice_id": invoice_id,
        "matched": delta == 0,
        "computed_subtotal_usd": computed_subtotal,
        "stored_subtotal_usd": stored_subtotal,
        "delta_usd": delta,
    }


def refund_invoice(invoice_id: str, amount_usd: float, reason: str, actor: str) -> dict[str, Any]:
    if invoice_id not in INVOICES:
        raise KeyError("invoice not found")
    if amount_usd <= 0:
        raise ValueError("refund amount must be greater than zero")

    row = INVOICES[invoice_id]
    new_refunded = round(float(row["refunded_usd"]) + float(amount_usd), 6)
    if new_refunded > float(row["subtotal_usd"]):
        raise ValueError("refund exceeds invoice subtotal")

    row["refunded_usd"] = new_refunded
    row["due_usd"] = round(float(row["subtotal_usd"]) - new_refunded, 6)
    row.setdefault("refunds", []).append(
        {
            "amount_usd": round(float(amount_usd), 6),
            "reason": reason,
            "actor": actor,
            "timestamp": _iso(_now_epoch()),
        }
    )
    return row.copy()
