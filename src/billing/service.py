from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from src.billing.storage import _STORAGE
from src.common.time import iso_from_epoch, utc_now_epoch, utc_now_iso


def _round(value: float) -> float:
    return round(float(value), 6)


def create_subscription(
    account_id: str,
    plan_id: str,
    owner: str,
    monthly_fee_usd: float,
    included_units: int = 0,
) -> dict[str, Any]:
    now = utc_now_iso()
    row = {
        "account_id": account_id,
        "plan_id": plan_id,
        "owner": owner,
        "monthly_fee_usd": _round(monthly_fee_usd),
        "included_units": int(included_units),
        "created_at": now,
        "updated_at": now,
    }
    _STORAGE.upsert_subscription(row)
    return {
        "account_id": row["account_id"],
        "plan_id": row["plan_id"],
        "owner": row["owner"],
        "monthly_fee_usd": row["monthly_fee_usd"],
        "included_units": row["included_units"],
        "created_at": row["created_at"],
    }


def record_usage_event(
    account_id: str,
    meter: str,
    quantity: float,
    unit_price_usd: float,
    owner: str,
) -> dict[str, Any]:
    now = utc_now_epoch()
    row = {
        "event_id": str(uuid.uuid4()),
        "account_id": account_id,
        "owner": owner,
        "meter": meter,
        "quantity": float(quantity),
        "unit_price_usd": float(unit_price_usd),
        "cost_usd": _round(float(quantity) * float(unit_price_usd)),
        "timestamp": iso_from_epoch(now),
        "timestamp_epoch": now,
        "invoice_id": None,
    }
    _STORAGE.insert_usage_event(row)
    _STORAGE.append_ledger_transaction(
        tx_id=f"usage:{row['event_id']}",
        account_id=account_id,
        source_type="usage_event",
        source_id=row["event_id"],
        entries=[
            {
                "ledger_account": "unbilled_usage",
                "debit_usd": row["cost_usd"],
                "credit_usd": 0.0,
                "metadata": {"meter": meter},
                "created_at": row["timestamp"],
            },
            {
                "ledger_account": "usage_accrual",
                "debit_usd": 0.0,
                "credit_usd": row["cost_usd"],
                "metadata": {"meter": meter},
                "created_at": row["timestamp"],
            },
        ],
    )
    return row.copy()


def _invoice_ledger_entries(
    *, subscription_fee: float, usage_total: float, timestamp: str
) -> list[dict[str, Any]]:
    total = _round(subscription_fee + usage_total)
    if total == 0:
        return []
    entries: list[dict[str, Any]] = [
        {
            "ledger_account": "accounts_receivable",
            "debit_usd": total,
            "credit_usd": 0.0,
            "metadata": {"component": "invoice_total"},
            "created_at": timestamp,
        }
    ]
    if subscription_fee > 0:
        entries.append(
            {
                "ledger_account": "subscription_revenue",
                "debit_usd": 0.0,
                "credit_usd": _round(subscription_fee),
                "metadata": {"component": "subscription"},
                "created_at": timestamp,
            }
        )
    if usage_total > 0:
        entries.append(
            {
                "ledger_account": "usage_revenue",
                "debit_usd": 0.0,
                "credit_usd": _round(usage_total),
                "metadata": {"component": "usage"},
                "created_at": timestamp,
            }
        )
    return entries


def generate_invoice(account_id: str, owner: str) -> dict[str, Any]:
    # Hold storage lock for the full read-compute-write cycle to prevent double-billing
    with _STORAGE._lock:
        usage_events = _STORAGE.list_uninvoiced_usage(account_id)
        usage_total = _round(sum(float(row["cost_usd"]) for row in usage_events))

        subscription = _STORAGE.get_subscription(account_id)
        subscription_fee = _round(float(subscription["monthly_fee_usd"]) if subscription else 0.0)

        invoice_id = str(uuid.uuid4())
        now = utc_now_iso()
        subtotal = _round(subscription_fee + usage_total)
        invoice = {
            "invoice_id": invoice_id,
            "account_id": account_id,
            "owner": owner,
            "line_items": [
                {"type": "subscription", "amount_usd": subscription_fee},
                {"type": "usage", "amount_usd": usage_total, "event_count": len(usage_events)},
            ],
            "subscription_snapshot_usd": subscription_fee,
            "subtotal_usd": subtotal,
            "refunded_usd": 0.0,
            "due_usd": subtotal,
            "usage_event_ids": [row["event_id"] for row in usage_events],
            "created_at": now,
        }
        _STORAGE.insert_invoice(invoice)
        _STORAGE.mark_usage_invoiced(invoice["usage_event_ids"], invoice_id)

        ledger_entries = _invoice_ledger_entries(subscription_fee=subscription_fee, usage_total=usage_total, timestamp=now)
        if ledger_entries:
            _STORAGE.append_ledger_transaction(
                tx_id=f"invoice:{invoice_id}",
                account_id=account_id,
                source_type="invoice",
                source_id=invoice_id,
                entries=ledger_entries,
            )
    return invoice.copy()


def get_invoice(invoice_id: str) -> dict[str, Any]:
    row = _STORAGE.get_invoice(invoice_id)
    if row is None:
        raise KeyError("invoice not found")
    return row


def replay_invoice_accounts(invoice_id: str) -> dict[str, float]:
    entries = _STORAGE.list_ledger_entries(source_id=invoice_id)
    balances: dict[str, float] = {}
    for row in entries:
        account = str(row["ledger_account"])
        delta = _round(float(row["debit_usd"]) - float(row["credit_usd"]))
        balances[account] = _round(balances.get(account, 0.0) + delta)
    return balances


def list_ledger_entries(
    invoice_id: str | None = None,
    *,
    tx_id: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
) -> list[dict[str, Any]]:
    if tx_id is not None:
        return _STORAGE.list_ledger_entries(tx_id=tx_id)
    if source_type is not None or source_id is not None:
        return _STORAGE.list_ledger_entries(source_type=source_type, source_id=source_id)
    if invoice_id is not None:
        return _STORAGE.list_ledger_entries(source_id=invoice_id)
    return _STORAGE.list_ledger_entries()


def verify_double_entry(tx_id: str | None = None, source_id: str | None = None) -> dict[str, Any]:
    if tx_id is not None:
        entries = list_ledger_entries(tx_id=tx_id)
        debit = _round(sum(float(row["debit_usd"]) for row in entries))
        credit = _round(sum(float(row["credit_usd"]) for row in entries))
        delta = _round(debit - credit)
        return {
            "tx_id": tx_id,
            "debit_usd": debit,
            "credit_usd": credit,
            "delta_usd": delta,
            "balanced": delta == 0,
        }

    entries = list_ledger_entries(source_id=source_id)
    totals: dict[str, dict[str, float]] = {}
    for row in entries:
        tx_id = str(row["tx_id"])
        bucket = totals.setdefault(tx_id, {"debit": 0.0, "credit": 0.0})
        bucket["debit"] = _round(bucket["debit"] + float(row["debit_usd"]))
        bucket["credit"] = _round(bucket["credit"] + float(row["credit_usd"]))
    unbalanced = [
        {
            "tx_id": tx_id,
            "debit_total_usd": _round(values["debit"]),
            "credit_total_usd": _round(values["credit"]),
        }
        for tx_id, values in totals.items()
        if _round(values["debit"] - values["credit"]) != 0
    ]
    return {
        "valid": len(unbalanced) == 0,
        "transaction_count": len(totals),
        "unbalanced_transactions": unbalanced,
    }


def verify_ledger_chain() -> dict[str, Any]:
    return _STORAGE.verify_ledger_chain()


def reconcile_invoice(invoice_id: str) -> dict[str, Any]:
    row = get_invoice(invoice_id)
    subscription_amount = _round(
        float(next((item["amount_usd"] for item in row["line_items"] if item["type"] == "subscription"), 0.0))
    )
    usage_amount = _round(float(next((item["amount_usd"] for item in row["line_items"] if item["type"] == "usage"), 0.0)))
    computed_subtotal = _round(subscription_amount + usage_amount)
    stored_subtotal = _round(float(row["subtotal_usd"]))
    subtotal_delta = _round(computed_subtotal - stored_subtotal)

    usage_total = _STORAGE.invoice_usage_sum(invoice_id)
    usage_matches = usage_total == usage_amount

    replay_subtotal = _round(float(row.get("subscription_snapshot_usd", subscription_amount)) + usage_total)
    replay_delta = _round(replay_subtotal - stored_subtotal)

    double_entry = verify_double_entry(source_id=invoice_id)

    replay = replay_invoice_accounts(invoice_id)
    replay_due = _round(float(replay.get("accounts_receivable", 0.0)))
    expected_due = _round(float(row["due_usd"]))
    replay_matches_due = replay_due == expected_due

    chain_validation = _STORAGE.verify_ledger_chain()
    matched = (
        subtotal_delta == 0
        and replay_delta == 0
        and usage_matches
        and bool(double_entry["valid"])
        and replay_matches_due
        and bool(chain_validation["valid"])
    )
    return {
        "invoice_id": invoice_id,
        "matched": matched,
        "computed_subtotal_usd": computed_subtotal,
        "stored_subtotal_usd": stored_subtotal,
        "delta_usd": subtotal_delta,
        "replay_subtotal_usd": replay_subtotal,
        "replay_delta_usd": replay_delta,
        "usage_total_from_events_usd": usage_total,
        "usage_line_item_usd": usage_amount,
        "double_entry_balanced": bool(double_entry["valid"]),
        "unbalanced_transactions": double_entry["unbalanced_transactions"],
        "replay_due_usd": replay_due,
        "expected_due_usd": expected_due,
        "replay_accounts": replay,
        "chain_valid": bool(chain_validation["valid"]),
        "chain_entry_count": int(chain_validation["entry_count"]),
    }


def refund_invoice(invoice_id: str, amount_usd: float, reason: str, actor: str) -> dict[str, Any]:
    if amount_usd <= 0:
        raise ValueError("refund amount must be greater than zero")

    row = get_invoice(invoice_id)
    amount = _round(amount_usd)
    new_refunded = _round(float(row["refunded_usd"]) + amount)
    if new_refunded > float(row["subtotal_usd"]):
        raise ValueError("refund exceeds invoice subtotal")

    refund_event = {
        "refund_id": str(uuid.uuid4()),
        "amount_usd": amount,
        "reason": reason,
        "actor": actor,
        "timestamp": utc_now_iso(),
    }
    row.setdefault("refunds", []).append(refund_event)
    row["refunded_usd"] = new_refunded
    row["due_usd"] = _round(float(row["subtotal_usd"]) - new_refunded)
    _STORAGE.update_invoice(row)
    refund_index = len(row["refunds"])

    _STORAGE.append_ledger_transaction(
        tx_id=f"refund:{invoice_id}:{refund_index}",
        account_id=str(row["account_id"]),
        source_type="refund",
        source_id=invoice_id,
        entries=[
            {
                "ledger_account": "refunds_contra_revenue",
                "debit_usd": amount,
                "credit_usd": 0.0,
                "metadata": {"reason": reason, "actor": actor},
                "created_at": refund_event["timestamp"],
            },
            {
                "ledger_account": "accounts_receivable",
                "debit_usd": 0.0,
                "credit_usd": amount,
                "metadata": {"reason": reason, "actor": actor},
                "created_at": refund_event["timestamp"],
            },
        ],
    )
    return row.copy()


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)
