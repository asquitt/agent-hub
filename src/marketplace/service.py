from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from src.marketplace import storage
from src.procurement import evaluate_purchase_policy


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_contract(contracts: list[dict[str, Any]], contract_id: str) -> dict[str, Any]:
    row = next((item for item in contracts if item.get("contract_id") == contract_id), None)
    if row is None:
        raise KeyError("contract not found")
    return row


def list_listings() -> list[dict[str, Any]]:
    rows = storage.load("listings")
    rows.sort(key=lambda row: row.get("created_at", ""), reverse=True)
    return rows


def create_listing(
    *,
    owner: str,
    capability_ref: str,
    unit_price_usd: float,
    max_units_per_purchase: int,
    policy_purchase_limit_usd: float,
) -> dict[str, Any]:
    if unit_price_usd < 0:
        raise ValueError("unit_price_usd must be >= 0")
    if max_units_per_purchase <= 0:
        raise ValueError("max_units_per_purchase must be > 0")
    if policy_purchase_limit_usd <= 0:
        raise ValueError("policy_purchase_limit_usd must be > 0")

    row = {
        "listing_id": str(uuid.uuid4()),
        "owner": owner,
        "capability_ref": capability_ref,
        "unit_price_usd": round(unit_price_usd, 6),
        "max_units_per_purchase": max_units_per_purchase,
        "policy_purchase_limit_usd": round(policy_purchase_limit_usd, 6),
        "status": "active",
        "created_at": _utc_now(),
    }
    rows = storage.load("listings")
    rows.append(row)
    storage.save("listings", rows)
    return row


def purchase_listing(
    *,
    buyer: str,
    listing_id: str,
    units: int,
    max_total_usd: float,
    policy_approved: bool,
    procurement_approval_id: str | None = None,
    procurement_exception_id: str | None = None,
) -> dict[str, Any]:
    if not policy_approved:
        raise PermissionError("policy approval required for purchase")
    if units <= 0:
        raise ValueError("units must be > 0")
    if max_total_usd <= 0:
        raise ValueError("max_total_usd must be > 0")

    listings = storage.load("listings")
    listing = next((row for row in listings if row.get("listing_id") == listing_id and row.get("status") == "active"), None)
    if listing is None:
        raise KeyError("listing not found")

    if units > int(listing["max_units_per_purchase"]):
        raise PermissionError("units exceed listing purchase limit")

    total_estimated = units * float(listing["unit_price_usd"])
    if total_estimated > float(listing["policy_purchase_limit_usd"]):
        raise PermissionError("purchase exceeds policy purchase limit")
    if total_estimated > max_total_usd:
        raise PermissionError("purchase exceeds caller max_total_usd")
    try:
        procurement_decision = evaluate_purchase_policy(
            actor=buyer,
            buyer=buyer,
            listing_id=listing_id,
            seller=str(listing["owner"]),
            estimated_total_usd=round(total_estimated, 6),
            approval_id=procurement_approval_id,
            exception_id=procurement_exception_id,
        )
    except KeyError as exc:
        raise PermissionError(str(exc)) from exc

    contract = {
        "contract_id": str(uuid.uuid4()),
        "listing_id": listing_id,
        "buyer": buyer,
        "seller": listing["owner"],
        "capability_ref": listing["capability_ref"],
        "units_purchased": units,
        "unit_price_usd": listing["unit_price_usd"],
        "estimated_total_usd": round(total_estimated, 6),
        "units_settled": 0,
        "amount_settled_usd": 0.0,
        "procurement_decision": procurement_decision,
        "status": "active",
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
    }
    contracts = storage.load("contracts")
    contracts.append(contract)
    storage.save("contracts", contracts)
    return contract


def get_contract(contract_id: str) -> dict[str, Any]:
    contracts = storage.load("contracts")
    return _find_contract(contracts, contract_id)


def settle_contract(*, contract_id: str, actor: str, units_used: int) -> dict[str, Any]:
    if units_used <= 0:
        raise ValueError("units_used must be > 0")
    contracts = storage.load("contracts")
    row = next((item for item in contracts if item.get("contract_id") == contract_id), None)
    if row is None:
        raise KeyError("contract not found")
    if actor not in {row.get("buyer"), row.get("seller"), "owner-platform"}:
        raise PermissionError("actor not permitted to settle contract")
    if row.get("status") not in {"active", "settled"}:
        raise ValueError("contract not active")

    total_units = int(row["units_purchased"])
    if int(row["units_settled"]) + units_used > total_units:
        raise ValueError("units_used exceeds purchased units")

    incremental_cost = units_used * float(row["unit_price_usd"])
    row["units_settled"] = int(row["units_settled"]) + units_used
    row["amount_settled_usd"] = round(float(row["amount_settled_usd"]) + incremental_cost, 6)
    row["status"] = "settled" if int(row["units_settled"]) == total_units else "active"
    row["updated_at"] = _utc_now()

    storage.save("contracts", contracts)
    return row


def list_disputes(contract_id: str | None = None) -> list[dict[str, Any]]:
    rows = storage.load("disputes")
    if contract_id is not None:
        rows = [row for row in rows if row.get("contract_id") == contract_id]
    rows.sort(key=lambda row: row.get("created_at", ""), reverse=True)
    return rows


def create_dispute(*, contract_id: str, actor: str, reason: str, requested_amount_usd: float) -> dict[str, Any]:
    if requested_amount_usd <= 0:
        raise ValueError("requested_amount_usd must be > 0")
    if len(reason.strip()) < 3:
        raise ValueError("reason must be at least 3 characters")

    contracts = storage.load("contracts")
    contract = _find_contract(contracts, contract_id)
    if actor not in {contract.get("buyer"), contract.get("seller")}:
        raise PermissionError("actor not permitted to file dispute")
    if contract.get("status") not in {"active", "settled"}:
        raise ValueError("contract not eligible for dispute")

    disputes = storage.load("disputes")
    row = {
        "dispute_id": str(uuid.uuid4()),
        "contract_id": contract_id,
        "filed_by": actor,
        "reason": reason.strip(),
        "requested_amount_usd": round(float(requested_amount_usd), 6),
        "status": "open",
        "resolution": None,
        "approved_amount_usd": 0.0,
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
    }
    disputes.append(row)
    storage.save("disputes", disputes)
    return row


def resolve_dispute(
    *,
    dispute_id: str,
    actor: str,
    resolution: str,
    approved_amount_usd: float | None = None,
) -> dict[str, Any]:
    if actor != "owner-platform":
        raise PermissionError("only platform owner can resolve disputes")
    normalized = resolution.strip().lower()
    if normalized not in {"rejected", "approved_partial", "approved_full"}:
        raise ValueError("resolution must be rejected, approved_partial, or approved_full")

    disputes = storage.load("disputes")
    row = next((item for item in disputes if item.get("dispute_id") == dispute_id), None)
    if row is None:
        raise KeyError("dispute not found")
    if row.get("status") != "open":
        raise ValueError("dispute already resolved")

    contracts = storage.load("contracts")
    contract = _find_contract(contracts, str(row["contract_id"]))
    max_disputable = float(contract.get("amount_settled_usd", 0.0))
    requested = float(row.get("requested_amount_usd", 0.0))

    approved = 0.0
    status = "resolved_rejected"
    if normalized == "approved_full":
        approved = min(requested, max_disputable)
        status = "resolved_approved_full"
    elif normalized == "approved_partial":
        if approved_amount_usd is None or approved_amount_usd <= 0:
            raise ValueError("approved_amount_usd must be > 0 for approved_partial")
        approved = min(float(approved_amount_usd), requested, max_disputable)
        status = "resolved_approved_partial"

    row["resolution"] = normalized
    row["approved_amount_usd"] = round(approved, 6)
    row["resolved_by"] = actor
    row["status"] = status
    row["updated_at"] = _utc_now()
    row["resolved_at"] = _utc_now()
    storage.save("disputes", disputes)
    return row


def list_payouts(contract_id: str | None = None) -> list[dict[str, Any]]:
    rows = storage.load("payouts")
    if contract_id is not None:
        rows = [row for row in rows if row.get("contract_id") == contract_id]
    rows.sort(key=lambda row: row.get("created_at", ""), reverse=True)
    return rows


def create_payout(*, contract_id: str, actor: str) -> dict[str, Any]:
    if actor not in {"owner-platform", "owner-dev"}:
        raise PermissionError("actor not permitted to execute payout")

    contracts = storage.load("contracts")
    contract = _find_contract(contracts, contract_id)
    if contract.get("status") != "settled":
        raise ValueError("contract must be settled before payout")

    disputes = list_disputes(contract_id=contract_id)
    if any(row.get("status") == "open" for row in disputes):
        raise ValueError("open disputes must be resolved before payout")

    payouts = storage.load("payouts")
    existing = next((row for row in payouts if row.get("contract_id") == contract_id), None)
    if existing is not None:
        return existing

    dispute_adjustment = sum(float(row.get("approved_amount_usd", 0.0)) for row in disputes if str(row.get("status", "")).startswith("resolved_approved"))
    gross = float(contract.get("amount_settled_usd", 0.0))
    net = max(0.0, gross - dispute_adjustment)
    row = {
        "payout_id": str(uuid.uuid4()),
        "contract_id": contract_id,
        "seller": contract.get("seller"),
        "executed_by": actor,
        "gross_amount_usd": round(gross, 6),
        "dispute_adjustment_usd": round(dispute_adjustment, 6),
        "net_payout_usd": round(net, 6),
        "status": "paid",
        "created_at": _utc_now(),
    }
    payouts.append(row)
    storage.save("payouts", payouts)
    return row
