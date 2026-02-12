from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from src.marketplace import storage


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    row = next((item for item in contracts if item.get("contract_id") == contract_id), None)
    if row is None:
        raise KeyError("contract not found")
    return row


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
