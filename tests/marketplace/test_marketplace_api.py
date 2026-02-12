from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app


@pytest.fixture(autouse=True)
def isolate_marketplace_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_LISTINGS_PATH", str(tmp_path / "listings.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_CONTRACTS_PATH", str(tmp_path / "contracts.json"))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))


def test_marketplace_purchase_and_settlement_integrity() -> None:
    client = TestClient(app)

    listing = client.post(
        "/v1/marketplace/listings",
        json={
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "unit_price_usd": 0.5,
            "max_units_per_purchase": 10,
            "policy_purchase_limit_usd": 3.0,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert listing.status_code == 200
    listing_id = listing.json()["listing_id"]

    purchase = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 4,
            "max_total_usd": 2.5,
            "policy_approved": True,
        },
        headers={"X-API-Key": "partner-owner-key"},
    )
    assert purchase.status_code == 200
    contract_id = purchase.json()["contract_id"]

    settle = client.post(
        f"/v1/marketplace/contracts/{contract_id}/settle",
        json={"units_used": 4},
        headers={"X-API-Key": "partner-owner-key"},
    )
    assert settle.status_code == 200
    assert settle.json()["status"] == "settled"
    assert settle.json()["amount_settled_usd"] == 2.0


def test_marketplace_policy_scoped_purchase_limit_enforced() -> None:
    client = TestClient(app)
    listing = client.post(
        "/v1/marketplace/listings",
        json={
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "unit_price_usd": 1.0,
            "max_units_per_purchase": 10,
            "policy_purchase_limit_usd": 2.0,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    listing_id = listing.json()["listing_id"]

    denied = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 3,
            "max_total_usd": 10.0,
            "policy_approved": True,
        },
        headers={"X-API-Key": "partner-owner-key"},
    )
    assert denied.status_code == 403


def test_marketplace_abuse_smoke_over_settlement_blocked() -> None:
    client = TestClient(app)
    listing = client.post(
        "/v1/marketplace/listings",
        json={
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "unit_price_usd": 0.4,
            "max_units_per_purchase": 5,
            "policy_purchase_limit_usd": 2.0,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    listing_id = listing.json()["listing_id"]

    purchase = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 2,
            "max_total_usd": 1.0,
            "policy_approved": True,
        },
        headers={"X-API-Key": "partner-owner-key"},
    )
    contract_id = purchase.json()["contract_id"]

    denied = client.post(
        f"/v1/marketplace/contracts/{contract_id}/settle",
        json={"units_used": 3},
        headers={"X-API-Key": "partner-owner-key"},
    )
    assert denied.status_code == 400
