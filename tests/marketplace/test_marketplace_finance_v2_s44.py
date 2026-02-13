from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.cost_governance import storage as cost_storage


@pytest.fixture(autouse=True)
def isolate_marketplace_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_LISTINGS_PATH", str(tmp_path / "listings.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_CONTRACTS_PATH", str(tmp_path / "contracts.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_DISPUTES_PATH", str(tmp_path / "disputes.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_PAYOUTS_PATH", str(tmp_path / "payouts.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH", str(tmp_path / "proc-policy-packs.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_APPROVALS_PATH", str(tmp_path / "proc-approvals.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_EXCEPTIONS_PATH", str(tmp_path / "proc-exceptions.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_AUDIT_PATH", str(tmp_path / "proc-audit.json"))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    cost_storage.reset_for_tests(db_path=billing_db)


def _create_settled_contract(client: TestClient) -> str:
    listing = client.post(
        "/v1/marketplace/listings",
        json={
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "unit_price_usd": 0.5,
            "max_units_per_purchase": 10,
            "policy_purchase_limit_usd": 3.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s60-fin-listing"},
    )
    assert listing.status_code == 200
    listing_id = listing.json()["listing_id"]
    pack = client.post(
        "/v1/procurement/policy-packs",
        json={
            "buyer": "owner-partner",
            "auto_approve_limit_usd": 5.0,
            "hard_stop_limit_usd": 10.0,
            "allowed_sellers": ["owner-dev"],
        },
        headers={"X-API-Key": "platform-owner-key", "Idempotency-Key": "s60-fin-pack"},
    )
    assert pack.status_code == 200, pack.text

    purchase = client.post(
        "/v1/marketplace/purchase",
        json={"listing_id": listing_id, "units": 4, "max_total_usd": 2.5, "policy_approved": True},
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-fin-purchase"},
    )
    assert purchase.status_code == 200
    contract_id = purchase.json()["contract_id"]

    settle = client.post(
        f"/v1/marketplace/contracts/{contract_id}/settle",
        json={"units_used": 4},
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-fin-settle"},
    )
    assert settle.status_code == 200
    assert settle.json()["status"] == "settled"
    return contract_id


def test_marketplace_dispute_resolution_and_payout_integrity() -> None:
    client = TestClient(app)
    contract_id = _create_settled_contract(client)

    dispute = client.post(
        f"/v1/marketplace/contracts/{contract_id}/disputes",
        json={"reason": "Incorrect completion quality", "requested_amount_usd": 0.6},
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-fin-dispute-1"},
    )
    assert dispute.status_code == 200
    dispute_id = dispute.json()["dispute_id"]

    resolved = client.post(
        f"/v1/marketplace/disputes/{dispute_id}/resolve",
        json={"resolution": "approved_partial", "approved_amount_usd": 0.3},
        headers={"X-API-Key": "platform-owner-key", "Idempotency-Key": "s60-fin-resolve-1"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved_approved_partial"
    assert resolved.json()["approved_amount_usd"] == 0.3

    payout = client.post(
        f"/v1/marketplace/contracts/{contract_id}/payout",
        headers={"X-API-Key": "platform-owner-key", "Idempotency-Key": "s60-fin-payout-1"},
    )
    assert payout.status_code == 200
    payload = payout.json()
    assert payload["gross_amount_usd"] == 2.0
    assert payload["dispute_adjustment_usd"] == 0.3
    assert payload["net_payout_usd"] == 1.7

    payouts = client.get(
        f"/v1/marketplace/contracts/{contract_id}/payouts",
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert payouts.status_code == 200
    assert len(payouts.json()["data"]) == 1


def test_open_dispute_blocks_payout_until_resolved() -> None:
    client = TestClient(app)
    contract_id = _create_settled_contract(client)

    dispute = client.post(
        f"/v1/marketplace/contracts/{contract_id}/disputes",
        json={"reason": "Pending investigation", "requested_amount_usd": 0.4},
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-fin-dispute-2"},
    )
    assert dispute.status_code == 200

    blocked = client.post(
        f"/v1/marketplace/contracts/{contract_id}/payout",
        headers={"X-API-Key": "platform-owner-key", "Idempotency-Key": "s60-fin-payout-2"},
    )
    assert blocked.status_code == 400


def test_dispute_and_payout_permission_boundaries() -> None:
    client = TestClient(app)
    contract_id = _create_settled_contract(client)

    dispute = client.post(
        f"/v1/marketplace/contracts/{contract_id}/disputes",
        json={"reason": "Need credit", "requested_amount_usd": 0.2},
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-fin-dispute-3"},
    )
    dispute_id = dispute.json()["dispute_id"]

    denied_resolve = client.post(
        f"/v1/marketplace/disputes/{dispute_id}/resolve",
        json={"resolution": "rejected"},
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-fin-resolve-3"},
    )
    assert denied_resolve.status_code == 403

    denied_payout = client.post(
        f"/v1/marketplace/contracts/{contract_id}/payout",
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-fin-payout-3"},
    )
    assert denied_payout.status_code == 403
